import type { CheckStatus } from "../types.js";

export interface UrlhausResult {
  status: CheckStatus;
  listed: boolean;
  urlCount: number;
  error?: string;
}

const AUTH_KEY = process.env.URLHAUS_AUTH_KEY || "";

export async function checkUrlhaus(domain: string, timeout: number = 5000): Promise<UrlhausResult> {
  if (!AUTH_KEY) {
    return { status: "info", listed: false, urlCount: 0, error: "URLhaus API key not configured" };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const res = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Auth-Key": AUTH_KEY,
      },
      body: `host=${encodeURIComponent(domain)}`,
    });
    clearTimeout(timer);

    if (!res.ok) {
      return { status: "info", listed: false, urlCount: 0, error: `URLhaus returned HTTP ${res.status}` };
    }

    const data = (await res.json()) as any;

    if (data.query_status === "no_results") {
      return { status: "pass", listed: false, urlCount: 0 };
    }

    if (data.query_status === "is_host") {
      const urlCount = data.urls?.length || 0;
      return { status: "warn", listed: true, urlCount };
    }

    return { status: "pass", listed: false, urlCount: 0 };
  } catch {
    return { status: "info", listed: false, urlCount: 0, error: "URLhaus lookup failed" };
  }
}
