import type { CheckStatus } from "../types.js";
import { createLogger } from "../lib/logger.js";

const log = createLogger("upstream");

export interface SafeBrowsingThreat {
  threatType: string;
  platformType: string;
}

export interface SafeBrowsingResult {
  status: CheckStatus;
  safe: boolean | null;
  threats: SafeBrowsingThreat[];
  error?: string;
}

export async function checkSafeBrowsing(domain: string, timeout: number = 5000): Promise<SafeBrowsingResult> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY || "";
  if (!apiKey) {
    return { status: "info", safe: null, threats: [], error: "Safe Browsing API key not configured" };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "domain-security-checker", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [
              { url: `https://${domain}/` },
              { url: `http://${domain}/` },
            ],
          },
        }),
      }
    );
    clearTimeout(timer);

    if (!res.ok) {
      log.warn({ upstream: "safebrowsing", status: res.status, domain }, "upstream returned non-2xx");
      return { status: "info", safe: null, threats: [], error: `API returned HTTP ${res.status}` };
    }

    const data = (await res.json()) as any;
    const matches = data.matches || [];

    if (matches.length === 0) {
      return { status: "pass", safe: true, threats: [] };
    }

    const threats: SafeBrowsingThreat[] = matches.map((m: any) => ({
      threatType: m.threatType || "UNKNOWN",
      platformType: m.platformType || "ANY_PLATFORM",
    }));

    return { status: "fail", safe: false, threats };
  } catch (err: any) {
    log.warn({ upstream: "safebrowsing", domain, err: err?.name || err?.message || String(err) }, "upstream request failed");
    return { status: "info", safe: null, threats: [], error: "Safe Browsing lookup failed" };
  }
}
