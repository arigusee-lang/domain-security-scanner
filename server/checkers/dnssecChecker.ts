import type { DnssecResult } from "../types.js";
import { createLogger } from "../lib/logger.js";

const log = createLogger("upstream");

export async function checkDnssec(domain: string, timeout: number = 5000): Promise<DnssecResult> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    // Use Google DNS-over-HTTPS to query DS records (Node dns.resolve doesn't support 'DS')
    const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DS`;
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);

    if (!response.ok) {
      log.warn({ upstream: "doh-google", status: response.status, domain }, "upstream returned non-2xx");
      return { status: "fail", enabled: false, error: "DNS-over-HTTPS request failed" };
    }

    const data = await response.json() as { Status: number; Answer?: unknown[]; AD?: boolean };

    // Status 0 = NOERROR, Answer present means DS records exist
    if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
      return { status: "pass", enabled: true };
    }

    return { status: "warn", enabled: false };
  } catch (err: any) {
    log.warn({ upstream: "doh-google", domain, err: err?.name || err?.message || String(err) }, "upstream request failed");
    if (err.name === "AbortError") {
      return { status: "fail", enabled: false, error: "DNS lookup timed out" };
    }
    return { status: "fail", enabled: false, error: err.message || "DNS lookup failed" };
  }
}
