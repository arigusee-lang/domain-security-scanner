import type { CheckStatus } from "../types.js";

export interface CtLogEntry {
  issuerName: string;
  commonName: string;
  notBefore: string;
  notAfter: string;
}

export interface CtLogsResult {
  status: CheckStatus;
  totalCerts: number;
  recentCerts: CtLogEntry[];
  error?: string;
}

/**
 * Queries crt.sh for Certificate Transparency log entries.
 * crt.sh can be slow — we use a generous timeout and limit results.
 */
export async function checkCtLogs(domain: string, timeout: number = 15000): Promise<CtLogsResult> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&limit=20`,
      {
        signal: controller.signal,
        headers: { "User-Agent": "security-txt-validator/1.0", Accept: "application/json" },
      }
    );
    clearTimeout(timer);

    if (!res.ok) {
      return { status: "info", totalCerts: 0, recentCerts: [], error: `crt.sh returned HTTP ${res.status}` };
    }

    const text = await res.text();
    if (!text || text.trim().length === 0) {
      return { status: "info", totalCerts: 0, recentCerts: [] };
    }

    let data: any[];
    try {
      data = JSON.parse(text);
    } catch {
      return { status: "info", totalCerts: 0, recentCerts: [], error: "Invalid response from crt.sh" };
    }

    if (!Array.isArray(data)) {
      return { status: "info", totalCerts: 0, recentCerts: [] };
    }

    const totalCerts = data.length;

    // Deduplicate by common_name + not_before, take 10 most recent
    const seen = new Set<string>();
    const recentCerts: CtLogEntry[] = [];
    for (const entry of data) {
      const key = `${entry.common_name}|${entry.not_before}`;
      if (seen.has(key)) continue;
      seen.add(key);
      recentCerts.push({
        issuerName: entry.issuer_name || "Unknown",
        commonName: entry.common_name || domain,
        notBefore: entry.not_before || "",
        notAfter: entry.not_after || "",
      });
      if (recentCerts.length >= 10) break;
    }

    return { status: totalCerts > 0 ? "pass" : "info", totalCerts, recentCerts };
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { status: "info", totalCerts: 0, recentCerts: [], error: "crt.sh timed out (service may be slow)" };
    }
    return { status: "info", totalCerts: 0, recentCerts: [], error: "CT log lookup failed" };
  }
}
