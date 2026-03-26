import dns from "node:dns/promises";
import type { CaaResult, CaaRecord } from "../types.js";

export async function checkCaa(domain: string, timeout: number = 5000): Promise<CaaResult> {
  try {
    const result = await Promise.race([
      dns.resolveCaa(domain),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
    ]);
    if (!result || result.length === 0) {
      return { status: "warn", records: [] };
    }
    // dns.resolveCaa returns objects like { critical: 0, issue: "letsencrypt.org" }
    // or { critical: 0, issuewild: ";" } or { critical: 0, iodef: "mailto:..." }
    const records: CaaRecord[] = result.map((r: any) => {
      const flags = r.critical ?? 0;
      // The record has exactly one of: issue, issuewild, iodef
      if (r.issue !== undefined) return { flags, tag: "issue", value: r.issue };
      if (r.issuewild !== undefined) return { flags, tag: "issuewild", value: r.issuewild };
      if (r.iodef !== undefined) return { flags, tag: "iodef", value: r.iodef };
      // Fallback for unknown tags
      const keys = Object.keys(r).filter(k => k !== "critical");
      const tag = keys[0] || "unknown";
      return { flags, tag, value: String(r[tag] ?? "") };
    });
    return { status: "pass", records };
  } catch (err: any) {
    if (err.message === "timeout") {
      return { status: "fail", records: [], error: "DNS lookup timed out" };
    }
    if (err.code === "ENODATA" || err.code === "ENOTFOUND") {
      return { status: "warn", records: [] };
    }
    return { status: "fail", records: [], error: err.message || "DNS lookup failed" };
  }
}
