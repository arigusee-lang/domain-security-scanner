import dns from "node:dns/promises";
import type { MxResult } from "../types.js";
import { createLogger } from "../lib/logger.js";
import { safeResolve } from "../lib/dnsResolve.js";

const log = createLogger("mx");

/** RFC 7505 Null MX: a single record with priority 0 and root-label exchange ("" or "."). */
function isNullMx(records: Array<{ exchange: string; priority: number }>): boolean {
  if (records.length !== 1) return false;
  const r = records[0];
  return r.priority === 0 && (r.exchange === "" || r.exchange === ".");
}

export async function checkMx(domain: string, timeout: number = 5000): Promise<MxResult> {
  try {
    const records = await safeResolve(() => dns.resolveMx(domain), timeout);
    if (!records || records.length === 0) {
      return { status: "info", records: [], hasMail: false };
    }
    const sorted = records
      .map(r => ({ exchange: r.exchange, priority: r.priority }))
      .sort((a, b) => a.priority - b.priority);
    if (isNullMx(sorted)) {
      return { status: "info", records: sorted, hasMail: false, nullMx: true };
    }
    return { status: "pass", records: sorted, hasMail: true };
  } catch (err: any) {
    if (err.code === "ENODATA" || err.code === "ENOTFOUND") {
      return { status: "info", records: [], hasMail: false };
    }
    log.warn({ domain, err: err?.code || err?.message || err }, "DNS lookup failed");
    return { status: "info", records: [], hasMail: false };
  }
}
