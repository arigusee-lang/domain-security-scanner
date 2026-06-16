import dns from "node:dns/promises";
import type { NsResult } from "../types.js";
import { createLogger } from "../lib/logger.js";
import { safeResolve } from "../lib/dnsResolve.js";

const log = createLogger("ns");

export async function checkNs(domain: string, timeout: number = 5000): Promise<NsResult> {
  try {
    const nameservers = await safeResolve(() => dns.resolveNs(domain), timeout);
    if (!nameservers || nameservers.length === 0) {
      return { status: "fail", nameservers: [], error: "No NS records found" };
    }
    return { status: "pass", nameservers: nameservers.sort() };
  } catch (err: any) {
    if (err.code === "ENODATA" || err.code === "ENOTFOUND") {
      return { status: "fail", nameservers: [], error: "No NS records found" };
    }
    if (err?.message === "timeout") {
      log.warn({ domain }, "DNS lookup timed out");
    } else {
      log.warn({ domain, err: err?.code || err?.message || err }, "DNS lookup failed");
    }
    return { status: "fail", nameservers: [], error: err.message || "DNS lookup failed" };
  }
}
