import dns from "node:dns/promises";
import type { NsResult } from "../types.js";

export async function checkNs(domain: string, timeout: number = 5000): Promise<NsResult> {
  try {
    const nameservers = await Promise.race([
      dns.resolveNs(domain),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
    ]);
    if (!nameservers || nameservers.length === 0) {
      return { status: "fail", nameservers: [], error: "No NS records found" };
    }
    return { status: "pass", nameservers: nameservers.sort() };
  } catch (err: any) {
    if (err.code === "ENODATA" || err.code === "ENOTFOUND") {
      return { status: "fail", nameservers: [], error: "No NS records found" };
    }
    return { status: "fail", nameservers: [], error: err.message || "DNS lookup failed" };
  }
}
