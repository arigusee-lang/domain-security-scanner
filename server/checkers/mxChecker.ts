import dns from "node:dns/promises";
import type { MxResult } from "../types.js";

export async function checkMx(domain: string, timeout: number = 5000): Promise<MxResult> {
  try {
    const records = await Promise.race([
      dns.resolveMx(domain),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
    ]);
    if (!records || records.length === 0) {
      return { status: "info", records: [] };
    }
    const sorted = records
      .map(r => ({ exchange: r.exchange, priority: r.priority }))
      .sort((a, b) => a.priority - b.priority);
    return { status: "pass", records: sorted };
  } catch (err: any) {
    if (err.code === "ENODATA" || err.code === "ENOTFOUND") {
      return { status: "info", records: [] };
    }
    return { status: "info", records: [] };
  }
}
