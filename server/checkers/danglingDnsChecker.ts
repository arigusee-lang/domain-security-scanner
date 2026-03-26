import dns from "node:dns/promises";
import type { CheckStatus } from "../types.js";

export interface DanglingRecord {
  type: "MX" | "NS";
  hostname: string;
  resolves: boolean;
}

export interface DanglingDnsResult {
  status: CheckStatus;
  records: DanglingRecord[];
  danglingCount: number;
  error?: string;
}

async function canResolve(hostname: string, timeout: number): Promise<boolean> {
  try {
    await Promise.race([
      dns.resolve4(hostname),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
    ]);
    return true;
  } catch {
    // Try IPv6 as fallback
    try {
      await Promise.race([
        dns.resolve6(hostname),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
      ]);
      return true;
    } catch {
      return false;
    }
  }
}

export async function checkDanglingDns(domain: string, timeout: number = 5000): Promise<DanglingDnsResult> {
  const records: DanglingRecord[] = [];

  // Get MX and NS records
  let mxHosts: string[] = [];
  let nsHosts: string[] = [];

  try {
    const mx = await Promise.race([
      dns.resolveMx(domain),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
    ]);
    mxHosts = mx.map(r => r.exchange);
  } catch { /* no MX is fine */ }

  try {
    const ns = await Promise.race([
      dns.resolveNs(domain),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
    ]);
    nsHosts = ns;
  } catch { /* no NS is fine */ }

  // Check all hostnames in parallel
  const checks = [
    ...mxHosts.map(async (h): Promise<DanglingRecord> => ({
      type: "MX" as const, hostname: h, resolves: await canResolve(h, timeout),
    })),
    ...nsHosts.map(async (h): Promise<DanglingRecord> => ({
      type: "NS" as const, hostname: h, resolves: await canResolve(h, timeout),
    })),
  ];

  const results = await Promise.allSettled(checks);
  for (const r of results) {
    if (r.status === "fulfilled") records.push(r.value);
  }

  const danglingCount = records.filter(r => !r.resolves).length;

  let status: CheckStatus;
  if (records.length === 0) {
    status = "info";
  } else if (danglingCount > 0) {
    // Dangling NS is critical, dangling MX is a warning
    const danglingNs = records.some(r => r.type === "NS" && !r.resolves);
    status = danglingNs ? "fail" : "warn";
  } else {
    status = "pass";
  }

  return { status, records, danglingCount };
}
