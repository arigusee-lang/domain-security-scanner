import dns from "node:dns/promises";
import type { BlacklistResult, DnsblProviderResult } from "../types.js";

const DNSBL_PROVIDERS = [
  { provider: "Spamhaus ZEN", host: "zen.spamhaus.org" },
  { provider: "Barracuda", host: "b.barracudacentral.org" },
  { provider: "SpamCop", host: "bl.spamcop.net" },
  { provider: "SORBS", host: "dnsbl.sorbs.net" },
  { provider: "UCEPROTECT L1", host: "dnsbl-1.uceprotect.net" },
];

// Domain-based blocklists (checked by domain name, not IP)
const DOMAIN_BL_PROVIDERS = [
  { provider: "Spamhaus DBL", host: "dbl.spamhaus.org" },
  { provider: "SURBL", host: "multi.surbl.org" },
];

export async function checkBlacklist(domain: string, timeout: number = 5000): Promise<BlacklistResult> {
  // Resolve domain to IP
  let ip: string;
  try {
    const addresses = await Promise.race([
      dns.resolve4(domain),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
    ]);
    if (!addresses || addresses.length === 0) {
      return { status: "info", ip: null, providers: [], error: "Could not resolve domain IP" };
    }
    ip = addresses[0];
  } catch {
    return { status: "info", ip: null, providers: [], error: "Could not resolve domain IP" };
  }

  // Reverse IP octets
  const reversed = ip.split(".").reverse().join(".");

  // Check each IP-based DNSBL in parallel
  const ipResults = await Promise.allSettled(
    DNSBL_PROVIDERS.map(async ({ provider, host }): Promise<DnsblProviderResult> => {
      try {
        await Promise.race([
          dns.resolve4(`${reversed}.${host}`),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
        ]);
        return { provider, host, listed: true };
      } catch {
        return { provider, host, listed: false };
      }
    })
  );

  // Check domain-based blocklists in parallel
  const domainResults = await Promise.allSettled(
    DOMAIN_BL_PROVIDERS.map(async ({ provider, host }): Promise<DnsblProviderResult> => {
      try {
        await Promise.race([
          dns.resolve4(`${domain}.${host}`),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
        ]);
        return { provider, host, listed: true };
      } catch {
        return { provider, host, listed: false };
      }
    })
  );

  const providers: DnsblProviderResult[] = [
    ...ipResults.map(r => r.status === "fulfilled" ? r.value : { provider: "Unknown", host: "", listed: false }),
    ...domainResults.map(r => r.status === "fulfilled" ? r.value : { provider: "Unknown", host: "", listed: false }),
  ];

  const anyListed = providers.some(p => p.listed);

  return {
    status: anyListed ? "warn" : "pass",
    ip,
    providers,
  };
}
