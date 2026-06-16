import dns from "node:dns/promises";
import type { BlacklistResult, DnsblProviderResult } from "../types.js";
import { createLogger } from "../lib/logger.js";
import { safeResolve } from "../lib/dnsResolve.js";

const log = createLogger("blacklist");

const DNSBL_PROVIDERS = [
  { provider: "Spamhaus ZEN", host: "zen.spamhaus.org" },
  { provider: "Barracuda", host: "b.barracudacentral.org" },
  { provider: "SpamCop", host: "bl.spamcop.net" },
  { provider: "SORBS", host: "dnsbl.sorbs.net" },
  { provider: "UCEPROTECT L1", host: "dnsbl-1.uceprotect.net" },
];

const DOMAIN_BL_PROVIDERS = [
  { provider: "Spamhaus DBL", host: "dbl.spamhaus.org" },
  { provider: "SURBL", host: "multi.surbl.org" },
];

/**
 * Query DNSBL providers (IP-based and domain-based) and aggregate their
 * listed/clean state.
 *
 * After the Phase A infrastructure split, this checker no longer resolves the
 * domain itself — the caller passes `primaryIp` (from `checkInfrastructure`).
 * If `primaryIp` is null, IP-based DNSBL is skipped and only domain-based runs.
 */
export async function checkBlacklist(
  domain: string,
  primaryIp: string | null,
  timeout: number = 5000,
): Promise<BlacklistResult> {
  if (!primaryIp) {
    log.debug({ domain }, "no primary IP — skipping IP-based DNSBL");
  }

  const ipResults: PromiseSettledResult<DnsblProviderResult>[] = primaryIp
    ? await Promise.allSettled(
        DNSBL_PROVIDERS.map(async ({ provider, host }): Promise<DnsblProviderResult> => {
          const reversed = primaryIp.split(".").reverse().join(".");
          try {
            await safeResolve(() => dns.resolve4(`${reversed}.${host}`), timeout);
            return { provider, host, listed: true, type: "ip" };
          } catch {
            return { provider, host, listed: false, type: "ip" };
          }
        }),
      )
    : [];

  const domainResults = await Promise.allSettled(
    DOMAIN_BL_PROVIDERS.map(async ({ provider, host }): Promise<DnsblProviderResult> => {
      try {
        await safeResolve(() => dns.resolve4(`${domain}.${host}`), timeout);
        return { provider, host, listed: true, type: "domain" };
      } catch {
        return { provider, host, listed: false, type: "domain" };
      }
    }),
  );

  const providers: DnsblProviderResult[] = [
    ...domainResults.map((r) =>
      r.status === "fulfilled" ? r.value : { provider: "Unknown", host: "", listed: false, type: "domain" as const },
    ),
    ...ipResults.map((r) =>
      r.status === "fulfilled" ? r.value : { provider: "Unknown", host: "", listed: false, type: "ip" as const },
    ),
  ];

  const anyListed = providers.some((p) => p.listed);

  return {
    status: anyListed ? "warn" : "pass",
    providers,
  };
}
