import dns from "node:dns/promises";
import type { InfrastructureResult } from "../types.js";
import { createLogger } from "../lib/logger.js";
import { safeResolve, resolveMultiResolver } from "../lib/dnsResolve.js";

const log = createLogger("infrastructure");

// ── CIDR matching ──────────────────────────────────────────────────────────

function ipToNum(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr(ip: string, cidr: string): boolean {
  const [net, bits] = cidr.split("/");
  const mask = bits ? (~0 << (32 - Number(bits))) >>> 0 : 0xffffffff;
  return (ipToNum(ip) & mask) === (ipToNum(net) & mask);
}

// Official CIDR ranges from provider documentation. Keep names short — they
// surface in UI directly.
const CDN_CIDRS: { cidrs: string[]; name: string }[] = [
  // Source: https://www.cloudflare.com/ips-v4
  { cidrs: ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"], name: "Cloudflare" },
  // Source: https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips (subset of common ranges)
  { cidrs: ["13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "18.64.0.0/14", "18.154.0.0/15", "18.160.0.0/13", "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18", "99.84.0.0/16", "99.86.0.0/16", "143.204.0.0/16", "205.251.192.0/19"], name: "AWS CloudFront" },
  // Source: https://www.gstatic.com/ipranges/cloud.json (Global LB ranges)
  { cidrs: ["34.96.0.0/14", "34.102.0.0/15", "34.104.0.0/14", "34.110.0.0/15", "34.117.0.0/16", "34.120.0.0/14", "34.128.0.0/10", "34.144.0.0/14", "34.149.0.0/16", "34.160.0.0/14"], name: "Google Cloud" },
  // Fastly: https://api.fastly.com/public-ip-list
  { cidrs: ["23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16"], name: "Fastly" },
  // Azure Front Door / CDN: https://www.microsoft.com/en-us/download/details.aspx?id=56519 (subset: AzureFrontDoor.Frontend)
  { cidrs: ["13.107.213.0/24", "13.107.246.0/24", "20.21.37.0/24", "20.36.120.0/21", "20.37.64.0/18", "20.38.132.0/22", "20.39.224.0/21", "20.41.64.0/18", "20.42.0.0/17", "20.43.128.0/18", "20.44.0.0/18", "20.45.128.0/17", "20.46.0.0/17", "20.47.0.0/17", "20.48.0.0/17", "20.49.0.0/17", "20.50.0.0/17", "20.51.0.0/17", "20.52.0.0/17", "20.53.0.0/17", "20.54.0.0/17", "20.60.0.0/17", "20.150.0.0/17", "20.157.0.0/17"], name: "Azure" },
  // Meta (Facebook / Instagram / WhatsApp) — ASN 32934.
  // Sources: https://whois.arin.net/rest/asn/AS32934 and RIPE.
  { cidrs: ["31.13.24.0/21", "31.13.64.0/18", "66.220.144.0/20", "66.220.152.0/21", "69.63.176.0/20", "69.171.224.0/19", "74.119.76.0/22", "102.132.96.0/20", "157.240.0.0/16", "173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22", "204.15.20.0/22"], name: "Meta" },
];

function detectCdn(ip: string): string | null {
  for (const { cidrs, name } of CDN_CIDRS) {
    if (cidrs.some((cidr) => inCidr(ip, cidr))) return name;
  }
  return null;
}

// ── Main check ─────────────────────────────────────────────────────────────

/**
 * Resolve a domain's IPs and identify which CDN/cloud (if any) hosts the
 * primary IP. This is the single source of truth for "where does this domain
 * actually live" — DNSBL, multi-edge TLS probe, CDN-managed cert detection,
 * and the Infrastructure banner all consume the result.
 *
 * Tries 4 public resolvers in parallel and unions the IPs. If all public
 * resolvers fail, falls back to the system resolver (last-resort safety net).
 */
export async function checkInfrastructure(
  domain: string,
  timeout: number = 5000,
): Promise<InfrastructureResult> {
  let ips: string[];
  let resolverCount: number;
  try {
    const probe = await resolveMultiResolver(domain, timeout);
    ips = probe.ips;
    resolverCount = probe.successCount;
    if (ips.length === 0) {
      // All public resolvers failed — fall back to the system resolver.
      try {
        const sys = await safeResolve(() => dns.resolve4(domain), timeout);
        if (sys && sys.length > 0) {
          ips = sys;
          resolverCount = 0;
        }
      } catch {
        // handled below
      }
    }
    if (ips.length === 0) {
      return {
        ip: null,
        ips: [],
        resolverCount: 0,
        cdnProvider: null,
        cdnProviders: [],
        error: "Could not resolve domain IP",
      };
    }
  } catch (err: any) {
    log.warn({ domain, err: err?.code || err?.message || err }, "could not resolve IP");
    return {
      ip: null,
      ips: [],
      resolverCount: 0,
      cdnProvider: null,
      cdnProviders: [],
      error: `Could not resolve domain IP: ${err?.code || err?.message || "unknown"}`,
    };
  }

  const ip = ips[0];
  const cdnProvider = detectCdn(ip);
  // Detect CDNs across *all* observed IPs — multi-CDN setups can show 2+ here.
  const cdnProviders = Array.from(
    new Set(ips.map((p) => detectCdn(p)).filter((c): c is string => !!c)),
  );

  return {
    ip,
    ips,
    resolverCount,
    cdnProvider,
    cdnProviders,
  };
}
