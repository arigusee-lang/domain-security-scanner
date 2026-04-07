import dns from "node:dns/promises";
import type { BlacklistResult, DnsblProviderResult } from "../types.js";

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

// ── CIDR matching ──

function ipToNum(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr(ip: string, cidr: string): boolean {
  const [net, bits] = cidr.split("/");
  const mask = bits ? (~0 << (32 - Number(bits))) >>> 0 : 0xffffffff;
  return (ipToNum(ip) & mask) === (ipToNum(net) & mask);
}

// Official CIDR ranges from provider documentation
const CDN_CIDRS: { cidrs: string[]; name: string }[] = [
  // Source: https://www.cloudflare.com/ips-v4
  { cidrs: ["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"], name: "Cloudflare" },
  // Source: https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips (subset of common ranges)
  { cidrs: ["13.32.0.0/15","13.35.0.0/16","13.224.0.0/14","18.64.0.0/14","18.154.0.0/15","18.160.0.0/13","52.84.0.0/15","54.182.0.0/16","54.192.0.0/16","54.230.0.0/16","54.239.128.0/18","99.84.0.0/16","99.86.0.0/16","143.204.0.0/16","205.251.192.0/19"], name: "AWS CloudFront" },
  // Source: https://www.gstatic.com/ipranges/cloud.json (Global LB ranges)
  { cidrs: ["34.96.0.0/14","34.102.0.0/15","34.104.0.0/14","34.110.0.0/15","34.117.0.0/16","34.120.0.0/14","34.128.0.0/10","34.144.0.0/14","34.149.0.0/16","34.160.0.0/14"], name: "Google Cloud" },
  // Fastly: https://api.fastly.com/public-ip-list
  { cidrs: ["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23","103.245.224.0/24","104.156.80.0/20","140.248.64.0/18","140.248.128.0/17","146.75.0.0/17","151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","167.82.128.0/20","167.82.160.0/20","167.82.224.0/20","172.111.64.0/18","185.31.16.0/22","199.27.72.0/21","199.232.0.0/16"], name: "Fastly" },
  // Azure Front Door / CDN: https://www.microsoft.com/en-us/download/details.aspx?id=56519 (subset: AzureFrontDoor.Frontend)
  { cidrs: ["13.107.213.0/24","13.107.246.0/24","20.21.37.0/24","20.36.120.0/21","20.37.64.0/18","20.38.132.0/22","20.39.224.0/21","20.41.64.0/18","20.42.0.0/17","20.43.128.0/18","20.44.0.0/18","20.45.128.0/17","20.46.0.0/17","20.47.0.0/17","20.48.0.0/17","20.49.0.0/17","20.50.0.0/17","20.51.0.0/17","20.52.0.0/17","20.53.0.0/17","20.54.0.0/17","20.60.0.0/17","20.150.0.0/17","20.157.0.0/17"], name: "Azure" },
];

function detectCdn(ip: string): string | undefined {
  for (const { cidrs, name } of CDN_CIDRS) {
    if (cidrs.some(cidr => inCidr(ip, cidr))) return name;
  }
  return undefined;
}

export async function checkBlacklist(domain: string, timeout: number = 5000): Promise<BlacklistResult> {
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
  } catch (err: any) {
    console.warn(`[blacklist] Could not resolve IP for "${domain}": ${err?.code || err?.message || err}`);
    return { status: "info", ip: null, providers: [], error: `Could not resolve domain IP: ${err?.code || err?.message || "unknown"}` };
  }

  const cdnProvider = detectCdn(ip);
  const reversed = ip.split(".").reverse().join(".");

  const ipResults = await Promise.allSettled(
    DNSBL_PROVIDERS.map(async ({ provider, host }): Promise<DnsblProviderResult> => {
      try {
        await Promise.race([
          dns.resolve4(`${reversed}.${host}`),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
        ]);
        return { provider, host, listed: true, type: "ip" };
      } catch {
        return { provider, host, listed: false, type: "ip" };
      }
    })
  );

  const domainResults = await Promise.allSettled(
    DOMAIN_BL_PROVIDERS.map(async ({ provider, host }): Promise<DnsblProviderResult> => {
      try {
        await Promise.race([
          dns.resolve4(`${domain}.${host}`),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
        ]);
        return { provider, host, listed: true, type: "domain" };
      } catch {
        return { provider, host, listed: false, type: "domain" };
      }
    })
  );

  const providers: DnsblProviderResult[] = [
    ...domainResults.map(r => r.status === "fulfilled" ? r.value : { provider: "Unknown", host: "", listed: false, type: "domain" as const }),
    ...ipResults.map(r => r.status === "fulfilled" ? r.value : { provider: "Unknown", host: "", listed: false, type: "ip" as const }),
  ];

  const anyListed = providers.some(p => p.listed);

  return { status: anyListed ? "warn" : "pass", ip, cdnProvider, providers };
}
