/**
 * Client-side security score calculator.
 * Mirrors server/scoreCalculator.ts logic but runs in the browser.
 */

const WEIGHTS: Record<string, number> = {
  ssl: 15, headers: 15, spf: 8, dmarc: 8, dkim: 6, dnssec: 6,
  caa: 4, redirects: 6, blacklist: 8, safeBrowsing: 6, urlhaus: 4,
  danglingDns: 5, domainExpiry: 3, securityTxt: 3, mx: 2, ns: 1,
};

function statusToPoints(status: string): number {
  if (status === "pass") return 1;
  if (status === "warn") return 0.5;
  if (status === "fail") return 0;
  return 1; // info
}

export interface ClientScoreResult {
  total: number;
  breakdown: Record<string, { earned: number; max: number }>;
}

/**
 * Calculate score from the check results available on the client.
 * dns, web, expiry, ct, redirects, seo, reputation — same shape as API responses.
 * Returns null if not enough data (dns + web minimum).
 */
export function calculateClientScore(
  dns: any,
  web: any,
  expiry: any,
  redirects: any,
  reputation: any,
): ClientScoreResult | null {
  if (!dns || !web) return null;

  const flat: Record<string, any> = {};

  // DNS section
  if (dns.spf) flat.spf = dns.spf;
  if (dns.dmarc) flat.dmarc = dns.dmarc;
  if (dns.dkim) flat.dkim = dns.dkim;
  if (dns.dnssec) flat.dnssec = dns.dnssec;
  if (dns.caa) flat.caa = dns.caa;
  if (dns.mx) flat.mx = dns.mx;
  if (dns.ns) flat.ns = dns.ns;
  if (dns.blacklist) flat.blacklist = dns.blacklist;
  if (dns.danglingDns) flat.danglingDns = dns.danglingDns;

  // Web section
  if (web.securityTxt) flat.securityTxt = web.securityTxt;
  if (web.headers) flat.headers = web.headers;
  if (web.ssl) flat.ssl = web.ssl;

  // Other sections
  if (expiry) flat.domainExpiry = expiry;
  if (redirects) flat.redirects = redirects;
  if (reputation?.safeBrowsing) flat.safeBrowsing = reputation.safeBrowsing;
  if (reputation?.urlhaus) flat.urlhaus = reputation.urlhaus;

  const breakdown: Record<string, { earned: number; max: number }> = {};
  let total = 0;

  for (const [category, weight] of Object.entries(WEIGHTS)) {
    const result = flat[category];
    if (!result) continue;

    let earned: number;

    if (category === "headers" && result.items?.length) {
      const sum = result.items.reduce((acc: number, item: any) => acc + statusToPoints(item.status), 0);
      earned = (sum / result.items.length) * weight;
    } else if (category === "spf" && result.validations?.length) {
      const sum = result.validations.reduce((acc: number, v: any) => acc + statusToPoints(v.status), 0);
      earned = (sum / result.validations.length) * weight;
    } else if (category === "dmarc" && result.validations?.length) {
      const sum = result.validations.reduce((acc: number, v: any) => acc + statusToPoints(v.status), 0);
      earned = (sum / result.validations.length) * weight;
    } else if (category === "redirects" && result.items?.length) {
      const sum = result.items.reduce((acc: number, item: any) => acc + statusToPoints(item.status), 0);
      earned = (sum / result.items.length) * weight;
    } else {
      earned = statusToPoints(result.status) * weight;
    }

    breakdown[category] = { earned: Math.round(earned * 100) / 100, max: weight };
    total += earned;
  }

  return { total: Math.round(total), breakdown };
}
