/**
 * Programmatic domain check pipeline — reusable by batch scanner and scheduler.
 * Mirrors the logic in server/routes/domainCheck.ts but returns a DomainCheckResponse
 * directly instead of sending HTTP responses.
 */
import { safeFetchWithHeaders } from "./lib/safeFetch.js";
import { ssrfSafeFetch, ssrfSafeTlsConnect } from "./lib/ipCheck.js";
import { cacheGet, cacheSet } from "./lib/cache.js";
import { analyzeHeaders } from "./checkers/headersAnalyzer.js";
import { checkSpf } from "./checkers/spfChecker.js";
import { checkDmarc } from "./checkers/dmarcChecker.js";
import { checkDkim } from "./checkers/dkimChecker.js";
import { checkDnssec } from "./checkers/dnssecChecker.js";
import { checkCaa } from "./checkers/caaChecker.js";
import { checkMx } from "./checkers/mxChecker.js";
import { checkNs } from "./checkers/nsChecker.js";
import { analyzeSsl, analyzeSslDeep } from "./checkers/sslChecker.js";
import type { ChainCertInfo } from "./checkers/sslChecker.types.js";
import { checkDomainExpiry } from "./checkers/domainExpiryChecker.js";
import { checkBlacklist } from "./checkers/blacklistChecker.js";
import { checkCtLogs } from "./checkers/ctLogsChecker.js";
import { checkRedirects } from "./checkers/redirectChecker.js";
import { checkSeo } from "./checkers/seoChecker.js";
import { checkSafeBrowsing } from "./checkers/safeBrowsingChecker.js";
import { checkUrlhaus } from "./checkers/urlhausChecker.js";
import { checkDanglingDns } from "./checkers/danglingDnsChecker.js";
import { parse } from "../src/lib/parser.js";
import { validate } from "../src/lib/validator.js";
import type { DomainCheckResponse, ScanConfig, CtCheckOptions, SslResult } from "./types.js";

const DNS_TIMEOUT = 8000;
const HTTP_TIMEOUT = 15000;
const CACHE_TTL = 5 * 60 * 1000;

/** Helper: run a checker with caching */
async function cached<T>(key: string, noCache: boolean, fn: () => Promise<T>): Promise<T> {
  if (!noCache) {
    const hit = cacheGet<T>(key);
    if (hit) return hit;
  }
  const result = await fn();
  cacheSet(key, result, CACHE_TTL);
  return result;
}

function settled<T>(s: PromiseSettledResult<T>, fallback: T): T {
  return s.status === "fulfilled" ? s.value : fallback;
}

/**
 * Runs the full domain check pipeline programmatically.
 * Returns a complete DomainCheckResponse — same data as the HTTP endpoints produce.
 */
export async function runDomainCheck(
  domain: string,
  config: ScanConfig,
): Promise<DomainCheckResponse> {
  const nc = config.noCache;
  const checks = config.checks;

  // --- DNS checks (parallel) ---
  const dnsPromises = await Promise.allSettled([
    checks.spf ? cached(`spf:${domain}`, nc, () => checkSpf(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.dmarc ? cached(`dmarc:${domain}`, nc, () => checkDmarc(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.dkim ? cached(`dkim:${domain}`, nc, () => checkDkim(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.dnssec ? cached(`dnssec:${domain}`, nc, () => checkDnssec(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.caa ? cached(`caa:${domain}`, nc, () => checkCaa(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.mx ? cached(`mx:${domain}`, nc, () => checkMx(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.ns ? cached(`ns:${domain}`, nc, () => checkNs(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.blacklist ? cached(`bl:${domain}`, nc, () => checkBlacklist(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.danglingDns ? cached(`dng:${domain}`, nc, () => checkDanglingDns(domain, DNS_TIMEOUT)) : Promise.resolve(null),
  ]);

  const [spfR, dmarcR, dkimR, dnssecR, caaR, mxR, nsR, blacklistR, danglingDnsR] = dnsPromises;

  const spf = settled(spfR, null) ?? { status: "fail" as const, record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: "Check failed" };
  const dmarc = settled(dmarcR, null) ?? { status: "fail" as const, record: null, validations: [], tags: [], error: "Check failed" };
  const dkim = settled(dkimR, null) ?? { status: "info" as const, foundCount: 0, totalChecked: 14, selectors: [] };
  const dnssec = settled(dnssecR, null) ?? { status: "fail" as const, enabled: false, error: "Check failed" };
  const caa = settled(caaR, null) ?? { status: "fail" as const, records: [], error: "Check failed" };
  const mx = settled(mxR, null) ?? { status: "info" as const, records: [] };
  const ns = settled(nsR, null) ?? { status: "fail" as const, nameservers: [], error: "Check failed" };
  const blacklist = settled(blacklistR, null) ?? { status: "info" as const, ip: null, providers: [], error: "Check failed" };
  const danglingDns = settled(danglingDnsR, null) ?? { status: "info" as const, records: [], danglingCount: 0, error: "Check failed" };

  // --- Web checks (parallel) ---
  const webPromises = await Promise.allSettled([
    checks.securityTxt
      ? cached(`fetch:${domain}`, nc, () => safeFetchWithHeaders(domain, HTTP_TIMEOUT))
      : Promise.resolve(null),
    checks.headers
      ? cached(`hdrs:${domain}`, nc, async () => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT);
          try {
            const headRes = await ssrfSafeFetch(`https://${domain}/`, {
              method: "HEAD",
              signal: controller.signal,
              redirect: "follow",
              headers: { "User-Agent": "security-txt-validator/1.0" },
            });
            clearTimeout(timer);
            const h: Record<string, string> = {};
            headRes.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
            return h;
          } catch {
            clearTimeout(timer);
            return null;
          }
        })
      : Promise.resolve(null),
    checks.ssl
      ? cached(`tls:${domain}`, nc, async () => {
          return new Promise<any>(async (resolve) => {
            try {
              const socket = await ssrfSafeTlsConnect(
                { host: domain, port: 443, servername: domain, timeout: HTTP_TIMEOUT, rejectUnauthorized: false },
              );

              // Get detailed cert (with issuerCertificate linked list) and basic cert (with raw Buffer)
              let detailedCert: any;
              let basicCert: any;
              try {
                detailedCert = socket.getPeerCertificate(true);
                basicCert = socket.getPeerCertificate(false);
              } catch {
                detailedCert = null;
                basicCert = null;
              }
              socket.destroy();

              const cert = detailedCert || basicCert;
              if (!cert || !cert.valid_from) { resolve(null); return; }

              const validFrom = new Date(cert.valid_from).toISOString();
              const validTo = new Date(cert.valid_to).toISOString();
              const daysRemaining = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
              const sans: string[] = cert.subjectaltname
                ? cert.subjectaltname.split(",").map((s: string) => s.trim().replace(/^DNS:/, ""))
                : [];

              // Walk issuerCertificate linked list → ChainCertInfo[] with cycle detection
              let chainCerts: ChainCertInfo[] | undefined;
              try {
                if (detailedCert) {
                  chainCerts = [];
                  let current = detailedCert;
                  const seen = new Set<string>();
                  while (current && current.fingerprint256 && !seen.has(current.fingerprint256)) {
                    seen.add(current.fingerprint256);
                    const subjectCN = String(current.subject?.CN || "Unknown");
                    const issuerStr = String(current.issuer?.O || current.issuer?.CN || "Unknown");
                    const isSelfSigned = (current.subject?.CN === current.issuer?.CN)
                      && (current.subject?.O === current.issuer?.O);
                    chainCerts.push({
                      subject: subjectCN,
                      issuer: issuerStr,
                      validFrom: new Date(current.valid_from).toISOString(),
                      validTo: new Date(current.valid_to).toISOString(),
                      isSelfSigned,
                      role: "leaf", // roles assigned by validateChain
                    });
                    current = current.issuerCertificate;
                  }
                }
              } catch {
                chainCerts = undefined;
              }

              // Extract raw Buffer for SCT parsing
              let rawLeafCert: Buffer | undefined;
              try {
                if (basicCert?.raw) {
                  rawLeafCert = basicCert.raw;
                }
              } catch {
                rawLeafCert = undefined;
              }

              resolve({
                issuer: String(cert.issuer?.O || cert.issuer?.CN || "Unknown"),
                subject: String(cert.subject?.CN || "Unknown"),
                validFrom, validTo, daysRemaining, sans,
                chainCerts,
                rawLeafCert,
              });
            } catch { resolve(null); }
          });
        })
      : Promise.resolve(null),
  ]);

  const [fetchResultR, headersResultR, tlsCertR] = webPromises;

  // Build security.txt section
  let securityTxt: DomainCheckResponse["securityTxt"];
  const fr = settled(fetchResultR, null);
  if (fr && (fr as any).success) {
    const successFr = fr as any;
    const parsed = parse(successFr.content, { withPgp: true });
    const vr = validate(parsed.lines, {
      contentType: successFr.contentType,
      fetchedFrom: successFr.fetchedFrom,
      redirectChain: successFr.redirectChain,
      wellKnownFound: successFr.wellKnownFound,
      fallbackUsed: successFr.fallbackUsed,
      usedHttps: true,
    }, parsed.pgp);
    securityTxt = {
      status: vr.status === "valid" ? "pass" : vr.status === "valid-with-warnings" ? "warn" : "fail",
      available: true,
      validationStatus: vr.status,
      errorCount: vr.errorCount,
      warningCount: vr.warningCount,
      findings: vr.findings.map((f: any) => ({ severity: f.severity, title: f.title, explanation: f.explanation })),
      fetchedFrom: successFr.fetchedFrom,
    };
  } else {
    const errMsg = fr ? (fr as any).message || "Could not fetch security.txt" : "Could not fetch security.txt";
    securityTxt = {
      status: "fail", available: false, validationStatus: null,
      errorCount: 0, warningCount: 0, findings: [], fetchedFrom: null, error: errMsg,
    };
  }

  // Build headers
  const rawHeaders = settled(headersResultR, null) as Record<string, string> | null;
  const headers = rawHeaders ? await analyzeHeaders(rawHeaders, domain) : { status: "info" as const, items: [] };

  // Build SSL
  const tlsCertData = settled(tlsCertR, null) as any;
  let ssl: SslResult;
  if (tlsCertData) {
    const { chainCerts, rawLeafCert, ...certInfo } = tlsCertData;
    ssl = analyzeSslDeep(certInfo, chainCerts, rawLeafCert);
  } else {
    ssl = analyzeSsl(null);
  }

  // --- Additional checks (parallel) ---
  // Build CtCheckOptions from SSL and CAA results (available from earlier waves)
  const ctOpts: CtCheckOptions = {
    authenticated: !!config.authenticated,
    sslIssuer: ssl?.issuer ?? null,
    caaRecords: caa?.records ?? [],
    crtShFirst: config.crtShFirst ?? false,
  };

  const extraPromises = await Promise.allSettled([
    checks.domainExpiry ? cached(`exp:${domain}`, nc, () => checkDomainExpiry(domain, HTTP_TIMEOUT)) : Promise.resolve(null),
    checks.ctLogs ? cached(`ct:${domain}`, nc, () => checkCtLogs(domain, ctOpts)) : Promise.resolve(null),
    checks.redirects ? cached(`redir:${domain}`, nc, () => checkRedirects(domain, HTTP_TIMEOUT)) : Promise.resolve(null),
    checks.seo ? cached(`seo:${domain}`, nc, () => checkSeo(domain, HTTP_TIMEOUT)) : Promise.resolve(null),
    checks.reputation ? cached(`sb:${domain}`, nc, () => checkSafeBrowsing(domain, DNS_TIMEOUT)) : Promise.resolve(null),
    checks.reputation ? cached(`uh:${domain}`, nc, () => checkUrlhaus(domain, DNS_TIMEOUT)) : Promise.resolve(null),
  ]);

  const [domainExpiryR, ctLogsR, redirectsR, seoR, safeBrowsingR, urlhausR] = extraPromises;

  const domainExpiry = settled(domainExpiryR, null) ?? { status: "info" as const, expirationDate: null, daysRemaining: null, error: "Check failed" };
  const ctLogs = settled(ctLogsR, null) ?? { status: "info" as const, totalCerts: 0, recentCerts: [], error: "Check failed" };
  const redirects = settled(redirectsR, null) ?? { status: "info" as const, httpsRedirect: false, wwwBehavior: null, items: [], error: "Check failed" };
  const seo = settled(seoR, null) ?? { status: "info" as const, items: [], error: "Check failed" };
  const safeBrowsing = settled(safeBrowsingR, null) ?? { status: "info" as const, safe: null, threats: [], error: "Check failed" };
  const urlhaus = settled(urlhausR, null) ?? { status: "info" as const, listed: false, urlCount: 0, error: "Check failed" };

  return {
    domain,
    timestamp: new Date().toISOString(),
    securityTxt,
    headers,
    spf,
    dmarc,
    dkim,
    dnssec,
    caa,
    mx,
    ns,
    ssl,
    domainExpiry,
    blacklist,
    ctLogs,
    redirects,
    seo,
    safeBrowsing,
    urlhaus,
    danglingDns,
  } as DomainCheckResponse;
}
