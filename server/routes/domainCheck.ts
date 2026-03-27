import { Router } from "express";
import { safeFetchWithHeaders } from "../lib/safeFetch.js";
import { cacheGet, cacheSet } from "../lib/cache.js";
import { analyzeHeaders } from "../checkers/headersAnalyzer.js";
import { checkSpf } from "../checkers/spfChecker.js";
import { checkDmarc } from "../checkers/dmarcChecker.js";
import { checkDkim } from "../checkers/dkimChecker.js";
import { checkDnssec } from "../checkers/dnssecChecker.js";
import { checkCaa } from "../checkers/caaChecker.js";
import { checkMx } from "../checkers/mxChecker.js";
import { checkNs } from "../checkers/nsChecker.js";
import { analyzeSsl } from "../checkers/sslChecker.js";
import { checkDomainExpiry } from "../checkers/domainExpiryChecker.js";
import { checkBlacklist } from "../checkers/blacklistChecker.js";
import { checkCtLogs } from "../checkers/ctLogsChecker.js";
import { checkRedirects } from "../checkers/redirectChecker.js";
import { checkSeo } from "../checkers/seoChecker.js";
import { checkSafeBrowsing } from "../checkers/safeBrowsingChecker.js";
import { checkUrlhaus } from "../checkers/urlhausChecker.js";
import { checkDanglingDns } from "../checkers/danglingDnsChecker.js";
import { parse } from "../../src/lib/parser.js";
import { validate } from "../../src/lib/validator.js";
import type { SafeFetchWithHeadersResponse } from "../types.js";

const router = Router();
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

/** Individual check endpoints — each returns independently */

router.get("/dns", async (req, res) => {
  const domain = req.query.domain as string;
  const nc = req.query.noCache === "1";
  const [spf, dmarc, dkim, dnssec, caa, mx, ns, blacklist, danglingDns] = await Promise.allSettled([
    cached(`spf:${domain}`, nc, () => checkSpf(domain, DNS_TIMEOUT)),
    cached(`dmarc:${domain}`, nc, () => checkDmarc(domain, DNS_TIMEOUT)),
    cached(`dkim:${domain}`, nc, () => checkDkim(domain, DNS_TIMEOUT)),
    cached(`dnssec:${domain}`, nc, () => checkDnssec(domain, DNS_TIMEOUT)),
    cached(`caa:${domain}`, nc, () => checkCaa(domain, DNS_TIMEOUT)),
    cached(`mx:${domain}`, nc, () => checkMx(domain, DNS_TIMEOUT)),
    cached(`ns:${domain}`, nc, () => checkNs(domain, DNS_TIMEOUT)),
    cached(`bl:${domain}`, nc, () => checkBlacklist(domain, DNS_TIMEOUT)),
    cached(`dng:${domain}`, nc, () => checkDanglingDns(domain, DNS_TIMEOUT)),
  ]);
  const x = <T>(s: PromiseSettledResult<T>, f: T): T => s.status === "fulfilled" ? s.value : f;
  res.json({
    spf: x(spf, { status: "fail", record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: "Check failed" }),
    dmarc: x(dmarc, { status: "fail", record: null, validations: [], tags: [], error: "Check failed" }),
    dkim: x(dkim, { status: "info", foundCount: 0, totalChecked: 14, selectors: [] }),
    dnssec: x(dnssec, { status: "fail", enabled: false, error: "Check failed" }),
    caa: x(caa, { status: "fail", records: [], error: "Check failed" }),
    mx: x(mx, { status: "info", records: [] }),
    ns: x(ns, { status: "fail", nameservers: [], error: "Check failed" }),
    blacklist: x(blacklist, { status: "info", ip: null, providers: [], error: "Check failed" }),
    danglingDns: x(danglingDns, { status: "info", records: [], danglingCount: 0, error: "Check failed" }),
  });
});

router.get("/web", async (req, res) => {
  const domain = req.query.domain as string;
  const nc = req.query.noCache === "1";

  // Run security.txt fetch, headers fetch, and TLS check in parallel
  const [fetchResult, headersResult, tlsCert] = await Promise.allSettled([
    cached(`fetch:${domain}`, nc, () => safeFetchWithHeaders(domain, HTTP_TIMEOUT)),
    cached(`hdrs:${domain}`, nc, async () => {
      // Fetch headers from the domain root (independent of security.txt)
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT);
      try {
        const headRes = await fetch(`https://${domain}/`, {
          method: "HEAD", signal: controller.signal, redirect: "follow",
          headers: { "User-Agent": "security-txt-validator/1.0" },
        });
        clearTimeout(timer);
        const h: Record<string, string> = {};
        headRes.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
        return h;
      } catch { clearTimeout(timer); return null; }
    }),
    cached(`tls:${domain}`, nc, async () => {
      // TLS cert extraction is already in safeFetchWithHeaders, but we need it independently
      const tls = await import("node:tls");
      return new Promise<any>((resolve) => {
        const socket = tls.connect({ host: domain, port: 443, servername: domain, timeout: HTTP_TIMEOUT, rejectUnauthorized: false }, () => {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          if (!cert || !cert.valid_from) { resolve(null); return; }
          const validFrom = new Date(cert.valid_from).toISOString();
          const validTo = new Date(cert.valid_to).toISOString();
          const daysRemaining = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
          const sans: string[] = cert.subjectaltname ? cert.subjectaltname.split(",").map((s: string) => s.trim().replace(/^DNS:/, "")) : [];
          resolve({ issuer: String(cert.issuer?.O || cert.issuer?.CN || "Unknown"), subject: String(cert.subject?.CN || "Unknown"), validFrom, validTo, daysRemaining, sans });
        });
        socket.on("error", () => { socket.destroy(); resolve(null); });
        socket.on("timeout", () => { socket.destroy(); resolve(null); });
      });
    }),
  ]);

  // Build security.txt section
  let securityTxt: any;
  const fr = fetchResult.status === "fulfilled" ? fetchResult.value : null;
  if (fr && fr.success) {
    const parsed = parse(fr.content, { withPgp: true });
    const vr = validate(parsed.lines, {
      contentType: fr.contentType, fetchedFrom: fr.fetchedFrom, redirectChain: fr.redirectChain,
      wellKnownFound: fr.wellKnownFound, fallbackUsed: fr.fallbackUsed, usedHttps: true,
    }, parsed.pgp);
    securityTxt = {
      status: vr.status === "valid" ? "pass" : vr.status === "valid-with-warnings" ? "warn" : "fail",
      available: true, validationStatus: vr.status, errorCount: vr.errorCount, warningCount: vr.warningCount,
      findings: vr.findings.map((f: any) => ({ severity: f.severity, title: f.title, explanation: f.explanation })),
      fetchedFrom: fr.fetchedFrom,
    };
  } else {
    const errMsg = fr ? (fr as any).message || "Could not fetch security.txt" : "Could not fetch security.txt";
    securityTxt = { status: "fail", available: false, validationStatus: null, errorCount: 0, warningCount: 0, findings: [], fetchedFrom: null, error: errMsg };
  }

  // Build headers (independent of security.txt)
  const rawHeaders = headersResult.status === "fulfilled" ? headersResult.value : null;
  const headers = rawHeaders ? await analyzeHeaders(rawHeaders, domain) : { status: "info" as const, items: [] };

  // Build SSL (independent)
  const cert = tlsCert.status === "fulfilled" ? tlsCert.value : null;
  const ssl = analyzeSsl(cert);

  res.json({ securityTxt, headers, ssl });
});

router.get("/expiry", async (req, res) => {
  const domain = req.query.domain as string;
  const nc = req.query.noCache === "1";
  res.json(await cached(`exp:${domain}`, nc, () => checkDomainExpiry(domain, HTTP_TIMEOUT)));
});

router.get("/ct", async (req, res) => {
  const domain = req.query.domain as string;
  const nc = req.query.noCache === "1";
  res.json(await cached(`ct:${domain}`, nc, () => checkCtLogs(domain, 20000)));
});

router.get("/redirects", async (req, res) => {
  const domain = req.query.domain as string;
  const nc = req.query.noCache === "1";
  res.json(await cached(`redir:${domain}`, nc, () => checkRedirects(domain, HTTP_TIMEOUT)));
});

router.get("/seo", async (req, res) => {
  const domain = req.query.domain as string;
  const nc = req.query.noCache === "1";
  res.json(await cached(`seo:${domain}`, nc, () => checkSeo(domain, HTTP_TIMEOUT)));
});

router.get("/reputation", async (req, res) => {
  const domain = req.query.domain as string;
  const nc = req.query.noCache === "1";
  const [sb, uh] = await Promise.allSettled([
    cached(`sb:${domain}`, nc, () => checkSafeBrowsing(domain, DNS_TIMEOUT)),
    cached(`uh:${domain}`, nc, () => checkUrlhaus(domain, DNS_TIMEOUT)),
  ]);
  const x = <T>(s: PromiseSettledResult<T>, f: T): T => s.status === "fulfilled" ? s.value : f;
  res.json({
    safeBrowsing: x(sb, { status: "info", safe: null, threats: [], error: "Check failed" }),
    urlhaus: x(uh, { status: "info", listed: false, urlCount: 0, error: "Check failed" }),
  });
});

export default router;
