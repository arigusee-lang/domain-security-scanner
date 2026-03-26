import { Router } from "express";
import { safeFetchWithHeaders } from "../lib/safeFetch.js";
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
import type {
  DomainCheckResponse,
  SecurityTxtSection,
  HeadersResult,
  SpfResult,
  DmarcResult,
  DkimResult,
  DnssecResult,
  CaaResult,
  MxResult,
  NsResult,
  SslResult,
  DomainExpiryResult,
  BlacklistResult,
  CtLogsResult,
  RedirectResult,
  SeoResult,
  SafeBrowsingResult,
  UrlhausResult,
  DanglingDnsResult,
  SafeFetchWithHeadersResponse,
} from "../types.js";

const router = Router();
const DNS_TIMEOUT = 5000;
const HTTP_TIMEOUT = 8000;

router.get("/", async (req, res) => {
  const domain = req.query.domain as string;

  const [
    fetchSettled,
    spfSettled,
    dmarcSettled,
    dkimSettled,
    dnssecSettled,
    caaSettled,
    mxSettled,
    nsSettled,
    domainExpirySettled,
    blacklistSettled,
    ctLogsSettled,
    redirectsSettled,
    seoSettled,
    safeBrowsingSettled,
    urlhausSettled,
    danglingDnsSettled,
  ] = await Promise.allSettled([
    safeFetchWithHeaders(domain, HTTP_TIMEOUT),
    checkSpf(domain, DNS_TIMEOUT),
    checkDmarc(domain, DNS_TIMEOUT),
    checkDkim(domain, DNS_TIMEOUT),
    checkDnssec(domain, DNS_TIMEOUT),
    checkCaa(domain, DNS_TIMEOUT),
    checkMx(domain, DNS_TIMEOUT),
    checkNs(domain, DNS_TIMEOUT),
    checkDomainExpiry(domain, HTTP_TIMEOUT),
    checkBlacklist(domain, DNS_TIMEOUT),
    checkCtLogs(domain, 15000),
    checkRedirects(domain, DNS_TIMEOUT),
    checkSeo(domain, HTTP_TIMEOUT),
    checkSafeBrowsing(domain, DNS_TIMEOUT),
    checkUrlhaus(domain, DNS_TIMEOUT),
    checkDanglingDns(domain, DNS_TIMEOUT),
  ]);

  // Extract fetch result
  let securityTxt: SecurityTxtSection;
  let headers: HeadersResult;
  let ssl: SslResult;

  if (fetchSettled.status === "fulfilled" && fetchSettled.value.success) {
    const fetchResult = fetchSettled.value as SafeFetchWithHeadersResponse;

    // Parse and validate security.txt
    const parsed = parse(fetchResult.content, { withPgp: true });
    const validationResult = validate(parsed.lines, {
      contentType: fetchResult.contentType,
      fetchedFrom: fetchResult.fetchedFrom,
      redirectChain: fetchResult.redirectChain,
      wellKnownFound: fetchResult.wellKnownFound,
      fallbackUsed: fetchResult.fallbackUsed,
      usedHttps: true,
    }, parsed.pgp);

    securityTxt = {
      status: validationResult.status === "valid" ? "pass" : validationResult.status === "valid-with-warnings" ? "warn" : "fail",
      available: true,
      validationStatus: validationResult.status,
      errorCount: validationResult.errorCount,
      warningCount: validationResult.warningCount,
      findings: validationResult.findings.map(f => ({ severity: f.severity, title: f.title, explanation: f.explanation })),
      fetchedFrom: fetchResult.fetchedFrom,
    };

    headers = analyzeHeaders(fetchResult.responseHeaders);
    ssl = analyzeSsl(fetchResult.tlsCert);
  } else {
    const errorMsg = fetchSettled.status === "rejected"
      ? fetchSettled.reason?.message || "Fetch failed"
      : "Could not fetch security.txt";

    securityTxt = {
      status: "fail",
      available: false,
      validationStatus: null,
      errorCount: 0,
      warningCount: 0,
      findings: [],
      fetchedFrom: null,
      error: errorMsg,
    };
    headers = { status: "info", items: [] };
    ssl = { status: "fail", issuer: null, subject: null, validFrom: null, validTo: null, daysRemaining: null, sans: [], error: "Could not establish HTTPS connection" };
  }

  const extract = <T>(settled: PromiseSettledResult<T>, fallback: T): T =>
    settled.status === "fulfilled" ? settled.value : fallback;

  const response: DomainCheckResponse = {
    domain,
    timestamp: new Date().toISOString(),
    securityTxt,
    headers,
    spf: extract<SpfResult>(spfSettled, { status: "fail", record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: "Check failed" }),
    dmarc: extract<DmarcResult>(dmarcSettled, { status: "fail", record: null, validations: [], tags: [], error: "Check failed" }),
    dkim: extract<DkimResult>(dkimSettled, { status: "info", foundCount: 0, totalChecked: 14, selectors: [] }),
    dnssec: extract<DnssecResult>(dnssecSettled, { status: "fail", enabled: false, error: "Check failed" }),
    caa: extract<CaaResult>(caaSettled, { status: "fail", records: [], error: "Check failed" }),
    mx: extract<MxResult>(mxSettled, { status: "info", records: [] }),
    ns: extract<NsResult>(nsSettled, { status: "fail", nameservers: [], error: "Check failed" }),
    ssl,
    domainExpiry: extract<DomainExpiryResult>(domainExpirySettled, { status: "info", expirationDate: null, daysRemaining: null, error: "Check failed" }),
    blacklist: extract<BlacklistResult>(blacklistSettled, { status: "info", ip: null, providers: [], error: "Check failed" }),
    ctLogs: extract<CtLogsResult>(ctLogsSettled, { status: "info", totalCerts: 0, recentCerts: [], error: "Check failed" }),
    redirects: extract<RedirectResult>(redirectsSettled, { status: "info", httpsRedirect: false, wwwBehavior: null, items: [], error: "Check failed" }),
    seo: extract<SeoResult>(seoSettled, { status: "info", items: [], error: "Check failed" }),
    safeBrowsing: extract<SafeBrowsingResult>(safeBrowsingSettled, { status: "info", safe: null, threats: [], error: "Check failed" }),
    urlhaus: extract<UrlhausResult>(urlhausSettled, { status: "info", listed: false, urlCount: 0, error: "Check failed" }),
    danglingDns: extract<DanglingDnsResult>(danglingDnsSettled, { status: "info", records: [], danglingCount: 0, error: "Check failed" }),
  };

  res.json(response);
});

export default router;
