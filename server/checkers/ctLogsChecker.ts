import type { CheckStatus, CtLogEntry, CtLogsResult, CtFinding, CtDataSource, CtCheckOptions, CaaRecord } from "../types.js";
import { cacheGet, cacheSet } from "../lib/cache.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export type { CtLogEntry, CtLogsResult, CtFinding, CtDataSource };

const CT_LONG_TTL = 24 * 60 * 60 * 1000;

interface CtCacheEntry {
  certs: CtLogEntry[];
  totalCerts: number;
  cachedAt: string;
}

// Built-in fallback CA list
const BUILTIN_CAS = [
  "Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign", "GoDaddy",
  "Amazon", "Google Trust Services", "Microsoft", "Cloudflare", "ZeroSSL",
];

// Mozilla CA list - loaded eagerly at module import
const MOZILLA_CAS: string[] = (() => {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const raw = readFileSync(join(__dirname, "..", "data", "mozilla-trusted-cas.json"), "utf8");
    const cas = JSON.parse(raw) as string[];
    console.log(`[ct] Mozilla CA list loaded: ${cas.length} CAs`);
    return cas;
  } catch {
    console.warn("[ct] Mozilla CA list not found, using built-in fallback");
    return BUILTIN_CAS;
  }
})();

export function loadMozillaCAs(): string[] {
  return MOZILLA_CAS;
}

export function normalizeCAName(name: string): string {
  return name
    .toLowerCase()
    .replace(/\b(inc|llc|ltd|co|corp|gmbh|s\.?a\.?|authority|root|intermediate|certification|certificate|services|trust)\b/gi, "")
    .replace(/[.,]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function isKnownCA(issuerName: string): boolean {
  const norm = normalizeCAName(issuerName);
  return MOZILLA_CAS.some(
    (ca) => norm.includes(normalizeCAName(ca)) || normalizeCAName(ca).includes(norm),
  );
}

async function fetchWithRetry<T>(fn: () => Promise<T>, retries: number, delays: number[]): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err: any) {
      lastError = err;
      if (attempt < retries) await new Promise((r) => setTimeout(r, delays[attempt] ?? 1000));
    }
  }
  throw lastError;
}

async function fetchFromCrtSh(domain: string): Promise<{ certs: CtLogEntry[]; total: number }> {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), 10000);
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json&exclude=expired`, { signal: c.signal, headers: { "User-Agent": "dn-sec/1.0", Accept: "application/json" } });
    if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
    const text = await res.text(); if (!text?.trim()) return { certs: [], total: 0 };
    let data: any[]; try { data = JSON.parse(text); } catch { throw new Error("Invalid JSON"); }
    if (!Array.isArray(data)) return { certs: [], total: 0 };
    const seen = new Set<string>(); const certs: CtLogEntry[] = [];
    for (const e of data) {
      const k = `${e.common_name}|${e.not_before}`;
      if (seen.has(k)) continue; seen.add(k);
      certs.push({ issuerName: e.issuer_name || "Unknown", commonName: e.common_name || domain, notBefore: e.not_before || "", notAfter: e.not_after || "" });
      if (certs.length >= 50) break;
    }
    return { certs, total: data.length };
  } finally { clearTimeout(t); }
}

async function fetchAllFromCertSpotter(domain: string, authenticated: boolean): Promise<{ certs: CtLogEntry[]; total: number }> {
  const apiKey = process.env.CERTSPOTTER_API_KEY || "";
  const headers: Record<string, string> = { "User-Agent": "dn-sec/1.0", Accept: "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
  const subdomains = authenticated ? "true" : "false";
  const allCerts: CtLogEntry[] = []; const seen = new Set<string>();
  let after = ""; let pages = 0; let totalBeforeDedup = 0;
  while (pages < 50) {
    const c = new AbortController(); const t = setTimeout(() => c.abort(), 15000);
    try {
      const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=${subdomains}&expand=dns_names&expand=issuer${after ? "&after=" + after : ""}`;
      const res = await fetch(url, { signal: c.signal, headers });
      if (!res.ok) { if (res.status === 429) throw new Error("CertSpotter rate limited (429)"); throw new Error(`CertSpotter HTTP ${res.status}`); }
      const data: any[] = await res.json();
      if (!Array.isArray(data) || data.length === 0) break;
      totalBeforeDedup += data.length;
      for (const e of data) {
        const key = `${e.dns_names?.[0] || domain}|${(e.not_before || "").slice(0, 10)}|${e.issuer?.friendly_name || e.issuer?.name || ""}`;
        if (seen.has(key)) continue; seen.add(key);
        allCerts.push({ id: String(e.id || ""), issuerName: e.issuer?.friendly_name || e.issuer?.name || e.issuer?.organization || "Unknown", commonName: e.dns_names?.[0] || domain, notBefore: e.not_before || "", notAfter: e.not_after || "" });
      }
      after = String(data[data.length - 1].id); pages++;
      if (data.length < 100 || !apiKey) break;
    } catch (err) {
      if (pages > 0) { console.warn(`[ct] CertSpotter pagination error on page ${pages + 1}: ${(err as any)?.message || err}. Using ${allCerts.length} certs collected so far`); break; }
      throw err;
    } finally { clearTimeout(t); }
  }
  return { certs: allCerts, total: totalBeforeDedup };
}

export function analyzeFindings(certs: CtLogEntry[], totalCerts: number, domain: string, opts?: { sslIssuer?: string | null; caaRecords?: CaaRecord[] }): CtFinding[] {
  const f: CtFinding[] = [];
  const caaIssuers = (opts?.caaRecords || []).filter(r => r.tag === "issue" || r.tag === "issuewild").map(r => r.value);
  const hasCaa = caaIssuers.length > 0;
  for (const cert of certs) {
    if (cert.issuerName === "Unknown") continue;
    if (hasCaa) {
      const normalizedIssuer = normalizeCAName(cert.issuerName);
      const allowed = caaIssuers.some(caa => normalizedIssuer.includes(normalizeCAName(caa)) || normalizeCAName(caa).includes(normalizedIssuer));
      if (!allowed) f.push({ severity: "warn", title: `Cert issued by CA not in CAA: ${cert.issuerName}`, description: `Certificate for "${cert.commonName}" issued by "${cert.issuerName}" which is not authorized in CAA records.`, subdomain: cert.commonName });
    } else {
      if (!isKnownCA(cert.issuerName)) f.push({ severity: "warn", title: `Unknown CA: ${cert.issuerName}`, description: `Certificate for "${cert.commonName}" issued by "${cert.issuerName}" - not in Mozilla Trusted CA list.`, subdomain: cert.commonName });
    }
  }
  if (opts?.sslIssuer) {
    const normalizedSsl = normalizeCAName(opts.sslIssuer);
    for (const cert of certs) {
      if (cert.commonName !== domain && cert.commonName !== `*.${domain}`) continue;
      const normalizedCt = normalizeCAName(cert.issuerName);
      if (normalizedCt !== normalizedSsl && !normalizedCt.includes(normalizedSsl) && !normalizedSsl.includes(normalizedCt)) {
        f.push({ severity: "warn", title: "Cert from different CA than installed", description: `CT log shows cert for "${cert.commonName}" from "${cert.issuerName}", but installed cert is from "${opts.sslIssuer}".`, subdomain: cert.commonName });
      }
    }
  }
  const wc = new Set<string>(); for (const c of certs) if (c.commonName.startsWith("*.")) wc.add(c.commonName);
  if (wc.size > 0) f.push({ severity: wc.size > 3 ? "warn" : "info", title: `${wc.size} wildcard cert${wc.size > 1 ? "s" : ""} found`, description: wc.size > 3 ? `${wc.size} unique wildcard certs - expanded attack surface.` : `Wildcards: ${[...wc].join(", ")}`, subdomain: [...wc][0] });
  if (totalCerts > 500) f.push({ severity: "warn", title: `High cert count: ${totalCerts}`, description: "Verify all certificates are legitimate." });
  else if (totalCerts > 100) f.push({ severity: "info", title: `${totalCerts} certs in CT logs`, description: "Above average but may be normal for large orgs." });
  return f;
}

export function computeStatus(findings: CtFinding[], hasCerts: boolean): CheckStatus {
  if (findings.some(f => f.severity === "fail")) return "fail";
  if (findings.some(f => f.severity === "warn")) return "warn";
  return hasCerts ? "pass" : "info";
}

export function splitCerts(certs: CtLogEntry[], findings: CtFinding[]): { flaggedCerts: CtLogEntry[]; recentCerts: CtLogEntry[] } {
  const sorted = [...certs].sort((a, b) => (b.notBefore || "").localeCompare(a.notBefore || ""));
  const flaggedNames = new Set(findings.map(f => f.subdomain).filter(Boolean));
  const flaggedIssuers = new Set(findings.filter(f => f.title.includes("CA")).map(f => { const m = f.description.match(/issued by "([^"]+)"/); return m?.[1]; }).filter(Boolean));
  const flaggedCerts = sorted.filter(c => flaggedNames.has(c.commonName) || flaggedIssuers.has(c.issuerName));
  const recentCerts = sorted.slice(0, 10);
  return { flaggedCerts, recentCerts };
}

export async function checkCtLogs(domain: string, opts?: CtCheckOptions): Promise<CtLogsResult> {
  const authenticated = opts?.authenticated ?? false;
  const crtShFirst = opts?.crtShFirst ?? false;
  const primaryFn = crtShFirst
    ? () => fetchWithRetry(() => fetchFromCrtSh(domain), 2, [1000, 2000])
    : () => fetchWithRetry(() => fetchAllFromCertSpotter(domain, authenticated), 2, [1000, 2000]);
  const fallbackFn = crtShFirst
    ? () => fetchWithRetry(() => fetchAllFromCertSpotter(domain, authenticated), 1, [1000])
    : () => fetchWithRetry(() => fetchFromCrtSh(domain), 1, [1000]);
  const primarySource: CtDataSource = crtShFirst ? "crt.sh" : "certspotter";
  const fallbackSource: CtDataSource = crtShFirst ? "certspotter" : "crt.sh";
  let result: { certs: CtLogEntry[]; total: number } | null = null;
  let source: CtDataSource = "none";
  try { result = await primaryFn(); source = primarySource; } catch (e: any) {
    const reason = e?.name === "AbortError" ? "timeout (10s)" : e?.message || e;
    console.warn(`[ct] ${primarySource} failed for "${domain}" after retries: ${reason} [${e?.name || "Error"}]`);
  }
  if (!result) {
    try {
      console.warn(`[ct] Falling back to ${fallbackSource} for "${domain}"`);
      result = await fallbackFn(); source = fallbackSource;
    } catch (e: any) {
      const reason = e?.name === "AbortError" ? "timeout (10s)" : e?.message || e;
      console.warn(`[ct] ${fallbackSource} failed for "${domain}": ${reason} [${e?.name || "Error"}]`);
    }
  }
  if (result) {
    cacheSet(`ct-long:${domain}`, { certs: result.certs, totalCerts: result.total, cachedAt: new Date().toISOString() } as CtCacheEntry, CT_LONG_TTL);
    const findings = analyzeFindings(result.certs, result.total, domain, { sslIssuer: opts?.sslIssuer, caaRecords: opts?.caaRecords });
    const { flaggedCerts, recentCerts } = splitCerts(result.certs, findings);
    return { status: computeStatus(findings, result.total > 0), totalCerts: result.total, recentCerts, flaggedCerts, findings, source };
  }
  const cached = cacheGet<CtCacheEntry>(`ct-long:${domain}`);
  if (cached) {
    console.warn(`[ct] Using cached data for "${domain}"`);
    const findings = analyzeFindings(cached.certs, cached.totalCerts, domain, { sslIssuer: opts?.sslIssuer, caaRecords: opts?.caaRecords });
    const { flaggedCerts, recentCerts } = splitCerts(cached.certs, findings);
    return { status: "info", totalCerts: cached.totalCerts, recentCerts, flaggedCerts, findings, source: "cache", fromCache: true, cachedAt: cached.cachedAt };
  }
  console.warn(`[ct] All CT sources unavailable for "${domain}"`);
  return { status: "info", totalCerts: 0, recentCerts: [], flaggedCerts: [], findings: [], source: "none", error: "CT log sources temporarily unavailable" };
}
