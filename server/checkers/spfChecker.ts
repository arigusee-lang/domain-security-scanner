import dns from "node:dns/promises";
import type { CheckStatus, SpfResult, SpfMechanism, SpfValidationItem } from "../types.js";
import { createLogger } from "../lib/logger.js";
import { safeResolve } from "../lib/dnsResolve.js";

const log = createLogger("spf");

const MECHANISM_DESCRIPTIONS: Record<string, string> = {
  "include": "Authorizes another domain's SPF policy",
  "a": "Authorizes the domain's A/AAAA records",
  "mx": "Authorizes the domain's MX hosts",
  "ip4": "Authorizes an IPv4 address or range",
  "ip6": "Authorizes an IPv6 address or range",
  "all": "Catch-all mechanism",
  "redirect": "Redirects SPF evaluation to another domain",
  "exists": "Passes if a DNS A record exists for the given domain",
  "ptr": "Deprecated mechanism — checks reverse DNS",
};

const SPF_RECURSE_TIMEOUT = 3000;
const SPF_MAX_DEPTH = 12;
const SPF_LOOKUP_LIMIT = 10;

/** Strip qualifier prefix (+ - ~ ?) and return lowercase. */
function stripQualifier(part: string): string {
  return part.replace(/^[+\-~?]/, "").toLowerCase();
}

/** Extract the domain target from include:/redirect=/a:/mx:/exists:/ptr: parts. Returns null if no explicit target or if the target contains SPF macros. */
function extractTarget(part: string): string | null {
  const lower = stripQualifier(part);
  let target: string | undefined;
  if (lower.startsWith("include:")) target = part.replace(/^[+\-~?]/, "").substring("include:".length);
  else if (lower.startsWith("redirect=")) target = part.substring(part.toLowerCase().indexOf("redirect=") + "redirect=".length);
  else if (lower.startsWith("a:")) target = part.replace(/^[+\-~?]/, "").substring("a:".length);
  else if (lower.startsWith("mx:")) target = part.replace(/^[+\-~?]/, "").substring("mx:".length);
  else if (lower.startsWith("exists:")) target = part.replace(/^[+\-~?]/, "").substring("exists:".length);
  else if (lower.startsWith("ptr:")) target = part.replace(/^[+\-~?]/, "").substring("ptr:".length);
  if (!target) return null;
  // Drop CIDR suffix
  target = target.split("/")[0];
  // Skip macro-containing targets — they require runtime evaluation (sender IP, etc.)
  if (target.includes("%")) return null;
  return target || null;
}

/**
 * Returns true if the part is a DNS-lookup-causing mechanism per RFC 7208 §4.6.4:
 * include, a, mx, ptr, exists (and the redirect= modifier).
 */
function isDnsLookupPart(part: string): boolean {
  const lower = stripQualifier(part);
  if (lower.startsWith("include:")) return true;
  if (lower.startsWith("redirect=")) return true;
  if (lower === "a" || lower.startsWith("a:") || lower.startsWith("a/")) return true;
  if (lower === "mx" || lower.startsWith("mx:") || lower.startsWith("mx/")) return true;
  if (lower === "ptr" || lower.startsWith("ptr:")) return true;
  if (lower.startsWith("exists:")) return true;
  return false;
}

async function resolveSpfRecord(domain: string, timeout: number): Promise<string | null> {
  try {
    const txt = await safeResolve(() => dns.resolveTxt(domain), timeout);
    const records = txt.map(r => r.join("")).filter(r => r.toLowerCase().startsWith("v=spf1"));
    return records.length === 1 ? records[0] : null;
  } catch { return null; }
}

/**
 * Recursively count DNS lookups for an SPF record per RFC 7208 §4.6.4.
 * Returns both the count and whether traversal was capped (cycle / depth / limit).
 *
 * We stop counting *deeper* lookups once we exceed SPF_LOOKUP_LIMIT — at that
 * point the record is already non-compliant; we report the partial count plus
 * a "limit-exceeded" flag so the UI can say "≥ 11 lookups" rather than try to
 * be precise about an invalid configuration.
 */
async function countSpfLookups(
  domain: string,
  depth: number,
  visited: Set<string>,
  timeout: number,
): Promise<number> {
  if (depth > SPF_MAX_DEPTH) return 0;
  const key = domain.toLowerCase();
  if (visited.has(key)) return 0; // cycle protection
  visited.add(key);

  const record = await resolveSpfRecord(domain, timeout);
  if (!record) return 0;

  const parts = record.split(/\s+/).slice(1);
  let count = 0;

  for (const raw of parts) {
    if (!isDnsLookupPart(raw)) continue;
    count++;
    if (count > SPF_LOOKUP_LIMIT) return count; // already over limit, no point recursing further
    const lower = stripQualifier(raw);
    if (lower.startsWith("include:") || lower.startsWith("redirect=")) {
      const target = extractTarget(raw);
      if (target) {
        count += await countSpfLookups(target, depth + 1, visited, timeout);
        if (count > SPF_LOOKUP_LIMIT) return count;
      }
    }
  }

  return count;
}

export async function checkSpf(domain: string, timeout: number = 5000): Promise<SpfResult> {
  let txtRecords: string[][];
  try {
    txtRecords = await safeResolve(() => dns.resolveTxt(domain), timeout);
  } catch (err: any) {
    if (err.message === "timeout") {
      log.warn({ domain }, "DNS lookup timed out");
      return { status: "fail", record: null, validations: [], mechanisms: [], dnsLookupCount: 0, error: "DNS lookup timed out" };
    }
    return { status: "fail", record: null, validations: [{ check: "SPF record", status: "fail", detail: "No SPF record found", ref: "https://www.rfc-editor.org/rfc/rfc7208" }], mechanisms: [], dnsLookupCount: 0 };
  }

  const spfRecords = txtRecords.map(r => r.join("")).filter(r => r.toLowerCase().startsWith("v=spf1"));

  if (spfRecords.length === 0) {
    return { status: "fail", record: null, validations: [{ check: "SPF record", status: "fail", detail: "No SPF record published", ref: "https://www.rfc-editor.org/rfc/rfc7208" }], mechanisms: [], dnsLookupCount: 0 };
  }

  const validations: SpfValidationItem[] = [];

  const SPF_RFC = "https://www.rfc-editor.org/rfc/rfc7208";

  if (spfRecords.length > 1) {
    validations.push({ check: "Single record", status: "fail", detail: `${spfRecords.length} SPF records found — must have exactly one per RFC 7208`, ref: SPF_RFC + "#section-3.2" });
    return { status: "fail", record: spfRecords[0], validations, mechanisms: [], dnsLookupCount: 0 };
  }

  const record = spfRecords[0];
  validations.push({ check: "SPF record found", status: "pass", detail: "v=spf1 record published", ref: SPF_RFC });

  // Parse mechanisms (display only)
  const parts = record.split(/\s+/).slice(1); // skip "v=spf1"
  const mechanisms: SpfMechanism[] = [];

  for (const part of parts) {
    const clean = part.replace(/^[+\-~?]/, "");
    const mechType = clean.split(/[:/=]/)[0].toLowerCase();
    const desc = MECHANISM_DESCRIPTIONS[mechType] || "Unknown mechanism";
    mechanisms.push({ mechanism: part, description: desc });
  }

  // Recursively count DNS lookups across includes/redirects (RFC 7208 §4.6.4).
  // Macro-containing targets are skipped (they need runtime resolution); cycles
  // are detected via the visited set.
  let dnsLookupCount = 0;
  let macroSkipped = false;
  const visited = new Set<string>([domain.toLowerCase()]);

  for (const raw of parts) {
    if (!isDnsLookupPart(raw)) continue;
    dnsLookupCount++;
    const lower = stripQualifier(raw);
    if (lower.startsWith("include:") || lower.startsWith("redirect=")) {
      const target = extractTarget(raw);
      if (target) {
        dnsLookupCount += await countSpfLookups(target, 1, visited, SPF_RECURSE_TIMEOUT);
      } else if ((stripQualifier(raw).startsWith("include:") || stripQualifier(raw).startsWith("redirect=")) && raw.includes("%")) {
        macroSkipped = true;
      }
    }
    if (dnsLookupCount > SPF_LOOKUP_LIMIT) break;
  }

  const lookupNote = macroSkipped ? " (macro-based includes counted as 1 each, not recursed)" : "";
  if (dnsLookupCount > SPF_LOOKUP_LIMIT) {
    validations.push({ check: "DNS lookup limit", status: "fail", detail: `${dnsLookupCount}+ DNS lookups — exceeds RFC 7208 limit of 10${lookupNote}`, ref: SPF_RFC + "#section-4.6.4" });
  } else if (dnsLookupCount === SPF_LOOKUP_LIMIT) {
    validations.push({ check: "DNS lookup limit", status: "warn", detail: `${dnsLookupCount} of 10 DNS lookups — at the RFC 7208 limit, no headroom for new includes${lookupNote}`, ref: SPF_RFC + "#section-4.6.4" });
  } else {
    validations.push({ check: "DNS lookup limit", status: "pass", detail: `${dnsLookupCount} of 10 DNS lookups used${lookupNote}`, ref: SPF_RFC + "#section-4.6.4" });
  }

  // Check 'all' mechanism
  const allMech = parts.find(p => p.endsWith("all") && /^[+\-~?]?all$/.test(p));
  if (allMech) {
    const qualifier = allMech.startsWith("+") || allMech === "all" ? "+" : allMech[0];
    if (qualifier === "+") {
      validations.push({ check: "Catch-all policy", status: "fail", detail: "+all — allows any server to send email (too permissive)", ref: SPF_RFC + "#section-5.1" });
    } else if (qualifier === "-") {
      validations.push({ check: "Catch-all policy", status: "pass", detail: "-all — strict policy, unauthorized senders rejected", ref: SPF_RFC + "#section-5.1" });
    } else if (qualifier === "~") {
      validations.push({ check: "Catch-all policy", status: "warn", detail: "~all — softfail, unauthorized senders marked but not rejected", ref: SPF_RFC + "#section-5.1" });
    } else if (qualifier === "?") {
      validations.push({ check: "Catch-all policy", status: "warn", detail: "?all — neutral, no policy assertion", ref: SPF_RFC + "#section-5.1" });
    }
  } else {
    validations.push({ check: "Catch-all policy", status: "warn", detail: "No 'all' mechanism found — implicit ?all", ref: SPF_RFC + "#section-5.1" });
  }

  // Sort: fail first, then warn, then pass
  const order: Record<string, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
  validations.sort((a, b) => (order[a.status] ?? 2) - (order[b.status] ?? 2));

  const overall: CheckStatus = validations.some(v => v.status === "fail") ? "fail"
    : validations.some(v => v.status === "warn") ? "warn" : "pass";

  return { status: overall, record, validations, mechanisms, dnsLookupCount };
}
