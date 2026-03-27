import dns from "node:dns/promises";
import type { CheckStatus, SpfResult, SpfMechanism, SpfValidationItem } from "../types.js";

const DNS_LOOKUP_MECHANISMS = ["include", "a", "mx", "redirect", "exists"];

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

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); }
    );
  });
}

export async function checkSpf(domain: string, timeout: number = 5000): Promise<SpfResult> {
  let txtRecords: string[][];
  try {
    txtRecords = await withTimeout(dns.resolveTxt(domain), timeout);
  } catch (err: any) {
    if (err.message === "timeout") {
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

  // Parse mechanisms
  const parts = record.split(/\s+/).slice(1); // skip "v=spf1"
  const mechanisms: SpfMechanism[] = [];
  let dnsLookupCount = 0;

  for (const part of parts) {
    const clean = part.replace(/^[+\-~?]/, "");
    const mechType = clean.split(/[:/]/)[0].toLowerCase();

    if (DNS_LOOKUP_MECHANISMS.includes(mechType)) {
      dnsLookupCount++;
    }

    const desc = MECHANISM_DESCRIPTIONS[mechType] || "Unknown mechanism";
    mechanisms.push({ mechanism: part, description: desc });
  }

  // DNS lookup count check
  if (dnsLookupCount > 10) {
    validations.push({ check: "DNS lookup limit", status: "fail", detail: `${dnsLookupCount} DNS lookups — exceeds RFC 7208 limit of 10`, ref: SPF_RFC + "#section-4.6.4" });
  } else {
    validations.push({ check: "DNS lookup limit", status: "pass", detail: `${dnsLookupCount} of 10 DNS lookups used`, ref: SPF_RFC + "#section-4.6.4" });
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
