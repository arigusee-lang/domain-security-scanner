import dns from "node:dns/promises";
import type { CheckStatus, DmarcResult, DmarcReportUri, DmarcTag, DmarcValidationItem } from "../types.js";
import { createLogger } from "../lib/logger.js";
import { safeResolve } from "../lib/dnsResolve.js";

const log = createLogger("dmarc");

const EXTERNAL_AUTH_TIMEOUT = 3000;

/** Parse an "mailto:user@host[!size]" URI. Returns null fields for non-mailto or malformed. */
function parseReportUri(uri: string, fromDomain: string): DmarcReportUri {
  const trimmed = uri.trim();
  if (!trimmed.toLowerCase().startsWith("mailto:")) {
    return { uri: trimmed, email: null, domain: null, external: false, authorized: null };
  }
  // Strip optional !size suffix (max report size in bytes/k/m/g/t per RFC 7489 §6.2)
  const afterMailto = trimmed.substring("mailto:".length);
  const email = afterMailto.split("!")[0].trim();
  const at = email.indexOf("@");
  if (at === -1 || at === email.length - 1) {
    return { uri: trimmed, email: email || null, domain: null, external: false, authorized: null };
  }
  const domain = email.substring(at + 1).toLowerCase();
  const from = fromDomain.toLowerCase();
  // Internal if same domain or a subdomain of either side
  const internal = domain === from || domain.endsWith("." + from) || from.endsWith("." + domain);
  return { uri: trimmed, email, domain, external: !internal, authorized: null };
}

/**
 * RFC 7489 §7.1: when a DMARC record sends rua/ruf to an address outside its
 * own organizational domain, the receiver of those reports must publish a
 * "<from-domain>._report._dmarc.<destination-domain>" TXT record starting with
 * "v=DMARC1". Without it, conformant senders should refuse to deliver reports.
 */
async function checkExternalAuthorization(fromDomain: string, externalDomain: string, timeout: number): Promise<boolean> {
  try {
    const txt = await safeResolve(() => dns.resolveTxt(`${fromDomain}._report._dmarc.${externalDomain}`), timeout);
    const joined = txt.map(r => r.join(""));
    return joined.some(r => r.toLowerCase().startsWith("v=dmarc1"));
  } catch {
    return false;
  }
}

const TAG_DESCRIPTIONS: Record<string, string> = {
  v: "Protocol version",
  p: "Policy for the domain",
  sp: "Policy for subdomains",
  rua: "Aggregate report recipients",
  ruf: "Forensic report recipients",
  pct: "Percentage of messages subject to policy",
  fo: "Failure reporting options",
  aspf: "SPF alignment mode",
  adkim: "DKIM alignment mode",
  ri: "Aggregate report interval (seconds)",
  rf: "Forensic report format",
};

const VALID_POLICIES = new Set(["none", "quarantine", "reject"]);
const VALID_ALIGNMENT = new Set(["r", "s"]);
const SEVERITY_ORDER: Record<CheckStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };

/** Worst-wins: only override if the new status is more severe than the existing one. */
function markTag(tags: DmarcTag[], tagName: string, status: CheckStatus, issue: string): void {
  for (const t of tags) {
    if (t.tag !== tagName) continue;
    if (!t.status || SEVERITY_ORDER[status] < SEVERITY_ORDER[t.status]) {
      t.status = status;
      t.issue = issue;
    }
  }
}

export async function checkDmarc(domain: string, timeout: number = 5000): Promise<DmarcResult> {
  let txtRecords: string[][];
  try {
    txtRecords = await safeResolve(() => dns.resolveTxt(`_dmarc.${domain}`), timeout);
  } catch (err: any) {
    if (err.message === "timeout") {
      log.warn({ domain }, "DNS lookup timed out");
      return { status: "fail", record: null, validations: [], tags: [], error: "DNS lookup timed out" };
    }
    return { status: "fail", record: null, validations: [{ check: "DMARC record", status: "fail", detail: "No DMARC record found" }], tags: [] };
  }

  const dmarcRecords = txtRecords.map(r => r.join("")).filter(r => r.toLowerCase().startsWith("v=dmarc1"));

  if (dmarcRecords.length === 0) {
    return { status: "fail", record: null, validations: [{ check: "DMARC record", status: "fail", detail: "No DMARC record published" }], tags: [] };
  }

  const validations: DmarcValidationItem[] = [];
  const DMARC_RFC = "https://www.rfc-editor.org/rfc/rfc7489";

  if (dmarcRecords.length > 1) {
    validations.push({ check: "Single record", status: "fail", detail: `${dmarcRecords.length} DMARC records found — must have exactly one`, ref: DMARC_RFC + "#section-6.6.3" });
    return { status: "fail", record: dmarcRecords[0], validations, tags: [] };
  }

  const record = dmarcRecords[0];
  validations.push({ check: "DMARC record found", status: "pass", detail: "v=DMARC1 record published", ref: DMARC_RFC });

  // Parse tags. We intentionally keep duplicates in `tags[]` so the UI can flag
  // every offending occurrence; `tagMap` keeps last-wins for value lookups.
  const tags: DmarcTag[] = [];
  const tagPairs = record.split(";").map(s => s.trim()).filter(Boolean);
  const tagMap = new Map<string, string>();
  const tagCounts = new Map<string, number>();
  let malformedCount = 0;

  for (const pair of tagPairs) {
    const eqIdx = pair.indexOf("=");
    if (eqIdx === -1) {
      malformedCount++;
      // Surface malformed pair as a fail-tagged entry so it shows up colored.
      tags.push({ tag: pair, value: "", description: "Malformed — missing '='", status: "fail", issue: "Tag must be 'name=value'" });
      continue;
    }
    const tag = pair.slice(0, eqIdx).trim().toLowerCase();
    const value = pair.slice(eqIdx + 1).trim();
    tagMap.set(tag, value);
    tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
    tags.push({ tag, value, description: TAG_DESCRIPTIONS[tag] || "Unknown tag" });
  }

  // ── Duplicate tags ──
  const duplicates = [...tagCounts.entries()].filter(([, n]) => n > 1).map(([t]) => t);
  if (duplicates.length > 0) {
    for (const dup of duplicates) markTag(tags, dup, "warn", "Duplicate tag — must appear at most once");
    validations.push({
      check: "Duplicate tags",
      status: "warn",
      detail: `Tag${duplicates.length > 1 ? "s" : ""} repeated: ${duplicates.join(", ")}`,
      ref: DMARC_RFC + "#section-6.4",
    });
  }
  if (malformedCount > 0) {
    validations.push({ check: "Tag syntax", status: "fail", detail: `${malformedCount} malformed tag pair${malformedCount > 1 ? "s" : ""} (missing '=')`, ref: DMARC_RFC + "#section-6.4" });
  }

  // ── Policy (p) ──
  const policy = tagMap.get("p");
  const rua = tagMap.get("rua");
  if (!policy) {
    validations.push({ check: "Policy (p)", status: "fail", detail: "Required 'p' tag is missing", ref: DMARC_RFC + "#section-6.3" });
  } else if (policy === "none") {
    validations.push({ check: "Policy (p)", status: "warn", detail: "p=none — monitoring only, no enforcement", ref: DMARC_RFC + "#section-6.3" });
    // p=none is only useful when reports are collected.
    if (!rua) {
      validations.push({
        check: "Monitoring policy without reports",
        status: "warn",
        detail: "p=none without rua — neither enforcement nor visibility; record provides no real value",
        ref: DMARC_RFC + "#section-6.3",
      });
      markTag(tags, "p", "warn", "p=none with no rua = no enforcement and no reporting");
    }
  } else if (policy === "quarantine") {
    validations.push({ check: "Policy (p)", status: "pass", detail: "p=quarantine — suspicious messages quarantined", ref: DMARC_RFC + "#section-6.3" });
  } else if (policy === "reject") {
    validations.push({ check: "Policy (p)", status: "pass", detail: "p=reject — unauthorized messages rejected", ref: DMARC_RFC + "#section-6.3" });
  } else {
    validations.push({ check: "Policy (p)", status: "fail", detail: `Invalid policy value: ${policy} (expected none/quarantine/reject)`, ref: DMARC_RFC + "#section-6.3" });
    markTag(tags, "p", "fail", `Invalid value "${policy}" — expected none/quarantine/reject`);
  }

  // ── Subdomain policy (sp) ──
  const sp = tagMap.get("sp");
  if (sp !== undefined) {
    if (!VALID_POLICIES.has(sp)) {
      validations.push({ check: "Subdomain policy (sp)", status: "fail", detail: `Invalid sp value: ${sp} (expected none/quarantine/reject)`, ref: DMARC_RFC + "#section-6.3" });
      markTag(tags, "sp", "fail", `Invalid value "${sp}" — expected none/quarantine/reject`);
    } else if (sp === "none" && policy && policy !== "none") {
      validations.push({ check: "Subdomain policy (sp)", status: "warn", detail: `sp=none weakens domain policy p=${policy} for subdomains`, ref: DMARC_RFC + "#section-6.3" });
    }
  }

  // ── Alignment modes (adkim, aspf) ──
  for (const align of ["adkim", "aspf"] as const) {
    const v = tagMap.get(align);
    if (v !== undefined && !VALID_ALIGNMENT.has(v)) {
      validations.push({ check: `Alignment (${align})`, status: "fail", detail: `Invalid ${align} value: ${v} (expected r or s)`, ref: DMARC_RFC + "#section-6.3" });
      markTag(tags, align, "fail", `Invalid value "${v}" — expected "r" (relaxed) or "s" (strict)`);
    }
  }

  // ── rua ──
  let ruaUris: DmarcReportUri[] | undefined;
  if (rua) {
    ruaUris = rua.split(",").map(s => parseReportUri(s, domain));
    const allValid = ruaUris.every(u => u.email && u.domain);
    if (allValid) {
      validations.push({ check: "Aggregate reports (rua)", status: "pass", detail: `Reports sent to ${ruaUris.length} recipient(s)` });
    } else {
      validations.push({ check: "Aggregate reports (rua)", status: "warn", detail: "Some rua URIs are not valid mailto: addresses" });
      markTag(tags, "rua", "warn", "One or more URIs are not valid mailto: addresses");
    }
  } else {
    validations.push({ check: "Aggregate reports (rua)", status: "warn", detail: "No rua tag — aggregate reports not configured" });
  }

  // ── ruf ──
  const ruf = tagMap.get("ruf");
  let rufUris: DmarcReportUri[] | undefined;
  if (ruf) {
    rufUris = ruf.split(",").map(s => parseReportUri(s, domain));
    const allValid = rufUris.every(u => u.email && u.domain);
    if (!allValid) {
      validations.push({ check: "Forensic reports (ruf)", status: "warn", detail: "Some ruf URIs are not valid mailto: addresses" });
      markTag(tags, "ruf", "warn", "One or more URIs are not valid mailto: addresses");
    }
  }

  // ── External destination authorization (RFC 7489 §7.1) ──
  // For each external rua/ruf address, check that the destination domain
  // published a `<from>._report._dmarc.<dst>` TXT record. Without it,
  // conformant senders must refuse to deliver reports there.
  const allUris = [...(ruaUris ?? []), ...(rufUris ?? [])];
  const externalUris = allUris.filter(u => u.external && u.domain);
  if (externalUris.length > 0) {
    // Cache per destination domain — multiple URIs can share a domain.
    const destDomains = Array.from(new Set(externalUris.map(u => u.domain!)));
    const authResults = await Promise.all(
      destDomains.map(async (dst) => [dst, await checkExternalAuthorization(domain, dst, EXTERNAL_AUTH_TIMEOUT)] as const),
    );
    const authMap = new Map(authResults);
    for (const u of externalUris) {
      u.authorized = authMap.get(u.domain!) ?? false;
    }
    const unauthorized = externalUris.filter(u => u.authorized === false);
    if (unauthorized.length > 0) {
      const dstList = Array.from(new Set(unauthorized.map(u => u.domain!))).join(", ");
      validations.push({
        check: "External destination authorization",
        status: "warn",
        detail: `${unauthorized.length} external recipient(s) on ${dstList} lack the required authorization record. Conformant senders may refuse to deliver reports there.`,
        ref: DMARC_RFC + "#section-7.1",
      });
      // Mark the offending tag(s) so the breakdown highlights them
      const inRua = unauthorized.some(u => ruaUris?.includes(u));
      const inRuf = unauthorized.some(u => rufUris?.includes(u));
      if (inRua) markTag(tags, "rua", "warn", "External recipient(s) lack RFC 7489 §7.1 authorization");
      if (inRuf) markTag(tags, "ruf", "warn", "External recipient(s) lack RFC 7489 §7.1 authorization");
    }
  }

  // ── pct ──
  const pct = tagMap.get("pct");
  if (pct !== undefined) {
    const pctNum = Number(pct);
    if (!Number.isFinite(pctNum) || !/^\d+$/.test(pct)) {
      validations.push({ check: "Percentage (pct)", status: "fail", detail: `Invalid pct value: ${pct} (expected integer 0-100)` });
      markTag(tags, "pct", "fail", `Invalid value "${pct}" — expected integer 0-100`);
    } else if (pctNum < 0 || pctNum > 100) {
      validations.push({ check: "Percentage (pct)", status: "fail", detail: `pct=${pctNum} out of range (must be 0-100)` });
      markTag(tags, "pct", "fail", `Out of range — must be 0-100`);
    } else if (pctNum === 0) {
      validations.push({ check: "Percentage (pct)", status: "warn", detail: "pct=0 — policy is not applied to any message" });
      markTag(tags, "pct", "warn", "pct=0 means the policy applies to no messages");
    } else if (pctNum < 100) {
      validations.push({ check: "Percentage (pct)", status: "warn", detail: `pct=${pctNum} — policy applies to only ${pctNum}% of messages` });
      markTag(tags, "pct", "warn", `Only ${pctNum}% of messages subject to policy`);
    } else {
      validations.push({ check: "Percentage (pct)", status: "pass", detail: "pct=100 — policy applies to all messages" });
    }
  }

  // Sort: fail first, then warn, then pass
  const order: Record<string, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
  validations.sort((a, b) => (order[a.status] ?? 2) - (order[b.status] ?? 2));

  const overall: CheckStatus = validations.some(v => v.status === "fail") ? "fail"
    : validations.some(v => v.status === "warn") ? "warn" : "pass";

  return { status: overall, record, validations, tags, ruaUris, rufUris };
}
