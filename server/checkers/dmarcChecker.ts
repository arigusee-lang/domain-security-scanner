import dns from "node:dns/promises";
import type { CheckStatus, DmarcResult, DmarcTag, DmarcValidationItem } from "../types.js";

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

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); }
    );
  });
}

export async function checkDmarc(domain: string, timeout: number = 5000): Promise<DmarcResult> {
  let txtRecords: string[][];
  try {
    txtRecords = await withTimeout(dns.resolveTxt(`_dmarc.${domain}`), timeout);
  } catch (err: any) {
    if (err.message === "timeout") {
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

  // Parse tags
  const tags: DmarcTag[] = [];
  const tagPairs = record.split(";").map(s => s.trim()).filter(Boolean);
  const tagMap = new Map<string, string>();

  for (const pair of tagPairs) {
    const eqIdx = pair.indexOf("=");
    if (eqIdx === -1) continue;
    const tag = pair.slice(0, eqIdx).trim().toLowerCase();
    const value = pair.slice(eqIdx + 1).trim();
    tagMap.set(tag, value);
    tags.push({ tag, value, description: TAG_DESCRIPTIONS[tag] || "Unknown tag" });
  }

  // Validate p tag
  const policy = tagMap.get("p");
  if (!policy) {
    validations.push({ check: "Policy (p)", status: "fail", detail: "Required 'p' tag is missing", ref: DMARC_RFC + "#section-6.3" });
  } else if (policy === "none") {
    validations.push({ check: "Policy (p)", status: "warn", detail: "p=none — monitoring only, no enforcement", ref: DMARC_RFC + "#section-6.3" });
  } else if (policy === "quarantine") {
    validations.push({ check: "Policy (p)", status: "pass", detail: "p=quarantine — suspicious messages quarantined", ref: DMARC_RFC + "#section-6.3" });
  } else if (policy === "reject") {
    validations.push({ check: "Policy (p)", status: "pass", detail: "p=reject — unauthorized messages rejected", ref: DMARC_RFC + "#section-6.3" });
  } else {
    validations.push({ check: "Policy (p)", status: "warn", detail: `Unknown policy value: ${policy}`, ref: DMARC_RFC + "#section-6.3" });
  }

  // Validate rua
  const rua = tagMap.get("rua");
  if (rua) {
    const uris = rua.split(",").map(s => s.trim());
    const allValid = uris.every(u => u.startsWith("mailto:") && u.includes("@"));
    validations.push(allValid
      ? { check: "Aggregate reports (rua)", status: "pass", detail: `Reports sent to ${uris.length} recipient(s)` }
      : { check: "Aggregate reports (rua)", status: "warn", detail: "Some rua URIs may be malformed" }
    );
  } else {
    validations.push({ check: "Aggregate reports (rua)", status: "warn", detail: "No rua tag — aggregate reports not configured" });
  }

  // Validate pct
  const pct = tagMap.get("pct");
  if (pct) {
    const pctNum = parseInt(pct, 10);
    if (!isNaN(pctNum) && pctNum < 100) {
      validations.push({ check: "Percentage (pct)", status: "warn", detail: `pct=${pctNum} — policy applies to only ${pctNum}% of messages` });
    } else if (!isNaN(pctNum)) {
      validations.push({ check: "Percentage (pct)", status: "pass", detail: "pct=100 — policy applies to all messages" });
    }
  }

  // Sort: fail first, then warn, then pass
  const order: Record<string, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
  validations.sort((a, b) => (order[a.status] ?? 2) - (order[b.status] ?? 2));

  const overall: CheckStatus = validations.some(v => v.status === "fail") ? "fail"
    : validations.some(v => v.status === "warn") ? "warn" : "pass";

  return { status: overall, record, validations, tags };
}
