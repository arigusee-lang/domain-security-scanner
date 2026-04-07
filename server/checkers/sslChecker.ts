import type { TlsCertInfo, SslResult, CheckStatus } from "../types.js";
import type { ChainCertInfo, ChainIssue, SctInfo, CtPolicyResult } from "./sslChecker.types.js";
import { findLogByLogId } from "./knownCtLogs.js";

/**
 * Validate a certificate chain for completeness and correctness.
 *
 * Logic:
 * 1. Assign roles: first = leaf, last self-signed = root, rest = intermediate
 * 2. Check completeness: issuer of each cert matches subject of next
 * 3. Detect: empty chain (only leaf) → fail, self-signed leaf → fail,
 *    root in chain → warn, missing intermediates → fail, complete → pass
 */
export function validateChain(chain: ChainCertInfo[]): { status: CheckStatus; issues: ChainIssue[]; chain: ChainCertInfo[] } {
  const issues: ChainIssue[] = [];

  if (chain.length === 0) {
    return { status: "fail", issues: [{ severity: "fail", message: "No certificates in chain" }], chain: [] };
  }

  // Assign roles: mutate a working copy
  const certs = chain.map((c) => ({ ...c }));
  certs[0].role = "leaf";

  // Check self-signed leaf first
  if (certs[0].isSelfSigned) {
    issues.push({ severity: "fail", message: "Leaf certificate is self-signed" });
    return { status: "fail", issues, chain: certs };
  }

  // Find last self-signed cert and mark as root
  let rootIndex = -1;
  for (let i = certs.length - 1; i >= 1; i--) {
    if (certs[i].isSelfSigned) {
      rootIndex = i;
      certs[i].role = "root";
      break;
    }
  }

  // Mark intermediates
  for (let i = 1; i < certs.length; i++) {
    if (i !== rootIndex) {
      certs[i].role = "intermediate";
    }
  }

  // Only leaf, no intermediates → fail
  if (certs.length === 1) {
    issues.push({ severity: "fail", message: "Chain contains only the leaf certificate; intermediate certificates are missing" });
    return { status: "fail", issues, chain: certs };
  }

  // Root in chain → warn (redundant, increases TLS handshake size)
  // Chain gap check removed - O vs CN comparison is unreliable

  // If root is present → warn, otherwise pass
  const status: CheckStatus = "pass";
  return { status, issues, chain: certs };
}

export function analyzeSsl(tlsCert: TlsCertInfo | null): SslResult {
  if (!tlsCert) {
    return { status: "fail", issuer: null, subject: null, validFrom: null, validTo: null, daysRemaining: null, sans: [], error: "Could not retrieve TLS certificate" };
  }

  const { issuer, subject, validFrom, validTo, daysRemaining, sans } = tlsCert;

  let status: "pass" | "warn" | "fail";
  if (daysRemaining < 0) {
    status = "fail";
  } else if (daysRemaining <= 30) {
    status = "warn";
  } else {
    status = "pass";
  }

  return { status, issuer, subject, validFrom, validTo, daysRemaining, sans };
}

// OID 1.3.6.1.4.1.11129.2.4.2 as byte sequence
const SCT_OID_BYTES = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]);

/**
 * Parse SCTs from a raw DER-encoded X.509 certificate.
 * Searches for OID 1.3.6.1.4.1.11129.2.4.2, then parses the SCT list per RFC 6962 §3.3.
 */
export function parseSCTs(rawCert: Buffer): SctInfo[] {
  try {
    const oidIndex = rawCert.indexOf(SCT_OID_BYTES);
    if (oidIndex === -1) return [];

    // After OID, we expect an OCTET STRING wrapper.
    // Skip OID bytes, then parse ASN.1 tag+length for the outer OCTET STRING
    let pos = oidIndex + SCT_OID_BYTES.length;

    // Skip the outer OCTET STRING tag (0x04) + length
    pos = skipAsn1TagLength(rawCert, pos);
    if (pos < 0) return [];

    // There may be a second nested OCTET STRING wrapper
    if (rawCert[pos] === 0x04) {
      pos = skipAsn1TagLength(rawCert, pos);
      if (pos < 0) return [];
    }

    // Now we should be at the SCT list: 2-byte total length, then entries
    if (pos + 2 > rawCert.length) return [];
    const sctListLen = rawCert.readUInt16BE(pos);
    pos += 2;

    const sctListEnd = pos + sctListLen;
    if (sctListEnd > rawCert.length) return [];

    const scts: SctInfo[] = [];

    while (pos + 2 < sctListEnd) {
      const entryLen = rawCert.readUInt16BE(pos);
      pos += 2;
      if (pos + entryLen > sctListEnd) break;

      const entryEnd = pos + entryLen;

      // version: 1 byte
      if (pos + 1 > entryEnd) break;
      const version = rawCert[pos];
      pos += 1;

      // log_id: 32 bytes
      if (pos + 32 > entryEnd) break;
      const logId = rawCert.subarray(pos, pos + 32).toString("hex");
      pos += 32;

      // timestamp: 8 bytes big-endian (ms since epoch)
      if (pos + 8 > entryEnd) break;
      const timestamp = Number(rawCert.readBigUInt64BE(pos));
      pos += 8;

      // Look up log name and operator
      const knownLog = findLogByLogId(logId);

      scts.push({
        version,
        logId,
        timestamp,
        logName: knownLog?.name ?? null,
        operator: knownLog?.operator ?? null,
      });

      // Skip to end of this entry (extensions + signature)
      pos = entryEnd;
    }

    return scts;
  } catch {
    return [];
  }
}

/** Skip an ASN.1 tag + length, returning the position after the length bytes (start of value). Returns -1 on error. */
function skipAsn1TagLength(buf: Buffer, pos: number): number {
  if (pos >= buf.length) return -1;
  pos += 1; // skip tag byte
  if (pos >= buf.length) return -1;
  const lenByte = buf[pos];
  pos += 1;
  if (lenByte & 0x80) {
    const numLenBytes = lenByte & 0x7f;
    pos += numLenBytes;
  }
  return pos <= buf.length ? pos : -1;
}

/**
 * Check CT policy compliance (Chrome and Apple) for a certificate.
 */
export function checkCtPolicy(rawCert: Buffer, certLifetimeDays: number): CtPolicyResult {
  const scts = parseSCTs(rawCert);
  const findings: CtPolicyResult["findings"] = [];

  // --- Chrome policy: at least 2 SCTs from different operators ---
  const knownOperators = new Set<string>();
  for (const sct of scts) {
    if (sct.operator) knownOperators.add(sct.operator);
  }
  const chromeStatus: CheckStatus = knownOperators.size >= 2 ? "pass" : "fail";
  if (chromeStatus === "fail") {
    findings.push({
      severity: "fail",
      message: `Chrome CT policy requires SCTs from at least 2 different operators; found ${knownOperators.size}. This may cause NET::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED.`,
    });
  }

  // --- Apple policy: depends on certificate lifetime ---
  let requiredScts: number;
  if (certLifetimeDays < 180) {
    requiredScts = 2;
  } else if (certLifetimeDays <= 456) {
    requiredScts = 3;
  } else {
    requiredScts = 3;
  }

  let appleStatus: CheckStatus;
  if (certLifetimeDays > 456) {
    // >456 days: need 3 SCTs from different logs
    const uniqueLogIds = new Set(scts.map((s) => s.logId));
    appleStatus = uniqueLogIds.size >= 3 ? "pass" : "fail";
    if (appleStatus === "fail") {
      findings.push({
        severity: "fail",
        message: `Apple CT policy requires ${requiredScts} SCTs from different logs for certificates with lifetime > 456 days; found ${uniqueLogIds.size} unique log(s).`,
      });
    }
  } else {
    appleStatus = scts.length >= requiredScts ? "pass" : "fail";
    if (appleStatus === "fail") {
      findings.push({
        severity: "fail",
        message: `Apple CT policy requires ${requiredScts} SCTs for certificates with lifetime ${certLifetimeDays} days; found ${scts.length}.`,
      });
    }
  }

  return { scts, chromeStatus, appleStatus, findings };
}

/** Status priority for aggregation: fail > warn > pass > info */
const STATUS_PRIORITY: Record<CheckStatus, number> = { fail: 3, warn: 2, pass: 1, info: 0 };

/** Return the worst (highest priority) status from a list */
export function worstStatus(...statuses: CheckStatus[]): CheckStatus {
  let worst: CheckStatus = "info";
  for (const s of statuses) {
    if (STATUS_PRIORITY[s] > STATUS_PRIORITY[worst]) worst = s;
  }
  return worst;
}

/**
 * Extended SSL analysis with chain validation and CT policy checks.
 * Without chain/rawCert args, behaves identically to analyzeSsl (backward compatible).
 */
export function analyzeSslDeep(
  tlsCert: TlsCertInfo | null,
  chainCerts?: ChainCertInfo[],
  rawLeafCert?: Buffer,
): SslResult {
  const base = analyzeSsl(tlsCert);

  // If no extra data, return base result (backward compatible)
  if (!chainCerts?.length && !rawLeafCert) return base;

  const statusParts: CheckStatus[] = [base.status];

  // Chain validation
  if (chainCerts && chainCerts.length > 0) {
    const chainResult = validateChain(chainCerts);
    base.chain = chainResult.chain || chainCerts;
    base.chainStatus = chainResult.status;
    base.chainIssues = chainResult.issues;
    statusParts.push(chainResult.status);
  }

  // CT policy check
  if (rawLeafCert && tlsCert) {
    const validFrom = new Date(tlsCert.validFrom);
    const validTo = new Date(tlsCert.validTo);
    const certLifetimeDays = Math.floor((validTo.getTime() - validFrom.getTime()) / 86400000);
    const ctResult = checkCtPolicy(rawLeafCert, certLifetimeDays);
    base.ct = ctResult;
    statusParts.push(ctResult.chromeStatus, ctResult.appleStatus);
  }

  // Aggregate worst status
  base.status = worstStatus(...statusParts);

  return base;
}
