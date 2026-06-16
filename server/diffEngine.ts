import type {
  CheckStatus,
  DiffChange,
  DiffResult,
  DomainCheckResponse,
} from "./types.js";
import { calculateScore } from "./scoreCalculator.js";

/**
 * Classify the severity of a status transition.
 *
 * Rules (checked in order):
 * - same status → info
 * - anything → fail → critical (regression to failure)
 * - fail → anything else → resolved (failure cleared)
 * - anything → warn → warn (mild regression)
 * - warn → anything else (other than warn) → resolved (warning cleared)
 * - everything else (pass↔info, etc.) → info
 */
export function classifySeverity(
  prevStatus: CheckStatus,
  currStatus: CheckStatus,
): DiffChange["severity"] {
  if (prevStatus === currStatus) return "info";
  if (currStatus === "fail") return "critical";
  if (prevStatus === "fail") return "resolved";
  if (currStatus === "warn") return "warn";
  if (prevStatus === "warn") return "resolved";
  return "info";
}

function arraysEqual<T>(a: T[], b: T[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (JSON.stringify(a[i]) !== JSON.stringify(b[i])) return false;
  }
  return true;
}

function compareSSL(
  prev: DomainCheckResponse["ssl"],
  curr: DomainCheckResponse["ssl"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "ssl", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `SSL check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.issuer !== curr.issuer) {
    changes.push({ category: "ssl", type: "value_changed", field: "issuer", severity: "info",
      previous: prev.issuer, current: curr.issuer,
      message: `SSL issuer changed from "${prev.issuer}" to "${curr.issuer}"` });
  }
  if (prev.subject !== curr.subject) {
    changes.push({ category: "ssl", type: "value_changed", field: "subject", severity: "info",
      previous: prev.subject, current: curr.subject,
      message: `SSL subject changed from "${prev.subject}" to "${curr.subject}"` });
  }
  if (prev.validFrom !== curr.validFrom) {
    changes.push({ category: "ssl", type: "value_changed", field: "validFrom", severity: "info",
      previous: prev.validFrom, current: curr.validFrom,
      message: `SSL certificate validFrom changed from "${prev.validFrom}" to "${curr.validFrom}"` });
  }
  if (prev.validTo !== curr.validTo) {
    changes.push({ category: "ssl", type: "value_changed", field: "validTo", severity: "info",
      previous: prev.validTo, current: curr.validTo,
      message: `SSL certificate validTo changed from "${prev.validTo}" to "${curr.validTo}"` });
  }
  if (prev.daysRemaining !== curr.daysRemaining) {
    const certReplaced = prev.validTo !== curr.validTo;
    const sslThresholds = [30, 14, 7];
    let crossedThreshold = false;
    for (const t of sslThresholds) {
      const prevAbove = prev.daysRemaining !== null && prev.daysRemaining > t;
      const currBelow = curr.daysRemaining !== null && curr.daysRemaining <= t;
      if (prevAbove && currBelow) { crossedThreshold = true; break; }
    }
    if (certReplaced || crossedThreshold) {
      const severity: DiffChange["severity"] =
        curr.daysRemaining !== null && curr.daysRemaining < 14 ? "critical"
          : crossedThreshold ? "warn" : "info";
      changes.push({ category: "ssl", type: "value_changed", field: "daysRemaining", severity,
        previous: prev.daysRemaining, current: curr.daysRemaining,
        message: `SSL certificate expires in ${curr.daysRemaining} days (was ${prev.daysRemaining} days)` });
    }
  }
  if (!arraysEqual(prev.sans ?? [], curr.sans ?? [])) {
    changes.push({ category: "ssl", type: "value_changed", field: "sans", severity: "info",
      previous: prev.sans, current: curr.sans, message: "SSL SANs list changed" });
  }
  return changes;
}

function compareHeaders(
  prev: DomainCheckResponse["headers"],
  curr: DomainCheckResponse["headers"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "headers", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `Headers check changed from ${prev.status} to ${curr.status}` });
  }
  const prevMap = new Map((prev.items ?? []).map((h) => [h.name, h]));
  const currMap = new Map((curr.items ?? []).map((h) => [h.name, h]));
  for (const [name, currItem] of currMap) {
    const prevItem = prevMap.get(name);
    if (!prevItem) {
      changes.push({ category: "headers", type: "appeared", field: name,
        severity: currItem.status === "pass" ? "resolved" : "info",
        previous: null, current: currItem.present,
        message: `Header "${name}" appeared` });
    } else {
      if (prevItem.present !== currItem.present) {
        changes.push({ category: "headers", type: "status_changed", field: name,
          severity: currItem.present ? "resolved" : "warn",
          previous: prevItem.present, current: currItem.present,
          message: currItem.present ? `Header "${name}" was added` : `Header "${name}" was removed` });
      } else if (prevItem.value !== currItem.value) {
        changes.push({ category: "headers", type: "value_changed", field: name,
          severity: "info", previous: prevItem.value, current: currItem.value,
          message: `Header "${name}" value changed` });
      }
    }
  }
  for (const [name] of prevMap) {
    if (!currMap.has(name)) {
      changes.push({ category: "headers", type: "disappeared", field: name,
        severity: "info", previous: true, current: null,
        message: `Header "${name}" disappeared from check list` });
    }
  }
  return changes;
}

function compareSPF(
  prev: DomainCheckResponse["spf"],
  curr: DomainCheckResponse["spf"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "spf", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `SPF check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.record !== curr.record) {
    changes.push({ category: "spf", type: "value_changed", field: "record",
      severity: "warn", previous: prev.record, current: curr.record,
      message: "SPF record text changed" });
  }
  const prevMechs = (prev.mechanisms ?? []).map((m) => m.mechanism);
  const currMechs = (curr.mechanisms ?? []).map((m) => m.mechanism);
  if (!arraysEqual(prevMechs, currMechs)) {
    changes.push({ category: "spf", type: "value_changed", field: "mechanisms",
      severity: "warn", previous: prevMechs, current: currMechs,
      message: "SPF mechanism list changed" });
  }
  if (prev.dnsLookupCount !== curr.dnsLookupCount) {
    changes.push({ category: "spf", type: "value_changed", field: "dnsLookupCount",
      severity: curr.dnsLookupCount > 10 ? "warn" : "info",
      previous: prev.dnsLookupCount, current: curr.dnsLookupCount,
      message: `SPF DNS lookup count changed from ${prev.dnsLookupCount} to ${curr.dnsLookupCount}` });
  }
  return changes;
}

function compareDMARC(
  prev: DomainCheckResponse["dmarc"],
  curr: DomainCheckResponse["dmarc"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "dmarc", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `DMARC check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.record !== curr.record) {
    changes.push({ category: "dmarc", type: "value_changed", field: "record",
      severity: "warn", previous: prev.record, current: curr.record,
      message: "DMARC record text changed" });
  }
  const prevTags = new Map((prev.tags ?? []).map((t) => [t.tag, t.value]));
  const currTags = new Map((curr.tags ?? []).map((t) => [t.tag, t.value]));
  for (const key of ["p", "rua", "pct"]) {
    const pv = prevTags.get(key) ?? null;
    const cv = currTags.get(key) ?? null;
    if (pv !== cv) {
      changes.push({ category: "dmarc", type: "value_changed", field: key,
        severity: key === "p" ? "warn" : "info", previous: pv, current: cv,
        message: `DMARC tag "${key}" changed from "${pv}" to "${cv}"` });
    }
  }
  return changes;
}

function compareDKIM(
  prev: DomainCheckResponse["dkim"],
  curr: DomainCheckResponse["dkim"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "dkim", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `DKIM check changed from ${prev.status} to ${curr.status}` });
  }
  const prevMap = new Map((prev.selectors ?? []).map((s) => [s.selector, s]));
  const currMap = new Map((curr.selectors ?? []).map((s) => [s.selector, s]));
  for (const [sel, cs] of currMap) {
    const ps = prevMap.get(sel);
    if (!ps) {
      if (cs.found) {
        changes.push({ category: "dkim", type: "appeared", field: sel,
          severity: "info", previous: null, current: true,
          message: `DKIM selector "${sel}" appeared (found)` });
      }
    } else if (ps.found !== cs.found) {
      changes.push({ category: "dkim", type: "status_changed", field: sel,
        severity: cs.found ? "resolved" : "warn",
        previous: ps.found, current: cs.found,
        message: cs.found ? `DKIM selector "${sel}" is now found` : `DKIM selector "${sel}" is no longer found` });
    } else if (ps.record !== cs.record) {
      changes.push({ category: "dkim", type: "value_changed", field: sel,
        severity: "info", previous: ps.record, current: cs.record,
        message: `DKIM selector "${sel}" record changed` });
    }
  }
  for (const [sel, ps] of prevMap) {
    if (!currMap.has(sel) && ps.found) {
      changes.push({ category: "dkim", type: "disappeared", field: sel,
        severity: "warn", previous: true, current: null,
        message: `DKIM selector "${sel}" disappeared` });
    }
  }
  return changes;
}

function compareDNSSEC(
  prev: DomainCheckResponse["dnssec"],
  curr: DomainCheckResponse["dnssec"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "dnssec", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `DNSSEC check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.enabled !== curr.enabled) {
    changes.push({ category: "dnssec", type: "value_changed", field: "enabled",
      severity: curr.enabled ? "resolved" : "critical",
      previous: prev.enabled, current: curr.enabled,
      message: curr.enabled ? "DNSSEC was enabled" : "DNSSEC was disabled" });
  }
  return changes;
}

function compareCAA(
  prev: DomainCheckResponse["caa"],
  curr: DomainCheckResponse["caa"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "caa", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `CAA check changed from ${prev.status} to ${curr.status}` });
  }
  if (!arraysEqual(prev.records ?? [], curr.records ?? [])) {
    changes.push({ category: "caa", type: "value_changed", field: "records",
      severity: "info", previous: prev.records, current: curr.records,
      message: "CAA record list changed" });
  }
  return changes;
}

function compareMX(
  prev: DomainCheckResponse["mx"],
  curr: DomainCheckResponse["mx"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "mx", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `MX check changed from ${prev.status} to ${curr.status}` });
  }
  const prevExchanges = (prev.records ?? []).map((r) => `${r.priority}:${r.exchange}`);
  const currExchanges = (curr.records ?? []).map((r) => `${r.priority}:${r.exchange}`);
  if (!arraysEqual(prevExchanges, currExchanges)) {
    changes.push({ category: "mx", type: "value_changed", field: "records",
      severity: "info", previous: prev.records, current: curr.records,
      message: "MX exchange list or priorities changed" });
  }
  return changes;
}

function compareNS(
  prev: DomainCheckResponse["ns"],
  curr: DomainCheckResponse["ns"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "ns", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `NS check changed from ${prev.status} to ${curr.status}` });
  }
  const prevSorted = [...(prev.nameservers ?? [])].sort();
  const currSorted = [...(curr.nameservers ?? [])].sort();
  if (!arraysEqual(prevSorted, currSorted)) {
    changes.push({ category: "ns", type: "value_changed", field: "nameservers",
      severity: "info", previous: prev.nameservers, current: curr.nameservers,
      message: "Nameserver list changed" });
  }
  return changes;
}

function compareBlacklist(
  prev: DomainCheckResponse["blacklist"],
  curr: DomainCheckResponse["blacklist"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "blacklist", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `Blacklist check changed from ${prev.status} to ${curr.status}` });
  }
  const prevMap = new Map((prev.providers ?? []).map((p) => [p.provider, p.listed]));
  const currMap = new Map((curr.providers ?? []).map((p) => [p.provider, p.listed]));
  for (const [provider, listed] of currMap) {
    const wasListed = prevMap.get(provider);
    if (wasListed === undefined) continue;
    if (!wasListed && listed) {
      changes.push({ category: "blacklist", type: "appeared", field: provider,
        severity: "critical", previous: false, current: true,
        message: `IP listed on ${provider}` });
    } else if (wasListed && !listed) {
      changes.push({ category: "blacklist", type: "disappeared", field: provider,
        severity: "resolved", previous: true, current: false,
        message: `IP delisted from ${provider}` });
    }
  }
  return changes;
}

function compareSafeBrowsing(
  prev: DomainCheckResponse["safeBrowsing"],
  curr: DomainCheckResponse["safeBrowsing"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "safeBrowsing", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `Safe Browsing check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.safe !== curr.safe) {
    const severity: DiffChange["severity"] =
      prev.safe === true && curr.safe === false ? "critical" : "resolved";
    changes.push({ category: "safeBrowsing", type: "status_changed", field: "safe",
      severity, previous: prev.safe, current: curr.safe,
      message: curr.safe
        ? "Domain is now marked as safe by Google Safe Browsing"
        : "Domain flagged as unsafe by Google Safe Browsing" });
  }
  return changes;
}

function compareURLhaus(
  prev: DomainCheckResponse["urlhaus"],
  curr: DomainCheckResponse["urlhaus"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "urlhaus", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `URLhaus check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.listed !== curr.listed) {
    changes.push({ category: "urlhaus", type: curr.listed ? "appeared" : "disappeared",
      field: "listed", severity: curr.listed ? "critical" : "resolved",
      previous: prev.listed, current: curr.listed,
      message: curr.listed ? "Domain listed on URLhaus" : "Domain delisted from URLhaus" });
  }
  return changes;
}

function compareDanglingDns(
  prev: DomainCheckResponse["danglingDns"],
  curr: DomainCheckResponse["danglingDns"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "danglingDns", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `Dangling DNS check changed from ${prev.status} to ${curr.status}` });
  }
  const prevDangling = new Set(
    (prev.records ?? []).filter((r) => !r.resolves).map((r) => `${r.type}:${r.hostname}`),
  );
  const currDangling = new Set(
    (curr.records ?? []).filter((r) => !r.resolves).map((r) => `${r.type}:${r.hostname}`),
  );
  for (const key of currDangling) {
    if (!prevDangling.has(key)) {
      changes.push({ category: "danglingDns", type: "appeared", field: key,
        severity: "critical", previous: null, current: key,
        message: `New dangling DNS record: ${key}` });
    }
  }
  for (const key of prevDangling) {
    if (!currDangling.has(key)) {
      changes.push({ category: "danglingDns", type: "disappeared", field: key,
        severity: "resolved", previous: key, current: null,
        message: `Dangling DNS record resolved: ${key}` });
    }
  }
  return changes;
}

function compareDomainExpiry(
  prev: DomainCheckResponse["domainExpiry"],
  curr: DomainCheckResponse["domainExpiry"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "domainExpiry", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `Domain expiry check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.expirationDate !== curr.expirationDate) {
    changes.push({ category: "domainExpiry", type: "value_changed", field: "expirationDate",
      severity: "info", previous: prev.expirationDate, current: curr.expirationDate,
      message: `Domain expiration date changed from "${prev.expirationDate}" to "${curr.expirationDate}"` });
  }
  if (prev.daysRemaining !== curr.daysRemaining) {
    const expiryRenewed = prev.expirationDate !== curr.expirationDate;
    const thresholds = [60, 30, 14];
    let crossedThreshold = false;
    for (const t of thresholds) {
      const prevAbove = prev.daysRemaining !== null && prev.daysRemaining > t;
      const currBelow = curr.daysRemaining !== null && curr.daysRemaining <= t;
      if (prevAbove && currBelow) { crossedThreshold = true; break; }
    }
    if (expiryRenewed || crossedThreshold) {
      changes.push({ category: "domainExpiry", type: "value_changed", field: "daysRemaining",
        severity: crossedThreshold ? "warn" : "info",
        previous: prev.daysRemaining, current: curr.daysRemaining,
        message: `Domain expires in ${curr.daysRemaining} days (was ${prev.daysRemaining} days)` });
    }
  }
  return changes;
}

function compareRedirects(
  prev: DomainCheckResponse["redirects"],
  curr: DomainCheckResponse["redirects"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "redirects", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `Redirects check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.httpsRedirect !== curr.httpsRedirect) {
    changes.push({ category: "redirects", type: "value_changed", field: "httpsRedirect",
      severity: curr.httpsRedirect ? "resolved" : "warn",
      previous: prev.httpsRedirect, current: curr.httpsRedirect,
      message: curr.httpsRedirect
        ? "HTTPS redirect is now enforced"
        : "HTTPS redirect is no longer enforced" });
  }
  const prevChecks = (prev.items ?? []).map((i) => `${i.check}:${i.status}`);
  const currChecks = (curr.items ?? []).map((i) => `${i.check}:${i.status}`);
  if (!arraysEqual(prevChecks, currChecks)) {
    changes.push({ category: "redirects", type: "value_changed", field: "items",
      severity: "info", previous: prevChecks, current: currChecks,
      message: "Redirect chain checks changed" });
  }
  return changes;
}

function compareSecurityTxt(
  prev: DomainCheckResponse["securityTxt"],
  curr: DomainCheckResponse["securityTxt"],
): DiffChange[] {
  const changes: DiffChange[] = [];
  if (prev.status !== curr.status) {
    changes.push({ category: "securityTxt", type: "status_changed",
      severity: classifySeverity(prev.status, curr.status),
      previous: prev.status, current: curr.status,
      message: `Security.txt check changed from ${prev.status} to ${curr.status}` });
  }
  if (prev.available !== curr.available) {
    changes.push({ category: "securityTxt", type: curr.available ? "appeared" : "disappeared",
      field: "available", severity: curr.available ? "resolved" : "warn",
      previous: prev.available, current: curr.available,
      message: curr.available
        ? "security.txt is now available"
        : "security.txt is no longer available" });
  }
  if (prev.validationStatus !== curr.validationStatus) {
    changes.push({ category: "securityTxt", type: "value_changed", field: "validationStatus",
      severity: "info", previous: prev.validationStatus, current: curr.validationStatus,
      message: `security.txt validation status changed from "${prev.validationStatus}" to "${curr.validationStatus}"` });
  }
  return changes;
}

/**
 * Computes a structured diff between two DomainCheckResponse objects.
 * Returns hasDiff: false when previous is null (first scan).
 */
export function computeDiff(
  current: DomainCheckResponse,
  previous: DomainCheckResponse | null,
): DiffResult {
  if (!previous) {
    return {
      hasDiff: false,
      previousScanId: null,
      previousScanDate: null,
      scoreDelta: 0,
      changes: [],
      summary: { newIssues: 0, resolvedIssues: 0, valueChanges: 0, totalChanges: 0 },
    };
  }

  const allChanges: DiffChange[] = [];
  allChanges.push(...compareSSL(previous.ssl, current.ssl));
  allChanges.push(...compareHeaders(previous.headers, current.headers));
  allChanges.push(...compareSPF(previous.spf, current.spf));
  allChanges.push(...compareDMARC(previous.dmarc, current.dmarc));
  allChanges.push(...compareDKIM(previous.dkim, current.dkim));
  allChanges.push(...compareDNSSEC(previous.dnssec, current.dnssec));
  allChanges.push(...compareCAA(previous.caa, current.caa));
  allChanges.push(...compareMX(previous.mx, current.mx));
  allChanges.push(...compareNS(previous.ns, current.ns));
  allChanges.push(...compareBlacklist(previous.blacklist, current.blacklist));
  allChanges.push(...compareSafeBrowsing(previous.safeBrowsing, current.safeBrowsing));
  allChanges.push(...compareURLhaus(previous.urlhaus, current.urlhaus));
  allChanges.push(...compareDanglingDns(previous.danglingDns, current.danglingDns));
  allChanges.push(...compareDomainExpiry(previous.domainExpiry, current.domainExpiry));
  allChanges.push(...compareRedirects(previous.redirects, current.redirects));
  allChanges.push(...compareSecurityTxt(previous.securityTxt, current.securityTxt));

  // Compare score
  const prevScore = calculateScore(previous);
  const currScore = calculateScore(current);
  const scoreDelta = currScore.total - prevScore.total;

  if (scoreDelta !== 0) {
    const severity: DiffChange["severity"] = scoreDelta < 0 ? "warn" : "info";
    allChanges.push({ category: "score", type: "value_changed", field: "score",
      severity, previous: prevScore.total, current: currScore.total,
      message: `Security score changed from ${prevScore.total} to ${currScore.total} (${scoreDelta > 0 ? "+" : ""}${scoreDelta} points)` });
  }

  const newIssues = allChanges.filter((c) => c.severity === "critical" || c.severity === "warn").length;
  const resolvedIssues = allChanges.filter((c) => c.severity === "resolved").length;
  const valueChanges = allChanges.filter((c) => c.type === "value_changed").length;

  return {
    hasDiff: allChanges.length > 0,
    previousScanId: null, // Caller sets this from the scan row
    previousScanDate: previous.timestamp ?? null,
    scoreDelta,
    changes: allChanges,
    summary: { newIssues, resolvedIssues, valueChanges, totalChanges: allChanges.length },
  };
}
