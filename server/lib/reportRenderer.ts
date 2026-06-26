/**
 * Renders a self-contained HTML scan report for export (HTML download / PDF).
 *
 * All scan data is inlined; the output has no external assets or scripts and
 * matches the dark-theme look of the in-app report page (see
 * src/components/DomainCheckerPage.svelte for the live equivalent).
 */

import type {
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
  InfrastructureResult,
  SecurityTxtSection,
  CtLogsResult,
  RedirectResult,
  SafeBrowsingResult,
  UrlhausResult,
  DanglingDnsResult,
  CheckStatus,
} from "../../src/lib/types.js";

export interface ReportData {
  domain: string;
  scanDate: string; // ISO timestamp
  score: { total: number; breakdown?: Record<string, { earned: number; max: number }> } | null;
  /** Persisted scan id, when the scan was saved to history. Drives the verify-URL footer. */
  scanId?: string | null;
  /** Origin (scheme + host) used to build the verify URL — derived from the request on the server. */
  verifyBaseUrl?: string | null;
  diff?: {
    previousScanDate: string | null;
    summary: { newIssues: number; resolvedIssues: number; totalChanges: number };
  } | null;
  dns: {
    spf?: SpfResult;
    dmarc?: DmarcResult;
    dkim?: DkimResult;
    dnssec?: DnssecResult;
    caa?: CaaResult;
    mx?: MxResult;
    ns?: NsResult;
    infrastructure?: InfrastructureResult;
    blacklist?: BlacklistResult;
    danglingDns?: DanglingDnsResult;
  } | null;
  web: {
    securityTxt?: SecurityTxtSection;
    headers?: HeadersResult;
    ssl?: SslResult;
  } | null;
  expiry: DomainExpiryResult | null;
  ct: CtLogsResult | null;
  redirects: RedirectResult | null;
  reputation: { safeBrowsing?: SafeBrowsingResult; urlhaus?: UrlhausResult } | null;
}

// ── HTML utilities ──────────────────────────────────────────────────────────

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function esc(s: unknown): string {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPE_MAP[c]);
}

function statusIcon(status: CheckStatus): string {
  if (status === "pass") {
    return `<svg class="status-svg" width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="8" fill="#00d4aa"/><path d="M4.5 8L7 10.5L11.5 5.5" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`;
  }
  if (status === "warn") {
    return `<svg class="status-svg" width="16" height="16" viewBox="0 0 16 16"><path d="M8 1L15.5 14H0.5L8 1Z" fill="#ffb84d"/><path d="M8 6V10" stroke="#1a1a2e" stroke-width="1.8" stroke-linecap="round"/><circle cx="8" cy="12.5" r="1" fill="#1a1a2e"/></svg>`;
  }
  if (status === "fail") {
    return `<svg class="status-svg" width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="8" fill="#ff4d6a"/><path d="M5 5L11 11M11 5L5 11" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/></svg>`;
  }
  return `<svg class="status-svg" width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="8" fill="#4da6ff"/><path d="M8 7V11" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/><circle cx="8" cy="4.5" r="1" fill="#fff"/></svg>`;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return (
    d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" }) +
    " at " +
    d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );
}

function worst(...statuses: CheckStatus[]): CheckStatus {
  const order: Record<CheckStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
  return statuses.filter(Boolean).reduce(
    (a, b) => (order[a] <= order[b] ? a : b),
    "pass" as CheckStatus,
  );
}

// ── Card sections ───────────────────────────────────────────────────────────

function renderHeadersCard(data: HeadersResult): string {
  const presentCount = data.items.filter((i) => i.present).length;
  const subtitle = data.items.length > 0 ? `${presentCount} of ${data.items.length} headers present` : "";

  if (data.items.length === 0) {
    return cardShell("Security Headers", data.status, subtitle, `<p class="muted">Headers could not be analyzed.</p>`);
  }

  const rows = data.items
    .map(
      (h) => `
      <tr>
        <td class="icon-cell">${statusIcon(h.status)}</td>
        <td class="hdr-name">${esc(h.name)}</td>
        <td class="hdr-value"><code>${esc(h.value || "missing")}</code></td>
        <td class="hdr-note">${esc(h.explanation || "")}</td>
      </tr>`,
    )
    .join("");

  const body = `
    <div class="table-wrap">
      <table class="hdr-table">
        <thead>
          <tr><th class="col-status"></th><th>Header</th><th>Value</th><th>Note</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;

  return cardShell("Security Headers", data.status, subtitle, body);
}

function renderSecurityTxtCard(data: SecurityTxtSection): string {
  if (!data.available) {
    const body = `<p class="muted">${esc(data.error || "No security.txt file found on this domain.")}</p>`;
    return cardShell("security.txt", data.status, "Not found", body);
  }

  const statusLabel =
    data.validationStatus === "valid"
      ? "Valid"
      : data.validationStatus === "valid-with-warnings"
        ? "Valid with warnings"
        : "Invalid";

  const findings = data.findings
    .slice(0, 50)
    .map((f) => `<div class="finding-row sev-${esc(f.severity)}"><span class="sev-dot"></span> <span>${esc(f.title)}</span></div>`)
    .join("");

  const body = `
    <div class="status-line stx-${esc(data.validationStatus || "")}">
      <strong>${esc(statusLabel)}</strong>
      ${data.errorCount > 0 ? `<span class="count-bad">${data.errorCount} ${data.errorCount === 1 ? "error" : "errors"}</span>` : ""}
      ${data.warningCount > 0 ? `<span class="count-warn">${data.warningCount} ${data.warningCount === 1 ? "warning" : "warnings"}</span>` : ""}
    </div>
    ${findings ? `<div class="findings">${findings}</div>` : ""}
    ${data.fetchedFrom ? `<p class="muted small">Fetched from <code>${esc(data.fetchedFrom)}</code></p>` : ""}
  `;

  return cardShell("security.txt", data.status, statusLabel, body);
}

function renderSslCard(data: SslResult): string {
  if (data.error) {
    return cardShell("SSL/TLS Certificate", data.status, data.error, `<p class="error-text">${esc(data.error)}</p>`);
  }

  const daysLabel =
    data.daysRemaining != null
      ? data.daysRemaining < 0
        ? "Expired"
        : `${data.daysRemaining} days remaining`
      : "";
  const subtitle = data.managedBy && daysLabel
    ? `${daysLabel} · Managed by ${data.managedBy}`
    : daysLabel;

  const sansHtml =
    data.sans.length > 0
      ? `<div class="sub-section"><span class="kv-label">SANs (${data.sans.length})</span>
          <div class="chip-list">
            ${data.sans
              .slice(0, 30)
              .map((s) => `<span class="chip">${esc(s)}</span>`)
              .join("")}
            ${data.sans.length > 30 ? `<span class="muted small">+${data.sans.length - 30} more</span>` : ""}
          </div>
         </div>`
      : "";

  const chainHtml =
    data.chain && data.chain.length
      ? `<div class="sub-section"><h4 class="sub-title">Certificate Chain</h4>
          <div class="chain-list">
            ${data.chain
              .map(
                (c, i) => `<div class="chain-item">
                  <div class="chain-connector">
                    <span class="chain-dot"></span>
                    ${i < data.chain!.length - 1 ? `<span class="chain-link"></span>` : ""}
                  </div>
                  <div class="chain-info">
                    <div class="chain-header"><strong>${esc(c.subject)}</strong> <span class="badge badge-${esc(c.role)}">${esc(c.role)}</span></div>
                    <div class="muted small">Issued by: ${esc(c.issuer)}</div>
                  </div>
                </div>`,
              )
              .join("")}
          </div>
          ${
            data.chainIssues && data.chainIssues.length
              ? `<div class="issue-list">${data.chainIssues
                  .map((i) => `<div class="issue-row">${statusIcon(i.severity)} <span>${esc(i.message)}</span></div>`)
                  .join("")}</div>`
              : ""
          }
        </div>`
      : "";

  const sctTable =
    data.ct && data.ct.scts && data.ct.scts.length > 0
      ? `<div class="table-wrap">
          <table class="sct-table">
            <thead><tr><th>Log</th><th>Operator</th><th>Timestamp</th></tr></thead>
            <tbody>${data.ct.scts
              .map(
                (s) =>
                  `<tr><td>${esc(s.logName || "Unknown log")}</td><td>${esc(s.operator || "—")}</td><td>${esc(formatDateTime(new Date(s.timestamp).toISOString()))}</td></tr>`,
              )
              .join("")}</tbody>
          </table>
        </div>`
      : "";

  const edges = data.edges;
  const edgesHtml = edges && edges.samples.length > 0
    ? (() => {
        const summaryBadge =
          edges.consistency === "consistent"
            ? `<span class="edge-summary edge-summary-pass">All edges serve the same cert</span>`
            : edges.consistency === "rollout"
              ? `<span class="edge-summary edge-summary-info">${edges.distinctFingerprints} distinct certs — rollout in progress</span>`
              : edges.consistency === "inconsistent"
                ? `<span class="edge-summary edge-summary-fail">Inconsistent cert state</span>`
                : "";
        const tableHtml = `<div class="table-wrap">
            <table class="sct-table">
              <thead><tr><th>IP</th><th>Issuer</th><th>Days</th><th>Fingerprint</th><th>State</th></tr></thead>
              <tbody>${edges.samples
                .map((s) => {
                  const stateLabel = s.error
                    ? `<span class="status-badge status-fail" title="${esc(s.error)}">error</span>`
                    : !s.sanMatch
                      ? `<span class="status-badge status-fail">SAN mismatch</span>`
                      : !s.chainOk
                        ? `<span class="status-badge status-fail">chain broken</span>`
                        : `<span class="status-badge status-pass">ok</span>`;
                  const fpShort = s.fingerprint ? `<code class="small">${esc(s.fingerprint.slice(0, 16))}…</code>` : "—";
                  const issuer = s.error ? "—" : esc(s.issuer || "—");
                  const days = s.error ? "—" : esc(String(s.daysRemaining));
                  return `<tr><td><code class="small">${esc(s.ip)}</code></td><td>${issuer}</td><td>${days}</td><td>${fpShort}</td><td>${stateLabel}</td></tr>`;
                })
                .join("")}</tbody>
            </table>
          </div>`;
        // Collapse table for the boring `consistent` case so the report stays
        // compact; auto-expand when there's something to investigate.
        const openAttr = edges.consistency === "consistent" ? "" : " open";
        return `<div class="sub-section"><h4 class="sub-title">
            Edge Samples (${edges.samples.length})
            ${summaryBadge}
          </h4>
          <details class="edges-details"${openAttr}>
            <summary>Show per-edge details</summary>
            ${tableHtml}
          </details>
        </div>`;
      })()
    : "";

  const ctHtml = data.ct
    ? `<div class="sub-section"><h4 class="sub-title">CT Policy Compliance</h4>
        <div class="ct-badges">
          <span class="ct-badge"><span class="ct-label">Chrome</span> <span class="status-badge status-${data.ct.chromeStatus === "pass" ? "pass" : "fail"}">${esc(data.ct.chromeStatus)}</span></span>
          <span class="ct-badge"><span class="ct-label">Apple</span> <span class="status-badge status-${data.ct.appleStatus === "pass" ? "pass" : "fail"}">${esc(data.ct.appleStatus)}</span></span>
        </div>
        ${sctTable}
        ${
          data.ct.findings && data.ct.findings.length
            ? `<div class="issue-list">${data.ct.findings
                .map((f) => `<div class="issue-row">${statusIcon(f.severity)} <span>${esc(f.message)}</span></div>`)
                .join("")}</div>`
            : ""
        }
      </div>`
    : "";

  // Days-remaining tone: red for expired, info-blue for managed-and-expiring
  // (CDN auto-rotates so it's not the owner's problem), amber otherwise.
  const daysToneClass =
    data.daysRemaining == null
      ? "text-ok"
      : data.daysRemaining < 0
        ? "text-error"
        : data.daysRemaining <= 30
          ? (data.managedBy ? "text-info" : "text-warn")
          : "text-ok";
  const managedRow = data.managedBy
    ? `<div class="kv-row"><span class="kv-label">Managed by</span><span class="text-info">${esc(data.managedBy)} <span class="muted small">— provider auto-rotates this cert</span></span></div>`
    : "";

  const body = `
    <div class="kv-grid">
      <div class="kv-row"><span class="kv-label">Issuer</span><span>${esc(data.issuer || "—")}</span></div>
      <div class="kv-row"><span class="kv-label">Subject</span><span>${esc(data.subject || "—")}</span></div>
      <div class="kv-row"><span class="kv-label">Valid from</span><span>${esc(formatDate(data.validFrom))}</span></div>
      <div class="kv-row"><span class="kv-label">Valid to</span><span>${esc(formatDate(data.validTo))}</span></div>
      <div class="kv-row"><span class="kv-label">Days remaining</span><span class="${daysToneClass}">${data.daysRemaining != null ? (data.daysRemaining < 0 ? "Expired" : esc(String(data.daysRemaining))) : "—"}</span></div>
      ${managedRow}
    </div>
    ${sansHtml}
    ${chainHtml}
    ${edgesHtml}
    ${ctHtml}
  `;

  return cardShell("SSL/TLS Certificate", data.status, subtitle, body);
}

function renderDnsCard(opts: {
  dnssec?: DnssecResult;
  caa?: CaaResult;
  ns?: NsResult;
  expiry?: DomainExpiryResult | null;
  danglingDns?: DanglingDnsResult;
}): string {
  const { dnssec, caa, ns, expiry, danglingDns } = opts;
  const overall = worst(
    dnssec?.status || "info",
    caa?.status || "info",
    ns?.status || "info",
    expiry?.status || "info",
    danglingDns?.status || "info",
  );

  const sections: string[] = [];

  if (dnssec) {
    sections.push(`
      <div class="sub-section">
        <h4 class="sub-title">${statusIcon(dnssec.status)} DNSSEC</h4>
        <p class="muted">${dnssec.enabled ? "Enabled — DNS responses are cryptographically signed" : "Not enabled — DNS responses are not signed."}</p>
        ${dnssec.error ? `<p class="error-text">${esc(dnssec.error)}</p>` : ""}
      </div>`);
  }

  if (caa) {
    sections.push(`
      <div class="sub-section">
        <h4 class="sub-title">${statusIcon(caa.status)} CAA Records</h4>
        ${
          caa.records.length > 0
            ? `<div class="caa-list">${caa.records
                .map(
                  (r) => `<div class="caa-row"><code>${esc(r.tag)}</code> <span>${esc(r.value)}</span></div>`,
                )
                .join("")}</div>`
            : `<p class="muted">No CAA records configured. Any Certificate Authority can issue SSL certificates for this domain.</p>`
        }
        ${caa.error ? `<p class="error-text">${esc(caa.error)}</p>` : ""}
      </div>`);
  }

  if (ns) {
    sections.push(`
      <div class="sub-section">
        <h4 class="sub-title">${statusIcon(ns.status)} Nameservers</h4>
        ${
          ns.nameservers.length > 0
            ? `<div class="chip-list">${ns.nameservers.map((n) => `<span class="chip mono">${esc(n)}</span>`).join("")}</div>`
            : `<p class="error-text">${esc(ns.error || "No NS records found")}</p>`
        }
      </div>`);
  }

  if (expiry) {
    sections.push(`
      <div class="sub-section">
        <h4 class="sub-title">${statusIcon(expiry.status)} Domain Expiration</h4>
        ${
          expiry.expirationDate
            ? `<p class="muted">Expires ${esc(formatDate(expiry.expirationDate))}${expiry.daysRemaining != null ? ` <span class="${expiry.daysRemaining < 0 ? "text-error" : expiry.daysRemaining <= 60 ? "text-warn" : ""}">(${expiry.daysRemaining < 0 ? "expired" : `${expiry.daysRemaining} days remaining`})</span>` : ""}</p>`
            : `<p class="muted">${esc(expiry.error || "Expiration date not available")}</p>`
        }
      </div>`);
  }

  if (danglingDns && danglingDns.records.length > 0) {
    sections.push(`
      <div class="sub-section">
        <h4 class="sub-title">${statusIcon(danglingDns.status)} DNS Record Health</h4>
        ${
          danglingDns.danglingCount === 0
            ? `<p class="muted">All MX and NS hostnames resolve correctly</p>`
            : `<p class="text-warn">${danglingDns.danglingCount} dangling record${danglingDns.danglingCount !== 1 ? "s" : ""} found</p>
               <div class="dangling-list">${danglingDns.records
                 .filter((r) => !r.resolves)
                 .map(
                   (r) =>
                     `<div class="dangling-row"><span class="muted small">${esc(r.type)}</span> <code>${esc(r.hostname)}</code> <span class="text-error small">does not resolve</span></div>`,
                 )
                 .join("")}</div>`
        }
      </div>`);
  }

  return cardShell("DNS & Domain", overall, "", sections.join(""));
}

function renderEmailCard(opts: {
  spf?: SpfResult;
  dmarc?: DmarcResult;
  dkim?: DkimResult;
  mx?: MxResult;
}): string {
  const { spf, dmarc, dkim, mx } = opts;
  const noMail = !!(mx && (mx.hasMail === false || mx.records.length === 0 || mx.nullMx));

  // Two halves: outbound (SPF/DMARC/DKIM anti-spoofing) and inbound (MX delivery).
  // Outbound posture always drives the status; inbound only folds in when the
  // domain actually accepts mail. Mirrors EmailSecurityCard.svelte.
  const outboundStatus = worst(
    spf?.status || "info",
    dmarc?.status || "info",
    dkim?.status || "info",
  );
  const overall = noMail ? outboundStatus : worst(outboundStatus, mx?.status || "info");

  const outboundSummary = [
    spf?.record ? `SPF: ${spf.status}` : "No SPF",
    dmarc?.record ? `DMARC: ${dmarc.status}` : "No DMARC",
    dkim ? `DKIM: ${dkim.foundCount}/${dkim.totalChecked}` : "",
  ]
    .filter(Boolean)
    .join(" · ");

  const subtitle = noMail
    ? `${outboundSummary} · ${mx?.nullMx ? "Rejects inbound mail" : "No inbound mail"}`
    : outboundSummary;

  const spfHtml = spf
    ? `<div class="sub-section">
        <h4 class="sub-title">${statusIcon(spf.status)} SPF</h4>
        ${spf.record ? `<code class="raw-record">${esc(spf.record)}</code>` : ""}
        ${spf.error ? `<p class="error-text">${esc(spf.error)}</p>` : ""}
        ${spf.notice && !noMail ? `<p class="notice">${esc(spf.notice)}</p>` : ""}
        ${
          spf.validations.length > 0
            ? `<div class="check-list">${spf.validations
                .map((v) => renderCheckItem(v.status, v.check, v.detail))
                .join("")}</div>`
            : ""
        }
        ${
          spf.mechanisms.length > 0
            ? `<div class="mech-list muted small">
                <strong>Mechanism breakdown (${spf.dnsLookupCount} DNS lookups)</strong>
                ${spf.mechanisms
                  .map(
                    (m) =>
                      `<div class="mech-row"><code>${esc(m.mechanism)}</code> <span>${esc(m.description)}</span></div>`,
                  )
                  .join("")}
              </div>`
            : ""
        }
      </div>`
    : "";

  const dmarcHtml = dmarc
    ? `<div class="sub-section">
        <h4 class="sub-title">${statusIcon(dmarc.status)} DMARC</h4>
        ${dmarc.record ? `<code class="raw-record">${esc(dmarc.record)}</code>` : ""}
        ${dmarc.error ? `<p class="error-text">${esc(dmarc.error)}</p>` : ""}
        ${dmarc.notice && !noMail ? `<p class="notice">${esc(dmarc.notice)}</p>` : ""}
        ${
          dmarc.validations.length > 0
            ? `<div class="check-list">${dmarc.validations
                .map((v) => renderCheckItem(v.status, v.check, v.detail))
                .join("")}</div>`
            : ""
        }
        ${
          dmarc.tags.length > 0
            ? `<div class="mech-list muted small">
                <strong>Tag breakdown</strong>
                ${dmarc.tags
                  .map(
                    (t) =>
                      `<div class="mech-row tag-${esc(t.status || "ok")}"><code>${esc(t.tag)}${t.value ? "=" + esc(t.value) : ""}</code> <span>${esc(t.description)}</span>${t.issue ? ` <span class="text-warn">— ${esc(t.issue)}</span>` : ""}</div>`,
                  )
                  .join("")}
              </div>`
            : ""
        }
      </div>`
    : "";

  // DKIM is outbound signing — relevant even for send-only domains.
  const dkimHtml = dkim
    ? `<div class="sub-section">
        <h4 class="sub-title">${statusIcon(dkim.status)} DKIM</h4>
        <p class="muted">${dkim.foundCount} of ${dkim.totalChecked} common selectors found</p>
        <div class="selector-list">
          ${dkim.selectors
            .map(
              (s) =>
                `<div class="selector-row"><span class="dot ${s.found ? "ok" : ""}"></span> <code>${esc(s.selector)}</code> <span class="muted small">${esc(s.service)}</span> <span class="muted small">${s.found ? "found" : "—"}</span></div>`,
            )
            .join("")}
        </div>
        <p class="muted small">Partial check — common selectors only. Custom selectors may exist.</p>
      </div>`
    : "";

  const mxHtml = mx
    ? `<div class="sub-section">
        <h4 class="sub-title">${statusIcon(noMail ? "info" : mx.status)} MX Records</h4>
        ${
          mx.nullMx
            ? `<div class="callout"><strong>This domain rejects incoming email.</strong> It publishes a Null MX record (RFC 7505), which explicitly tells senders not to deliver mail here. That doesn't affect outbound mail — SPF, DKIM and DMARC above still protect the domain from spoofing.</div>`
            : mx.records.length > 0
              ? `<div class="table-wrap">
                <table class="mx-table">
                  <thead><tr><th>Priority</th><th>Target</th></tr></thead>
                  <tbody>${mx.records.map((r) => `<tr><td>${esc(String(r.priority))}</td><td>${esc(r.exchange)}</td></tr>`).join("")}</tbody>
                </table>
              </div>`
              : `<div class="callout"><strong>This domain does not accept incoming email.</strong> No MX records were found, so no mail server is configured to receive mail at this domain. This is expected for a send-only domain — SPF, DKIM and DMARC above still protect its outbound mail from spoofing.</div>`
        }
      </div>`
    : "";

  const outboundGroup = `<p class="group-label">Outbound — anti-spoofing</p>${spfHtml}${dmarcHtml}${dkimHtml}`;
  const inboundGroup = mx ? `<p class="group-label">Inbound — mail delivery</p>${mxHtml}` : "";

  return cardShell("Email Security", overall, subtitle, `${outboundGroup}${inboundGroup}`);
}

function renderReputationCard(opts: {
  safeBrowsing?: SafeBrowsingResult;
  urlhaus?: UrlhausResult;
  blacklist?: BlacklistResult;
  infrastructure?: InfrastructureResult;
}): string {
  const { safeBrowsing, urlhaus, blacklist, infrastructure } = opts;
  const overall = worst(
    safeBrowsing?.status || "info",
    urlhaus?.status || "info",
    blacklist?.status || "info",
  );

  const sb = safeBrowsing
    ? `<div class="sub-section">
        <h4 class="sub-title">${statusIcon(safeBrowsing.status)} Google Safe Browsing</h4>
        ${
          safeBrowsing.error
            ? `<p class="muted small">${esc(safeBrowsing.error)}</p>`
            : safeBrowsing.safe === true
              ? `<p class="muted">No threats detected</p>`
              : safeBrowsing.safe === false
                ? `<div class="chip-list">${safeBrowsing.threats.map((t) => `<span class="chip threat">${esc(t.threatType)}</span>`).join("")}</div>`
                : `<p class="muted small">Status unknown</p>`
        }
      </div>`
    : "";

  const uh = urlhaus
    ? `<div class="sub-section">
        <h4 class="sub-title">${statusIcon(urlhaus.status)} URLhaus (abuse.ch)</h4>
        ${
          urlhaus.error
            ? `<p class="muted small">${esc(urlhaus.error)}</p>`
            : urlhaus.listed
              ? `<p class="text-warn">Domain found in malware URL database (${urlhaus.urlCount} URL${urlhaus.urlCount !== 1 ? "s" : ""})</p>`
              : `<p class="muted">Not listed in malware URL database</p>`
        }
      </div>`
    : "";

  let blHtml = "";
  if (blacklist) {
    // Prefer new infrastructure block; fall back to legacy fields on blacklist.
    const legacy = blacklist as any;
    const hasIp = !!(infrastructure?.ip ?? legacy?.ip);
    const cdn = infrastructure?.cdnProvider ?? legacy?.cdnProvider ?? null;
    const domainProviders = blacklist.providers.filter((p) => p.type === "domain");
    const ipProviders = blacklist.providers.filter((p) => p.type === "ip");

    blHtml = `<div class="sub-section">
        <h4 class="sub-title">${statusIcon(blacklist.status)} Blacklists (DNSBL)</h4>
        ${
          blacklist.error
            ? `<p class="muted small">${esc(blacklist.error)}</p>`
            : hasIp
              ? `${
                  domainProviders.length > 0
                    ? `<p class="kv-label">Domain-based</p>
                      <div class="bl-list">${domainProviders
                        .map(
                          (p) =>
                            `<div class="bl-row"><span class="dot ${p.listed ? "bad" : "ok"}"></span> <span>${esc(p.provider)}</span> <span class="muted small">${p.listed ? "Listed" : "Clear"}</span></div>`,
                        )
                        .join("")}</div>`
                    : ""
                }
                ${
                  cdn
                    ? `<p class="kv-label">IP-based</p>
                      <p class="muted small">Not applicable — ${esc(cdn)} edge IPs are shared across many domains, so per-IP DNSBL results don't reflect this domain specifically.</p>`
                    : ipProviders.length > 0
                      ? `<p class="kv-label">IP-based</p>
                        <div class="bl-list">${ipProviders
                          .map(
                            (p) =>
                              `<div class="bl-row"><span class="dot ${p.listed ? "bad" : "ok"}"></span> <span>${esc(p.provider)}</span> <span class="muted small">${p.listed ? "Listed" : "Clear"}</span></div>`,
                          )
                          .join("")}</div>`
                      : ""
                }`
              : `<p class="muted small">Could not determine domain IP</p>`
        }
      </div>`;
  }

  return cardShell("Domain Reputation", overall, "", `${sb}${uh}${blHtml}`);
}

function renderRedirectsCard(data: RedirectResult): string {
  const subtitle = data.httpsRedirect ? "HTTPS redirect active" : "";
  const body = data.error
    ? `<p class="error-text">${esc(data.error)}</p>`
    : `<div class="check-list">${data.items.map((i) => renderCheckItem(i.status, i.check, i.detail)).join("")}</div>`;
  return cardShell("HTTPS & Redirects", data.status, subtitle, body);
}

function renderCtCard(data: CtLogsResult, domain: string): string {
  if (data.source === "none" && data.error) {
    return cardShell("Certificate Transparency", data.status, "", `<p class="error-text">CT log sources temporarily unavailable</p>`);
  }

  const findings = (data.findings || [])
    .map(
      (f) =>
        `<div class="finding-row"><span class="finding-icon">${statusIcon(f.severity === "warn" ? "warn" : f.severity === "fail" ? "fail" : "info")}</span><div><strong>${esc(f.title)}</strong><br><span class="muted small">${esc(f.description)}</span>${f.subdomain ? `<br><code class="muted small">${esc(f.subdomain)}</code>` : ""}</div></div>`,
    )
    .join("");

  const flagged =
    data.flaggedCerts && data.flaggedCerts.length > 0
      ? `<h4 class="sub-title small">Flagged Certificates</h4>
        <div class="table-wrap">
          <table class="ct-table">
            <thead><tr><th>Common Name</th><th>Issuer</th><th>Issued</th><th>Expires</th></tr></thead>
            <tbody>${data.flaggedCerts
              .map(
                (c) =>
                  `<tr><td class="mono">${esc(c.commonName)}</td><td>${esc(c.issuerName)}</td><td>${esc(formatDate(c.notBefore))}</td><td>${esc(formatDate(c.notAfter))}</td></tr>`,
              )
              .join("")}</tbody>
          </table>
        </div>`
      : "";

  const recent =
    data.recentCerts.length > 0
      ? `<h4 class="sub-title small">Recent Certificates</h4>
        <div class="table-wrap">
          <table class="ct-table">
            <thead><tr><th>Common Name</th><th>Issuer</th><th>Issued</th><th>Expires</th></tr></thead>
            <tbody>${data.recentCerts
              .slice(0, 50)
              .map(
                (c) =>
                  `<tr><td class="mono">${esc(c.commonName)}</td><td>${esc(c.issuerName)}</td><td>${esc(formatDate(c.notBefore))}</td><td>${esc(formatDate(c.notAfter))}</td></tr>`,
              )
              .join("")}</tbody>
          </table>
        </div>`
      : "";

  const summary = `<p class="muted">${data.totalCerts} certificate${data.totalCerts !== 1 ? "s" : ""} found in CT logs${data.recentCerts.length < data.totalCerts ? ` (showing ${data.recentCerts.length} unique recent)` : ""}</p>`;

  const source = data.source !== "none"
    ? `<p class="muted small">Data from ${esc(data.source)}${data.fromCache ? " (cached)" : ""}</p>`
    : "";

  void domain;
  return cardShell(
    "Certificate Transparency",
    data.status,
    "",
    `${findings ? `<div class="findings">${findings}</div>` : data.status === "pass" ? `<p class="muted small">No anomalies detected in CT logs</p>` : ""}
     ${summary}${flagged}${recent}${source}`,
  );
}

// ── Building blocks ─────────────────────────────────────────────────────────

function renderCheckItem(status: CheckStatus, title: string, detail: string): string {
  const isIssue = status === "fail" || status === "warn";
  if (isIssue) {
    return `<div class="check-item check-${esc(status)}">
      <div class="check-head">${statusIcon(status)} <strong>${esc(title)}</strong></div>
      ${detail ? `<p class="muted small">${esc(detail)}</p>` : ""}
    </div>`;
  }
  return `<div class="check-compact">${statusIcon(status)} <span>${esc(title)}</span>${detail ? ` <span class="muted small">— ${esc(detail)}</span>` : ""}</div>`;
}

function cardShell(title: string, status: CheckStatus, subtitle: string, body: string): string {
  return `<section class="result-card">
    <header class="card-head">
      ${statusIcon(status)}
      <h3 class="card-title">${esc(title)}</h3>
      ${subtitle ? `<span class="card-subtitle">${esc(subtitle)}</span>` : ""}
    </header>
    <div class="card-body">${body}</div>
  </section>`;
}

// ── Summary bar ─────────────────────────────────────────────────────────────

function isNoMail(data: ReportData): boolean {
  const mx = data.dns?.mx;
  if (!mx) return false;
  return mx.hasMail === false || mx.records.length === 0 || !!mx.nullMx;
}

function worstOfStatuses(...statuses: Array<CheckStatus | undefined | null>): CheckStatus {
  const order: Record<CheckStatus, number> = { fail: 3, warn: 2, pass: 1, info: 0 };
  let worst: CheckStatus = "info";
  for (const s of statuses) {
    if (!s) continue;
    if (order[s] > order[worst]) worst = s;
  }
  return worst;
}

function renderSummaryBar(data: ReportData): string {
  const noMail = isNoMail(data);

  // Mirror DomainCheckerPage.svelte: one entry per visible card, status =
  // worst of internal sub-checks. Counts match what the user sees on the page.
  const checks: { label: string; status: CheckStatus }[] = [];
  if (data.web?.headers?.items?.length) {
    checks.push({ label: "Headers", status: data.web.headers.status });
  }
  if (data.dns?.dnssec || data.dns?.caa || data.dns?.ns || data.dns?.danglingDns || data.expiry) {
    checks.push({
      label: "DNS & Domain",
      status: worstOfStatuses(
        data.dns?.dnssec?.status,
        data.dns?.caa?.status,
        data.dns?.ns?.status,
        data.dns?.danglingDns?.status,
        data.expiry?.status,
      ),
    });
  }
  if (data.reputation?.safeBrowsing || data.reputation?.urlhaus || data.dns?.blacklist) {
    checks.push({
      label: "Reputation",
      status: worstOfStatuses(
        data.reputation?.safeBrowsing?.status,
        data.reputation?.urlhaus?.status,
        data.dns?.blacklist?.status,
      ),
    });
  }
  if (data.dns?.spf || data.dns?.dmarc || data.dns?.dkim || data.dns?.mx) {
    // Outbound anti-spoofing (SPF/DMARC/DKIM) drives the Email status; inbound
    // (MX) only folds in when the domain accepts mail. Mirrors renderEmailCard.
    const outbound = worstOfStatuses(
      data.dns?.spf?.status,
      data.dns?.dmarc?.status,
      data.dns?.dkim?.status,
    );
    checks.push({
      label: "Email",
      status: noMail ? outbound : worstOfStatuses(outbound, data.dns?.mx?.status),
    });
  }
  if (data.web?.securityTxt) checks.push({ label: "security.txt", status: data.web.securityTxt.status });
  if (data.web?.ssl) checks.push({ label: "SSL/TLS", status: data.web.ssl.status });
  if (data.ct) checks.push({ label: "CT logs", status: data.ct.status });
  if (data.redirects) checks.push({ label: "Redirects", status: data.redirects.status });

  if (checks.length === 0) return "";

  // Info entries excluded from counts/progress (match SummaryBar.svelte).
  const passCount = checks.filter((c) => c.status === "pass").length;
  const warnCount = checks.filter((c) => c.status === "warn").length;
  const failCount = checks.filter((c) => c.status === "fail").length;
  const total = passCount + warnCount + failCount;

  if (total === 0) return "";

  const overallStatus: CheckStatus = failCount > 0 ? "fail" : warnCount > 0 ? "warn" : "pass";
  const overallLabel =
    overallStatus === "pass"
      ? "All checks passed"
      : overallStatus === "fail"
        ? `${failCount} issue${failCount !== 1 ? "s" : ""} found`
        : `${warnCount} warning${warnCount !== 1 ? "s" : ""}`;

  const failedLabels = checks.filter((c) => c.status === "fail").map((c) => c.label);
  const warnLabels = checks.filter((c) => c.status === "warn").map((c) => c.label);

  const troubleList =
    failedLabels.length === 0 && warnLabels.length === 0
      ? ""
      : `<div class="trouble-list">
          ${failedLabels.length > 0 ? `<span class="trouble-label count-fail">Failed:</span><span>${esc(failedLabels.join(", "))}</span>` : ""}
          ${warnLabels.length > 0 ? `<span class="trouble-label count-warn">Warnings:</span><span>${esc(warnLabels.join(", "))}</span>` : ""}
        </div>`;

  const score = data.score ? Math.ceil(data.score.total) : null;
  const scoreClass = score === null ? "" : score >= 90 ? "score-good" : score >= 70 ? "score-warn" : "score-bad";

  return `<div class="summary-bar overall-${overallStatus}">
    <div class="summary-main">
      ${score !== null ? `<span class="score-pill ${scoreClass}"><span class="score-value">${esc(String(score))}</span><span class="score-total">/100</span></span>` : ""}
      ${statusIcon(overallStatus)}
      <span class="summary-label">${esc(overallLabel)}</span>
      <span class="summary-counts">
        ${passCount > 0 ? `<span class="count count-pass">${passCount} passed</span>` : ""}
        ${warnCount > 0 ? `<span class="count count-warn">${warnCount} warnings</span>` : ""}
        ${failCount > 0 ? `<span class="count count-fail">${failCount} failed</span>` : ""}
      </span>
    </div>
    <div class="progress-bar">
      ${passCount > 0 ? `<div class="seg pass-seg" style="width: ${(passCount / total) * 100}%"></div>` : ""}
      ${warnCount > 0 ? `<div class="seg warn-seg" style="width: ${(warnCount / total) * 100}%"></div>` : ""}
      ${failCount > 0 ? `<div class="seg fail-seg" style="width: ${(failCount / total) * 100}%"></div>` : ""}
    </div>
    ${troubleList}
  </div>`;
}

function renderInfrastructureBanner(
  infrastructure: InfrastructureResult | undefined,
  blacklist: BlacklistResult | undefined,
  ssl: SslResult | undefined,
): string {
  // Prefer the new infrastructure block; fall back to legacy fields on
  // blacklist (pre-Phase-A historical scans).
  const legacy = blacklist as any;
  const primaryIp = infrastructure?.ip ?? legacy?.ip ?? null;
  if (!primaryIp) return "";
  const ips: string[] = (infrastructure?.ips && infrastructure.ips.length > 0)
    ? infrastructure.ips
    : (legacy?.ips && legacy.ips.length > 0)
      ? legacy.ips
      : [primaryIp];
  const cdn = infrastructure?.cdnProvider ?? legacy?.cdnProvider ?? null;
  const cdnProviders: string[] = (infrastructure?.cdnProviders && infrastructure.cdnProviders.length > 0)
    ? infrastructure.cdnProviders
    : (legacy?.cdnProviders ?? (cdn ? [cdn] : []));
  const multipleCdns = cdnProviders.length > 1;
  const multipleEdges = ips.length > 1;

  const title = multipleCdns
    ? `Behind multiple CDNs (${cdnProviders.map(esc).join(", ")})`
    : cdn
      ? `Behind ${esc(cdn)} CDN`
      : multipleEdges
        ? "Multiple origins"
        : "Direct origin";

  const detail = multipleEdges
    ? `${ips.length} IPs observed across public resolvers`
    : cdn
      ? `Origin IP <code>${esc(ips[0])}</code> belongs to ${esc(cdn)}'s edge network`
      : `IP <code>${esc(ips[0])}</code>`;

  const ipsList = multipleEdges
    ? `<div class="infra-iplist">${ips.map((p) => `<code>${esc(p)}</code>`).join("")}</div>`
    : "";

  // Cert consistency line — placed inline with the title when consistent (one
  // line save), on its own line for rollout/inconsistent (longer text).
  let inlineCertLine = "";
  let blockCertLine = "";
  const edges = ssl?.edges;
  if (edges && edges.samples.length > 0) {
    const valid = edges.samples.filter((s) => !s.error);
    const failedCount = edges.failedIps?.length ?? 0;
    const failedSuffix = failedCount > 0 ? ` · ${failedCount} probe${failedCount !== 1 ? "s" : ""} failed` : "";
    if (edges.consistency === "consistent" && valid.length > 0) {
      inlineCertLine = `<span class="cert-line cert-pass">✓ Cert: same across all ${valid.length} edge${valid.length !== 1 ? "s" : ""}${failedSuffix}</span>`;
    } else if (edges.consistency === "rollout") {
      const min = edges.minDaysRemaining;
      const max = edges.maxDaysRemaining;
      const range = min != null && max != null && min !== max ? ` (earliest expires in ${min}d, latest in ${max}d)` : "";
      blockCertLine = `<span class="cert-line cert-info">Cert rotation in progress: ${edges.distinctFingerprints} versions co-exist${range}${failedSuffix}</span>`;
    } else if (edges.consistency === "inconsistent") {
      const bad = valid.filter((s) => !s.sanMatch || !s.chainOk);
      blockCertLine = `<span class="cert-line cert-fail">⚠ ${bad.length === 1 ? "1 edge serves invalid cert" : `${bad.length} edges serve invalid cert`}${failedSuffix}</span>`;
    }
  }

  return `<div class="infra-banner">
    <div class="infra-header"><strong>${title}</strong>${inlineCertLine}</div>
    <span class="infra-detail">${detail}</span>
    ${ipsList}
    ${blockCertLine}
  </div>`;
}

function renderDiffBanner(diff: NonNullable<ReportData["diff"]>): string {
  const dateStr = diff.previousScanDate ? formatDate(diff.previousScanDate) : "unknown";
  const parts: string[] = [];
  if (diff.summary.newIssues > 0) {
    parts.push(`<span class="diff-new">${diff.summary.newIssues} new issue${diff.summary.newIssues !== 1 ? "s" : ""}</span>`);
  }
  if (diff.summary.resolvedIssues > 0) {
    parts.push(`<span class="diff-resolved">${diff.summary.resolvedIssues} resolved</span>`);
  }

  return `<div class="diff-banner">
    <span class="diff-count">${diff.summary.totalChanges} change${diff.summary.totalChanges !== 1 ? "s" : ""}</span>
    since last scan (${esc(dateStr)})
    ${parts.length > 0 ? "— " + parts.join(", ") : ""}
  </div>`;
}

// ── Top-level template ──────────────────────────────────────────────────────

const STYLES = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #ffffff;
    --surface: #ffffff;
    --surface-2: #f6f7f9;
    --border: #e2e5ec;
    --rule: #d8dce4;
    --text: #1a1a2e;
    --text-2: #5a6072;
    --accent: #00a07f;
    --error: #d93651;
    --warning: #b87100;
    --info: #2b6cb0;
    --valid: #00966e;
  }
  html, body { background: var(--bg); color: var(--text); }
  body {
    font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
  .container { max-width: 720px; margin: 0 auto; }
  .header { text-align: center; margin-bottom: 1.25rem; padding-bottom: 1rem; border-bottom: 1px solid var(--rule); }
  .header h1 { font-size: 1.4rem; font-weight: 700; }
  .header .domain { color: var(--accent); font-family: 'SF Mono', 'Fira Code', Consolas, monospace; }
  .header .scan-date { font-size: 0.8rem; color: var(--text-2); margin-top: 0.3rem; }

  /* Stack of report sections — visually separated by a horizontal rule rather
     than card borders, so a section that overflows a page splits naturally. */
  .stack { display: flex; flex-direction: column; }

  .diff-banner {
    padding: 0.5rem 0;
    font-size: 0.8rem;
    color: var(--text-2);
    margin-bottom: 0.4rem;
  }
  .diff-banner .diff-count { font-weight: 600; color: var(--info); }
  .diff-banner .diff-new { color: var(--error); font-weight: 500; }
  .diff-banner .diff-resolved { color: var(--valid); font-weight: 500; }

  .summary-bar { padding: 0.5rem 0 0.9rem; border-bottom: 1px solid var(--rule); margin-bottom: 0.4rem; }
  .summary-main { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .score-pill {
    display: inline-flex;
    align-items: baseline;
    gap: 1px;
    padding: 0.25rem 0.55rem;
    border-radius: 999px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    font-family: 'SF Mono', monospace;
    font-size: 0.85rem;
    font-weight: 600;
  }
  .score-pill.score-good { background: rgba(0,160,127,0.12); border-color: rgba(0,160,127,0.45); color: var(--valid); }
  .score-pill.score-warn { background: rgba(184,113,0,0.12); border-color: rgba(184,113,0,0.45); color: var(--warning); }
  .score-pill.score-bad { background: rgba(217,54,81,0.12); border-color: rgba(217,54,81,0.45); color: var(--error); }
  .score-total { opacity: 0.6; font-weight: 400; }
  .summary-label { font-size: 0.9rem; font-weight: 600; }
  .overall-pass .summary-label { color: var(--valid); }
  .overall-fail .summary-label { color: var(--error); }
  .overall-warn .summary-label { color: var(--warning); }
  .summary-counts { display: flex; gap: 0.6rem; margin-left: auto; font-size: 0.75rem; }
  .count-pass { color: var(--valid); }
  .count-warn { color: var(--warning); }
  .count-fail { color: var(--error); }
  .progress-bar { display: flex; height: 4px; border-radius: 2px; overflow: hidden; margin-top: 0.6rem; gap: 2px; background: var(--surface-2); }
  .seg { border-radius: 2px; min-width: 3px; }
  .pass-seg { background: var(--valid); }
  .warn-seg { background: var(--warning); }
  .fail-seg { background: var(--error); }
  .trouble-list { display: flex; flex-wrap: wrap; gap: 0.3rem 0.75rem; margin-top: 0.5rem; font-size: 0.72rem; color: var(--text-2); }
  .trouble-label { font-weight: 600; margin-right: 0.25rem; }

  /* Section ("card") — no box, just a header + content with a horizontal
     rule between sections. Lets long sections flow naturally across pages
     without the awkward "whole-card-or-nothing" page-break behaviour. */
  .result-card { padding: 0.6rem 0; border-bottom: 1px solid var(--rule); }
  .result-card:last-child { border-bottom: 0; }
  .card-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.2rem 0 0.5rem;
    /* Keep the heading with at least a few lines of body content. */
    page-break-after: avoid;
    break-after: avoid;
  }
  .card-title { font-size: 1rem; font-weight: 700; letter-spacing: -0.01em; }
  .card-subtitle { font-size: 0.75rem; color: var(--text-2); margin-left: 0.25rem; font-weight: 400; }
  .card-body { display: flex; flex-direction: column; gap: 0.45rem; }

  /* Subsection inside a card. */
  .sub-section { padding: 0.45rem 0; }
  .sub-section + .sub-section { border-top: 1px dashed var(--border); }
  .sub-title { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.35rem; page-break-after: avoid; break-after: avoid; }
  .group-label { font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-2); opacity: 0.7; margin: 0.5rem 0 0.1rem; page-break-after: avoid; break-after: avoid; }
  .group-label:first-child { margin-top: 0; }
  .sub-title.small { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-2); margin-top: 0.5rem; }

  .muted { color: var(--text-2); font-size: 0.8rem; line-height: 1.5; }
  .small { font-size: 0.75rem; }
  .text-error { color: var(--error); }
  .text-warn { color: var(--warning); }
  .text-info { color: var(--info); }
  .text-ok { color: var(--valid); font-weight: 600; }
  .error-text { color: var(--error); font-size: 0.8rem; }
  .status-svg { display: inline-block; vertical-align: middle; flex-shrink: 0; }

  /* Tables */
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  thead { display: table-header-group; }
  tr { page-break-inside: avoid; break-inside: avoid; }
  th { text-align: left; font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-2); padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--rule); }
  td { padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .col-status { width: 24px; }
  .icon-cell { width: 24px; }
  .hdr-name { font-weight: 500; white-space: nowrap; }
  .hdr-value code, code {
    background: var(--surface-2);
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
    font-family: 'SF Mono', monospace;
    font-size: 0.72rem;
    color: var(--text-2);
    word-break: break-all;
  }
  .hdr-note { color: var(--text-2); font-size: 0.75rem; }
  .raw-record {
    display: block;
    background: var(--surface-2);
    border-left: 3px solid var(--accent);
    padding: 0.4rem 0.6rem;
    margin-bottom: 0.5rem;
    color: var(--text);
    font-family: 'SF Mono', monospace;
    font-size: 0.72rem;
    word-break: break-all;
  }
  .ct-table .mono, .mono { font-family: 'SF Mono', monospace; font-size: 0.72rem; color: var(--text); background: transparent; padding: 0; }
  .mx-table td, .ct-table td { color: var(--text-2); }

  /* Checks */
  .check-list { display: flex; flex-direction: column; gap: 0.3rem; }
  .check-compact { display: flex; align-items: center; gap: 0.4rem; padding: 0.15rem 0; font-size: 0.8rem; flex-wrap: wrap; }
  .check-item { border-left: 3px solid var(--rule); padding: 0.35rem 0.6rem; background: var(--surface-2); border-radius: 3px; }
  .check-item.check-warn { border-left-color: var(--warning); background: rgba(184,113,0,0.06); }
  .check-item.check-fail { border-left-color: var(--error); background: rgba(217,54,81,0.06); }
  .check-head { display: flex; align-items: center; gap: 0.4rem; font-size: 0.82rem; }

  /* Findings (security.txt, CT) */
  .findings { display: flex; flex-direction: column; gap: 0.3rem; }
  .finding-row { display: flex; align-items: flex-start; gap: 0.4rem; font-size: 0.8rem; color: var(--text-2); }
  .finding-row .sev-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; margin-top: 0.4rem; }
  .finding-row.sev-error .sev-dot { background: var(--error); }
  .finding-row.sev-warning .sev-dot { background: var(--warning); }
  .finding-row.sev-info .sev-dot { background: var(--info); }
  .finding-icon { display: inline-flex; }

  /* security.txt status line */
  .status-line { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.4rem; font-size: 0.85rem; }
  .status-line.stx-valid strong { color: var(--valid); }
  .status-line.stx-invalid strong { color: var(--error); }
  .status-line.stx-valid-with-warnings strong { color: var(--warning); }
  .count-bad { color: var(--error); font-size: 0.8rem; }
  .count-warn { color: var(--warning); font-size: 0.8rem; }

  /* KV grid (SSL) */
  .kv-grid { display: flex; flex-direction: column; gap: 0.25rem; }
  .kv-row { display: flex; align-items: baseline; gap: 0.75rem; font-size: 0.8rem; }
  .kv-label { color: var(--text-2); font-size: 0.75rem; min-width: 110px; flex-shrink: 0; font-weight: 500; }

  /* Chips */
  .chip-list { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .chip {
    display: inline-block;
    padding: 0.12rem 0.5rem;
    border-radius: 100px;
    font-size: 0.7rem;
    border: 1px solid var(--border);
    color: var(--text-2);
    background: var(--surface-2);
  }
  .chip.mono { font-family: 'SF Mono', monospace; color: var(--text); }
  .chip.threat { background: rgba(217,54,81,0.1); color: var(--error); border-color: rgba(217,54,81,0.25); }

  /* Chain (SSL) — visual rope: dot per cert + thin connector line down to the
     next dot. Mirrors the in-app SslCard layout. */
  .chain-list { display: flex; flex-direction: column; }
  .chain-item { display: flex; gap: 0.6rem; }
  .chain-connector { display: flex; flex-direction: column; align-items: center; width: 12px; flex-shrink: 0; padding-top: 0.3rem; }
  .chain-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text-2); flex-shrink: 0; }
  .chain-link { width: 2px; flex: 1; background: var(--rule); min-height: 16px; margin-top: 2px; }
  .chain-info { padding-bottom: 0.5rem; flex: 1; }
  .chain-header { display: flex; align-items: center; gap: 0.4rem; }

  .badge {
    font-size: 0.6rem;
    font-weight: 600;
    text-transform: uppercase;
    padding: 0.1rem 0.35rem;
    border-radius: 4px;
    letter-spacing: 0.02em;
  }
  .badge-leaf { background: rgba(43,108,176,0.12); color: #2b6cb0; }
  .badge-intermediate { background: rgba(124,58,237,0.12); color: #6d28d9; }
  .badge-root { background: rgba(184,113,0,0.12); color: #92400e; }
  .badge-pass { background: rgba(0,150,110,0.12); color: var(--valid); }
  .badge-fail { background: rgba(217,54,81,0.12); color: var(--error); }

  /* CT Policy compliance — Chrome/Apple chips inline, then SCT log table. */
  .ct-badges { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 0.5rem; }
  .ct-badge { display: inline-flex; align-items: center; gap: 0.4rem; }
  .ct-label { font-size: 0.78rem; color: var(--text-2); }
  .status-badge {
    font-size: 0.6rem;
    font-weight: 600;
    text-transform: uppercase;
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
    letter-spacing: 0.02em;
  }
  .status-pass { background: rgba(0,150,110,0.12); color: var(--valid); }
  .status-fail { background: rgba(217,54,81,0.12); color: var(--error); }

  .sct-table { font-size: 0.74rem; }
  .sct-table th { font-size: 0.66rem; padding: 0.3rem 0.5rem; }
  .sct-table td { padding: 0.32rem 0.5rem; color: var(--text-2); border-bottom: 1px solid var(--border); }
  .sct-table td:first-child { color: var(--text); }

  .issue-list { display: flex; flex-direction: column; gap: 0.3rem; margin-top: 0.4rem; }
  .issue-row { display: flex; align-items: flex-start; gap: 0.4rem; font-size: 0.75rem; color: var(--text-2); }

  /* CAA */
  .caa-list { display: flex; flex-direction: column; gap: 0.2rem; }
  .caa-row { display: flex; align-items: baseline; gap: 0.5rem; font-size: 0.8rem; color: var(--text-2); }

  /* Selectors (DKIM) */
  .selector-list { display: flex; flex-direction: column; gap: 0.18rem; margin-top: 0.4rem; }
  .selector-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.75rem; color: var(--text-2); }
  .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--border); flex-shrink: 0; }
  .dot.ok { background: var(--valid); }
  .dot.bad { background: var(--error); }

  /* Mech list */
  .mech-list { margin-top: 0.4rem; display: flex; flex-direction: column; gap: 0.18rem; padding-left: 0.2rem; }
  .mech-list strong { color: var(--text); display: block; margin-bottom: 0.2rem; font-size: 0.78rem; }
  .mech-row { display: flex; align-items: baseline; gap: 0.5rem; font-size: 0.74rem; flex-wrap: wrap; }
  .tag-warn code { background: rgba(184,113,0,0.1); border-left: 2px solid var(--warning); color: var(--warning); }
  .tag-fail code { background: rgba(217,54,81,0.1); border-left: 2px solid var(--error); color: var(--error); }

  /* Blacklist */
  .bl-list { display: flex; flex-direction: column; gap: 0.18rem; margin-top: 0.2rem; }
  .bl-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.78rem; color: var(--text-2); }

  /* Dangling DNS */
  .dangling-list { display: flex; flex-direction: column; gap: 0.18rem; margin-top: 0.3rem; }
  .dangling-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.75rem; }

  /* Infrastructure banner (CDN / direct origin) */
  .infra-banner {
    background: rgba(43,108,176,0.05);
    border-left: 3px solid var(--info);
    padding: 0.5rem 0.7rem;
    font-size: 0.78rem;
    color: var(--text-2);
    margin-bottom: 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }
  .infra-banner .infra-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 0.75rem;
    flex-wrap: wrap;
  }
  .infra-banner strong { color: var(--text); font-size: 0.82rem; }
  .infra-banner .infra-detail code,
  .infra-iplist code {
    font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
    background: var(--surface-2);
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
    font-size: 0.72rem;
  }
  .infra-iplist {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
    margin-top: 0.25rem;
  }
  .cert-line {
    display: block;
    margin-top: 0.25rem;
    font-size: 0.72rem;
    font-weight: 500;
  }
  .cert-pass { color: var(--valid); }
  .cert-info { color: var(--info); }
  .cert-fail { color: var(--error); }

  /* Edge samples (SSL card) */
  .edge-summary {
    font-size: 0.7rem;
    font-weight: 500;
    margin-left: 0.5rem;
  }
  .edge-summary-pass { color: var(--valid); }
  .edge-summary-info { color: var(--info); }
  .edge-summary-fail { color: var(--error); }
  .edges-details summary {
    cursor: pointer;
    user-select: none;
    font-size: 0.72rem;
    color: var(--text-2);
    padding: 0.2rem 0;
  }
  .edges-details[open] summary { margin-bottom: 0.3rem; }

  /* Callout (no-mail banner) */
  .callout {
    background: rgba(43,108,176,0.06);
    border-left: 3px solid var(--info);
    padding: 0.5rem 0.7rem;
    font-size: 0.78rem;
    color: var(--text-2);
    margin-bottom: 0.5rem;
  }
  .callout.small { font-size: 0.72rem; padding: 0.35rem 0.6rem; }
  .callout strong { color: var(--text); display: block; margin-bottom: 0.15rem; }

  /* Notice (SPF/DMARC) */
  .notice {
    font-size: 0.75rem;
    color: var(--text-2);
    border-left: 2px solid var(--info);
    padding: 0.3rem 0.5rem;
    margin: 0.3rem 0;
  }

  /* Provenance footer */
  .report-footer {
    margin-top: 1.5rem;
    padding-top: 0.7rem;
    border-top: 1px solid var(--rule);
    font-size: 0.7rem;
    color: var(--text-2);
    line-height: 1.6;
  }
  .report-footer .generated-by { font-weight: 600; color: var(--text); }
  .report-footer a { color: var(--info); text-decoration: none; word-break: break-all; }
  .report-footer .footer-line { display: block; }
  .report-footer .scan-id-value { font-family: 'SF Mono', monospace; font-size: 0.68rem; }

  /* Page setup. Margins live in @page so the printed paper background (white)
     simply matches the body background and there's no visible "frame". */
  @page { size: A4; margin: 14mm 12mm; }
`;

function renderFooter(data: ReportData): string {
  const lines: string[] = [];
  lines.push(
    `<span class="footer-line"><span class="generated-by">Generated by Domain Security Checker</span> · ${esc(formatDateTime(new Date().toISOString()))}</span>`,
  );

  if (data.scanId) {
    lines.push(
      `<span class="footer-line">Scan ID: <span class="scan-id-value">${esc(data.scanId)}</span></span>`,
    );
    if (data.verifyBaseUrl) {
      const verifyUrl = `${data.verifyBaseUrl.replace(/\/$/, "")}/verify/${encodeURIComponent(data.scanId)}`;
      lines.push(
        `<span class="footer-line">Verify this report: <a href="${esc(verifyUrl)}">${esc(verifyUrl)}</a></span>`,
      );
    }
  } else {
    lines.push(
      `<span class="footer-line muted">Anonymous scan — not saved to history. To get a verifiable report, sign in before scanning.</span>`,
    );
  }

  return `<footer class="report-footer">${lines.join("")}</footer>`;
}

export function buildReportHtml(data: ReportData): string {
  const cards: string[] = [];

  // Order matches DomainCheckerPage.svelte:
  // Headers, DNS, Reputation, Redirects, security.txt, SSL, CT, Email, SEO
  if (data.web?.headers) cards.push(renderHeadersCard(data.web.headers));

  if (data.dns) {
    cards.push(
      renderDnsCard({
        dnssec: data.dns.dnssec,
        caa: data.dns.caa,
        ns: data.dns.ns,
        expiry: data.expiry,
        danglingDns: data.dns.danglingDns,
      }),
    );
  }

  if (data.reputation || data.dns?.blacklist) {
    cards.push(
      renderReputationCard({
        safeBrowsing: data.reputation?.safeBrowsing,
        urlhaus: data.reputation?.urlhaus,
        blacklist: data.dns?.blacklist,
        infrastructure: data.dns?.infrastructure,
      }),
    );
  }

  if (data.redirects) cards.push(renderRedirectsCard(data.redirects));
  if (data.web?.securityTxt) cards.push(renderSecurityTxtCard(data.web.securityTxt));
  if (data.web?.ssl) cards.push(renderSslCard(data.web.ssl));
  if (data.ct) cards.push(renderCtCard(data.ct, data.domain));

  if (data.dns && (data.dns.spf || data.dns.dmarc || data.dns.dkim || data.dns.mx)) {
    cards.push(
      renderEmailCard({
        spf: data.dns.spf,
        dmarc: data.dns.dmarc,
        dkim: data.dns.dkim,
        mx: data.dns.mx,
      }),
    );
  }


  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scan report — ${esc(data.domain)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${STYLES}</style>
</head>
<body>
<div class="container">
  <header class="header">
    <h1>Scan report for <span class="domain">${esc(data.domain)}</span></h1>
    <p class="scan-date">Scanned on ${esc(formatDateTime(data.scanDate))}</p>
  </header>
  <div class="stack">
    ${data.diff && data.diff.summary.totalChanges > 0 ? renderDiffBanner(data.diff) : ""}
    ${renderSummaryBar(data)}
    ${renderInfrastructureBanner(data.dns?.infrastructure, data.dns?.blacklist, data.web?.ssl)}
    ${cards.join("\n")}
  </div>
  ${renderFooter(data)}
</div>
</body>
</html>`;
}
