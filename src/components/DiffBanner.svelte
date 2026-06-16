<script lang="ts">
  type Severity = 'critical' | 'warn' | 'resolved' | 'info';

  interface Change {
    category: string;
    type: 'status_changed' | 'value_changed' | 'appeared' | 'disappeared';
    field?: string;
    severity: Severity;
    previous: unknown;
    current: unknown;
    message: string;
  }

  export let diff: {
    previousScanDate: string | null;
    summary: {
      newIssues: number;
      resolvedIssues: number;
      totalChanges: number;
    };
    changes?: Change[];
  };
  // When true, the banner is shown on a historical scan view (not the latest scan).
  // Wording switches from "since last scan" → "since previous scan" to make clear
  // we're comparing this archived scan to the one before it, not to "now".
  export let isHistorical = false;

  let expanded = false;
  let openRows: Record<number, boolean> = {};

  $: dateStr = diff.previousScanDate
    ? new Date(diff.previousScanDate).toLocaleDateString()
    : 'unknown';
  $: comparisonLabel = isHistorical ? 'since previous scan' : 'since last scan';

  $: changes = diff.changes ?? [];
  $: hasChanges = changes.length > 0;

  const severityRank: Record<Severity, number> = {
    critical: 0,
    warn: 1,
    resolved: 2,
    info: 3,
  };

  $: sortedChanges = [...changes].sort(
    (a, b) => severityRank[a.severity] - severityRank[b.severity],
  );

  const categoryLabel: Record<string, string> = {
    ssl: 'SSL',
    headers: 'Security Headers',
    spf: 'SPF',
    dmarc: 'DMARC',
    dkim: 'DKIM',
    dnssec: 'DNSSEC',
    caa: 'CAA',
    mx: 'MX',
    ns: 'Nameservers',
    blacklist: 'Blacklist',
    safeBrowsing: 'Google Safe Browsing',
    urlhaus: 'URLhaus',
    danglingDns: 'Dangling DNS',
    domainExpiry: 'Domain Expiry',
    redirects: 'Redirects',
    securityTxt: 'security.txt',
    score: 'Score',
  };

  function labelFor(c: Change): string {
    return categoryLabel[c.category] ?? c.category;
  }

  // Special-case the score row: a positive delta is informational but
  // styled green; a negative delta is rendered as a warning (orange).
  function visualSeverity(c: Change): Severity | 'improved' {
    if (c.category === 'score') {
      const a = typeof c.previous === 'number' ? c.previous : Number.NaN;
      const b = typeof c.current === 'number' ? c.current : Number.NaN;
      if (Number.isFinite(a) && Number.isFinite(b) && b > a) return 'improved';
    }
    return c.severity;
  }

  function badgeLabel(c: Change): string {
    const v = visualSeverity(c);
    switch (v) {
      case 'critical': return 'New issue';
      case 'warn': return 'Warning';
      case 'resolved': return 'Resolved';
      case 'improved': return 'Improved';
      default: return 'Changed';
    }
  }

  function isPlainObject(v: unknown): v is Record<string, unknown> {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
  }

  function isExpandable(c: Change): boolean {
    if (Array.isArray(c.previous) && Array.isArray(c.current)) return true;
    if (Array.isArray(c.previous) || Array.isArray(c.current)) return true;
    if (isPlainObject(c.previous) && isPlainObject(c.current)) return true;
    const a = c.previous;
    const b = c.current;
    const aStr = typeof a === 'string' ? a : null;
    const bStr = typeof b === 'string' ? b : null;
    if ((aStr !== null || bStr !== null) && (aStr !== bStr)) {
      const len = Math.max(aStr?.length ?? 0, bStr?.length ?? 0);
      if (len > 40) return true;
    }
    return false;
  }

  function arrayToStrings(arr: unknown[]): string[] {
    return arr.map((item) =>
      typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean'
        ? String(item)
        : JSON.stringify(item),
    );
  }

  function arrayDiff(prev: unknown, curr: unknown): { added: string[]; removed: string[] } {
    const a = Array.isArray(prev) ? arrayToStrings(prev) : [];
    const b = Array.isArray(curr) ? arrayToStrings(curr) : [];
    const aSet = new Set(a);
    const bSet = new Set(b);
    return {
      added: b.filter((x) => !aSet.has(x)),
      removed: a.filter((x) => !bSet.has(x)),
    };
  }

  function formatValue(v: unknown): string {
    if (v === null || v === undefined) return '—';
    if (typeof v === 'string') return v || '(empty)';
    return JSON.stringify(v, null, 2);
  }

  function toggle() {
    if (hasChanges) expanded = !expanded;
  }

  function toggleRow(i: number) {
    openRows = { ...openRows, [i]: !openRows[i] };
  }

  function handleHeaderKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggle();
    }
  }
</script>

<div class="diff-banner" class:expanded class:interactive={hasChanges} role="status" aria-label="Changes since last scan">
  <button
    type="button"
    class="diff-summary"
    on:click={toggle}
    on:keydown={handleHeaderKeydown}
    aria-expanded={expanded}
    aria-controls="diff-banner-details"
    disabled={!hasChanges}
  >
    <span class="summary-text">
      <span class="change-count">{diff.summary.totalChanges} change{diff.summary.totalChanges !== 1 ? 's' : ''}</span>
      {comparisonLabel} ({dateStr})
      {#if diff.summary.newIssues > 0 || diff.summary.resolvedIssues > 0}
        —
        {#if diff.summary.newIssues > 0}
          <span class="new-issues">{diff.summary.newIssues} new issue{diff.summary.newIssues !== 1 ? 's' : ''}</span>
        {/if}
        {#if diff.summary.newIssues > 0 && diff.summary.resolvedIssues > 0}, {/if}
        {#if diff.summary.resolvedIssues > 0}
          <span class="resolved-issues">{diff.summary.resolvedIssues} resolved</span>
        {/if}
      {/if}
    </span>
    {#if hasChanges}
      <span class="chevron" class:open={expanded} aria-hidden="true">▾</span>
    {/if}
  </button>

  {#if expanded && hasChanges}
    <ul id="diff-banner-details" class="diff-list">
      {#each sortedChanges as change, i}
        {@const v = visualSeverity(change)}
        {@const expandable = isExpandable(change)}
        <li class="diff-item severity-{v}">
          <div class="row-header">
            <span class="dot" aria-hidden="true">●</span>
            <span class="badge severity-{v}">{badgeLabel(change)}</span>
            <span class="category">{labelFor(change)}</span>
            <span class="message">{change.message}</span>
            {#if expandable}
              <button
                type="button"
                class="row-toggle"
                on:click={() => toggleRow(i)}
                aria-expanded={!!openRows[i]}
                aria-label={openRows[i] ? 'Hide details' : 'Show details'}
              >
                <span class="chevron small" class:open={openRows[i]} aria-hidden="true">▾</span>
              </button>
            {/if}
          </div>

          {#if expandable && openRows[i]}
            <div class="row-details">
              {#if Array.isArray(change.previous) || Array.isArray(change.current)}
                {@const d = arrayDiff(change.previous, change.current)}
                {#if d.added.length === 0 && d.removed.length === 0}
                  <div class="detail-block">
                    <div class="detail-label">Before</div>
                    <pre class="detail-value">{formatValue(change.previous)}</pre>
                    <div class="detail-label">After</div>
                    <pre class="detail-value">{formatValue(change.current)}</pre>
                  </div>
                {:else}
                  {#if d.removed.length > 0}
                    <div class="detail-block">
                      <div class="detail-label removed">Removed ({d.removed.length})</div>
                      <ul class="detail-list">
                        {#each d.removed as item}
                          <li class="detail-line removed"><span class="sign">−</span>{item}</li>
                        {/each}
                      </ul>
                    </div>
                  {/if}
                  {#if d.added.length > 0}
                    <div class="detail-block">
                      <div class="detail-label added">Added ({d.added.length})</div>
                      <ul class="detail-list">
                        {#each d.added as item}
                          <li class="detail-line added"><span class="sign">+</span>{item}</li>
                        {/each}
                      </ul>
                    </div>
                  {/if}
                {/if}
              {:else}
                <div class="detail-block">
                  <div class="detail-label">Before</div>
                  <pre class="detail-value">{formatValue(change.previous)}</pre>
                  <div class="detail-label">After</div>
                  <pre class="detail-value">{formatValue(change.current)}</pre>
                </div>
              {/if}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .diff-banner {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    overflow: hidden;
  }

  .diff-summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    width: 100%;
    padding: 0.5rem 0.75rem;
    background: transparent;
    border: 0;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: default;
  }

  .diff-banner.interactive .diff-summary {
    cursor: pointer;
  }

  .diff-banner.interactive .diff-summary:hover {
    background: rgba(255, 255, 255, 0.03);
  }

  .diff-summary:focus-visible {
    outline: 2px solid var(--color-info);
    outline-offset: -2px;
  }

  .diff-summary[disabled] {
    opacity: 1;
  }

  .summary-text {
    flex: 1;
    min-width: 0;
  }

  .change-count {
    font-weight: 600;
    color: var(--color-info);
  }

  .new-issues {
    color: var(--color-error);
    font-weight: 500;
  }

  .resolved-issues {
    color: var(--color-valid);
    font-weight: 500;
  }

  .chevron {
    display: inline-block;
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    transition: transform 0.15s ease;
  }

  .chevron.small {
    font-size: 0.65rem;
  }

  .chevron.open {
    transform: rotate(180deg);
  }

  .diff-list {
    list-style: none;
    margin: 0;
    padding: 0.25rem 0.75rem 0.6rem;
    border-top: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .diff-item {
    padding: 0.3rem 0;
    font-size: 0.78rem;
    line-height: 1.35;
  }

  .diff-item + .diff-item {
    border-top: 1px dashed var(--color-border);
  }

  .row-header {
    display: grid;
    grid-template-columns: auto auto auto 1fr auto;
    align-items: center;
    gap: 0.5rem;
  }

  .dot {
    font-size: 0.55rem;
    line-height: 1;
  }

  .severity-critical .dot { color: var(--color-error); }
  .severity-warn .dot { color: var(--color-warning); }
  .severity-resolved .dot { color: var(--color-valid); }
  .severity-improved .dot { color: var(--color-valid); }
  .severity-info .dot { color: var(--color-info); }

  .badge {
    font-size: 0.6rem;
    font-weight: 600;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    white-space: nowrap;
  }

  .badge.severity-critical {
    background: rgba(255, 77, 106, 0.1);
    color: var(--color-error);
  }

  .badge.severity-warn {
    background: rgba(255, 184, 77, 0.12);
    color: var(--color-warning);
  }

  .badge.severity-resolved,
  .badge.severity-improved {
    background: rgba(0, 212, 170, 0.1);
    color: var(--color-valid);
  }

  .badge.severity-info {
    background: rgba(77, 166, 255, 0.1);
    color: var(--color-info);
  }

  .category {
    font-weight: 600;
    color: var(--color-text);
    white-space: nowrap;
  }

  .message {
    color: var(--color-text-secondary);
    overflow-wrap: anywhere;
  }

  .row-toggle {
    background: transparent;
    border: 0;
    color: var(--color-text-secondary);
    cursor: pointer;
    padding: 0.15rem 0.3rem;
    border-radius: 3px;
    line-height: 1;
  }

  .row-toggle:hover {
    background: rgba(255, 255, 255, 0.05);
    color: var(--color-text);
  }

  .row-toggle:focus-visible {
    outline: 2px solid var(--color-info);
    outline-offset: 1px;
  }

  .row-details {
    margin-top: 0.4rem;
    padding: 0.5rem 0.6rem;
    background: rgba(0, 0, 0, 0.18);
    border: 1px solid var(--color-border);
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .detail-block {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .detail-label {
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--color-text-secondary);
  }

  .detail-label.added { color: var(--color-valid); }
  .detail-label.removed { color: var(--color-error); }

  .detail-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .detail-line {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    color: var(--color-text);
    overflow-wrap: anywhere;
  }

  .detail-line .sign {
    display: inline-block;
    width: 0.85rem;
    font-weight: 700;
  }

  .detail-line.added .sign { color: var(--color-valid); }
  .detail-line.removed .sign { color: var(--color-error); }

  .detail-value {
    margin: 0;
    padding: 0.35rem 0.5rem;
    background: rgba(255, 255, 255, 0.03);
    border-radius: 3px;
    font-family: var(--font-mono);
    font-size: 0.72rem;
    color: var(--color-text);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  @media (max-width: 600px) {
    .row-header {
      grid-template-columns: auto auto 1fr auto;
    }
    .row-header .category {
      grid-column: 1 / -1;
    }
    .row-header .message {
      grid-column: 1 / -1;
    }
  }
</style>
