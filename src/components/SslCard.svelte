<script lang="ts">
  import type { SslResult, CheckStatus } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let data: SslResult;

  function formatDate(iso: string | null): string {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function formatTimestamp(ts: number): string {
    return new Date(ts).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function roleBadgeClass(role: string): string {
    if (role === 'leaf') return 'badge-leaf';
    if (role === 'root') return 'badge-root';
    return 'badge-intermediate';
  }

  function statusBadgeClass(status: CheckStatus): string {
    return status === 'pass' ? 'badge-pass' : 'badge-fail';
  }

  $: daysClass = data.daysRemaining == null ? ''
    : data.daysRemaining < 0 ? 'expired'
    : data.daysRemaining <= 30 ? 'expiring'
    : 'ok';

  $: subtitle = data.daysRemaining != null
    ? (data.daysRemaining < 0 ? 'Expired' : `${data.daysRemaining} days remaining`)
    : data.error || '';
</script>

<ResultCard title="SSL/TLS Certificate" status={data.status} {subtitle}>
  {#if data.error}
    <p class="error-text">{data.error}</p>
  {:else}
    <div class="ssl-grid">
      <div class="ssl-row"><span class="ssl-label">Issuer</span><span class="ssl-value">{data.issuer || '—'}</span></div>
      <div class="ssl-row"><span class="ssl-label">Subject</span><span class="ssl-value">{data.subject || '—'}</span></div>
      <div class="ssl-row"><span class="ssl-label">Valid from</span><span class="ssl-value">{formatDate(data.validFrom)}</span></div>
      <div class="ssl-row"><span class="ssl-label">Valid to</span><span class="ssl-value">{formatDate(data.validTo)}</span></div>
      <div class="ssl-row">
        <span class="ssl-label">Days remaining</span>
        <span class="ssl-value days {daysClass}">
          {data.daysRemaining != null ? (data.daysRemaining < 0 ? 'Expired' : data.daysRemaining) : '—'}
        </span>
      </div>
    </div>
    {#if data.sans.length > 0}
      <div class="sans-section">
        <span class="ssl-label">SANs ({data.sans.length})</span>
        <div class="sans-list">
          {#each data.sans.slice(0, 10) as san}
            <span class="san-chip">{san}</span>
          {/each}
          {#if data.sans.length > 10}
            <span class="san-more">+{data.sans.length - 10} more</span>
          {/if}
        </div>
      </div>
    {/if}

    {#if data.chain}
      <div class="deep-section">
        <h4 class="section-title">Certificate Chain</h4>
        <div class="chain-list">
          {#each data.chain as cert, i}
            <div class="chain-item">
              <div class="chain-connector">
                <span class="chain-dot"></span>
                {#if i < data.chain.length - 1}
                  <span class="chain-line"></span>
                {/if}
              </div>
              <div class="chain-info">
                <div class="chain-header">
                  <span class="chain-subject">{cert.subject}</span>
                  <span class="role-badge {roleBadgeClass(cert.role)}">{cert.role}</span>
                </div>
                <span class="chain-issuer">Issued by: {cert.issuer}</span>
              </div>
            </div>
          {/each}
        </div>
        {#if data.chainIssues && data.chainIssues.length > 0}
          <div class="issues-list">
            {#each data.chainIssues as issue}
              <div class="issue-item">
                <CheckStatusIcon status={issue.severity} />
                <span class="issue-text">{issue.message}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    {#if data.ct}
      <div class="deep-section">
        <h4 class="section-title">CT Policy Compliance</h4>
        <div class="ct-badges">
          <div class="ct-badge-row">
            <span class="ct-label">Chrome</span>
            <span class="status-badge {statusBadgeClass(data.ct.chromeStatus)}">{data.ct.chromeStatus}</span>
          </div>
          <div class="ct-badge-row">
            <span class="ct-label">Apple</span>
            <span class="status-badge {statusBadgeClass(data.ct.appleStatus)}">{data.ct.appleStatus}</span>
          </div>
        </div>
        {#if data.ct.scts.length > 0}
          <table class="sct-table">
            <thead>
              <tr>
                <th>Log</th>
                <th>Operator</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {#each data.ct.scts as sct}
                <tr>
                  <td>{sct.logName || 'Unknown log'}</td>
                  <td>{sct.operator || '—'}</td>
                  <td>{formatTimestamp(sct.timestamp)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
        {#if data.ct.findings.length > 0}
          <div class="issues-list">
            {#each data.ct.findings as finding}
              <div class="issue-item">
                <CheckStatusIcon status={finding.severity} />
                <span class="issue-text">{finding.message}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
  {/if}
</ResultCard>

<style>
  .error-text {
    color: var(--color-error);
    font-size: 0.85rem;
  }

  .ssl-grid {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }

  .ssl-row {
    display: flex;
    align-items: baseline;
    gap: 0.75rem;
    font-size: 0.8rem;
  }

  .ssl-label {
    color: var(--color-text-secondary);
    font-size: 0.75rem;
    min-width: 100px;
    flex-shrink: 0;
  }

  .ssl-value {
    color: var(--color-text);
  }

  .days.ok { color: var(--color-valid); font-weight: 600; }
  .days.expiring { color: var(--color-warning); font-weight: 600; }
  .days.expired { color: var(--color-error); font-weight: 600; }

  .sans-section {
    margin-top: 0.6rem;
  }

  .sans-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
    margin-top: 0.3rem;
  }

  .san-chip {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 100px;
    font-size: 0.7rem;
    font-family: var(--font-mono);
    border: 1px solid var(--color-border);
    color: var(--color-text-secondary);
    background: var(--color-surface);
  }

  .san-more {
    font-size: 0.7rem;
    color: var(--color-text-secondary);
    opacity: 0.6;
    align-self: center;
  }

  /* Deep check sections */
  .deep-section {
    margin-top: 1rem;
    padding-top: 0.8rem;
    border-top: 1px solid var(--color-border);
  }

  .section-title {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--color-text);
    margin: 0 0 0.6rem 0;
  }

  /* Chain visualization */
  .chain-list {
    display: flex;
    flex-direction: column;
  }

  .chain-item {
    display: flex;
    gap: 0.6rem;
  }

  .chain-connector {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 12px;
    flex-shrink: 0;
  }

  .chain-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-text-secondary);
    flex-shrink: 0;
  }

  .chain-line {
    width: 2px;
    flex: 1;
    background: var(--color-border);
    min-height: 16px;
  }

  .chain-info {
    padding-bottom: 0.5rem;
  }

  .chain-header {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .chain-subject {
    font-size: 0.8rem;
    font-weight: 500;
    color: var(--color-text);
  }

  .chain-issuer {
    font-size: 0.7rem;
    color: var(--color-text-secondary);
  }

  .role-badge {
    font-size: 0.6rem;
    font-weight: 600;
    text-transform: uppercase;
    padding: 0.1rem 0.35rem;
    border-radius: 4px;
  }

  .badge-leaf { background: rgba(99, 179, 237, 0.15); color: #63b3ed; }
  .badge-intermediate { background: rgba(183, 148, 244, 0.15); color: #b794f4; }
  .badge-root { background: rgba(246, 173, 85, 0.15); color: #f6ad55; }

  /* Issues list */
  .issues-list {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin-top: 0.5rem;
  }

  .issue-item {
    display: flex;
    align-items: flex-start;
    gap: 0.4rem;
    font-size: 0.75rem;
    color: var(--color-text-secondary);
  }

  .issue-text {
    line-height: 1.4;
  }

  /* CT Policy */
  .ct-badges {
    display: flex;
    gap: 1rem;
    margin-bottom: 0.6rem;
  }

  .ct-badge-row {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .ct-label {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
  }

  .status-badge {
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
  }

  .badge-pass { background: rgba(72, 187, 120, 0.15); color: var(--color-valid); }
  .badge-fail { background: rgba(245, 101, 101, 0.15); color: var(--color-invalid); }

  /* SCT table */
  .sct-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.7rem;
    margin-bottom: 0.4rem;
  }

  .sct-table th {
    text-align: left;
    color: var(--color-text-secondary);
    font-weight: 500;
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }

  .sct-table td {
    padding: 0.3rem 0.5rem;
    color: var(--color-text);
    border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  }
</style>
