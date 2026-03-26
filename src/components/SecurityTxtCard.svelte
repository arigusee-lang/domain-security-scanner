<script lang="ts">
  import type { SecurityTxtSection } from '../lib/types';
  import ResultCard from './ResultCard.svelte';

  export let data: SecurityTxtSection;

  $: statusLabel = data.available
    ? data.validationStatus === 'valid' ? 'Valid'
      : data.validationStatus === 'valid-with-warnings' ? 'Valid with warnings'
      : 'Invalid'
    : 'Not found';
</script>

<ResultCard title="security.txt" status={data.status} expanded={true}>
  {#if !data.available}
    <p class="not-found">{data.error || 'No security.txt file found on this domain.'}</p>
  {:else}
    <div class="status-line {data.validationStatus || ''}">
      <span class="status-label">{statusLabel}</span>
      {#if data.errorCount > 0}
        <span class="count error-count">{data.errorCount} {data.errorCount === 1 ? 'error' : 'errors'}</span>
      {/if}
      {#if data.warningCount > 0}
        <span class="count warning-count">{data.warningCount} {data.warningCount === 1 ? 'warning' : 'warnings'}</span>
      {/if}
    </div>

    {#if data.findings.length > 0}
      <div class="findings">
        {#each data.findings.slice(0, 5) as finding}
          <div class="finding-row {finding.severity}">
            <span class="sev-dot" aria-hidden="true"></span>
            <span class="finding-title">{finding.title}</span>
          </div>
        {/each}
        {#if data.findings.length > 5}
          <p class="more-findings">and {data.findings.length - 5} more…</p>
        {/if}
      </div>
    {/if}

    {#if data.fetchedFrom}
      <p class="fetched-from">Fetched from <code>{data.fetchedFrom}</code></p>
    {/if}
  {/if}

  <a class="learn-link" href="/#/security-txt">Learn more about security.txt →</a>
</ResultCard>

<style>
  .not-found {
    color: var(--color-text-secondary);
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
  }

  .status-line {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.6rem;
    font-size: 0.85rem;
  }

  .status-label {
    font-weight: 600;
  }

  .status-line.valid .status-label { color: var(--color-valid); }
  .status-line.invalid .status-label { color: var(--color-invalid); }
  .status-line.valid-with-warnings .status-label { color: var(--color-warning); }

  .count { font-size: 0.8rem; font-weight: 400; }
  .error-count { color: var(--color-error); }
  .warning-count { color: var(--color-warning); }

  .findings {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin-bottom: 0.6rem;
  }

  .finding-row {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--color-text-secondary);
  }

  .sev-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .finding-row.error .sev-dot { background: var(--color-error); }
  .finding-row.warning .sev-dot { background: var(--color-warning); }
  .finding-row.info .sev-dot { background: var(--color-info); }

  .finding-title {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .more-findings {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    opacity: 0.7;
  }

  .fetched-from {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    margin-bottom: 0.5rem;
  }

  .fetched-from code {
    background: var(--color-bg);
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
    font-size: 0.75rem;
  }

  .learn-link {
    display: inline-block;
    font-size: 0.8rem;
    color: var(--color-accent);
    margin-top: 0.3rem;
  }
</style>
