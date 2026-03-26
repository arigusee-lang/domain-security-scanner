<script lang="ts">
  import type { CheckStatus } from '../lib/types';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let checks: { label: string; status: CheckStatus }[] = [];

  $: passCount = checks.filter(c => c.status === 'pass').length;
  $: warnCount = checks.filter(c => c.status === 'warn').length;
  $: failCount = checks.filter(c => c.status === 'fail').length;
  $: infoCount = checks.filter(c => c.status === 'info').length;
  $: total = checks.length;

  $: overallStatus = failCount > 0 ? 'fail' as CheckStatus
    : warnCount > 0 ? 'warn' as CheckStatus
    : 'pass' as CheckStatus;

  $: overallClass = overallStatus === 'pass' ? 'valid'
    : overallStatus === 'fail' ? 'invalid' : 'warnings';

  $: overallLabel = overallStatus === 'pass' ? 'All checks passed'
    : overallStatus === 'fail' ? `${failCount} issue${failCount !== 1 ? 's' : ''} found`
    : `${warnCount} warning${warnCount !== 1 ? 's' : ''}`;
</script>

<div class="summary-bar {overallClass}" role="status">
  <div class="summary-main">
    <CheckStatusIcon status={overallStatus} />
    <span class="summary-label">{overallLabel}</span>
    <span class="summary-counts">
      {#if passCount > 0}<span class="count pass-count">{passCount} passed</span>{/if}
      {#if warnCount > 0}<span class="count warn-count">{warnCount} warnings</span>{/if}
      {#if failCount > 0}<span class="count fail-count">{failCount} failed</span>{/if}
      {#if infoCount > 0}<span class="count info-count">{infoCount} info</span>{/if}
    </span>
  </div>
  <div class="progress-bar">
    {#if passCount > 0}<div class="seg pass-seg" style="width: {passCount / total * 100}%"></div>{/if}
    {#if warnCount > 0}<div class="seg warn-seg" style="width: {warnCount / total * 100}%"></div>{/if}
    {#if failCount > 0}<div class="seg fail-seg" style="width: {failCount / total * 100}%"></div>{/if}
    {#if infoCount > 0}<div class="seg info-seg" style="width: {infoCount / total * 100}%"></div>{/if}
  </div>
</div>

<style>
  .summary-bar {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    padding: 0.85rem 1.1rem;
  }

  .summary-bar.valid { border-color: rgba(0, 212, 170, 0.3); }
  .summary-bar.invalid { border-color: rgba(255, 77, 106, 0.3); }
  .summary-bar.warnings { border-color: rgba(255, 184, 77, 0.3); }

  .summary-main {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .summary-label {
    font-size: 0.9rem;
    font-weight: 600;
  }

  .valid .summary-label { color: var(--color-valid); }
  .invalid .summary-label { color: var(--color-invalid); }
  .warnings .summary-label { color: var(--color-warning); }

  .summary-counts {
    display: flex;
    gap: 0.6rem;
    margin-left: auto;
    font-size: 0.75rem;
    font-weight: 400;
  }

  .count { opacity: 0.85; }
  .pass-count { color: var(--color-valid); }
  .warn-count { color: var(--color-warning); }
  .fail-count { color: var(--color-error); }
  .info-count { color: var(--color-info); }

  .progress-bar {
    display: flex;
    height: 4px;
    border-radius: 2px;
    overflow: hidden;
    margin-top: 0.6rem;
    gap: 2px;
  }

  .seg {
    border-radius: 2px;
    min-width: 3px;
  }

  .pass-seg { background: var(--color-valid); }
  .warn-seg { background: var(--color-warning); }
  .fail-seg { background: var(--color-error); }
  .info-seg { background: var(--color-border); }
</style>
