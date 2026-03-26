<script lang="ts">
  import type { SslResult } from '../lib/types';
  import ResultCard from './ResultCard.svelte';

  export let data: SslResult;

  function formatDate(iso: string | null): string {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
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
</style>
