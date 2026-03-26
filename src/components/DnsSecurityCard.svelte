<script lang="ts">
  import type { DnssecResult, CaaResult, NsResult, DomainExpiryResult, DanglingDnsResult, CheckStatus } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let dnssec: DnssecResult;
  export let caa: CaaResult;
  export let ns: NsResult;
  export let domainExpiry: DomainExpiryResult;
  export let danglingDns: DanglingDnsResult;

  function worst(...statuses: CheckStatus[]): CheckStatus {
    const order: Record<CheckStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
    return statuses.reduce((a, b) => order[a] <= order[b] ? a : b);
  }

  $: overall = worst(dnssec.status, caa.status, ns.status, domainExpiry.status, danglingDns.status);

  function formatDate(iso: string | null): string {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }
</script>

<ResultCard title="DNS & Domain" status={overall}>
  <!-- DNSSEC -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={dnssec.status} /> DNSSEC</h4>
    <p class="sub-detail">{dnssec.enabled ? 'Enabled — DS records found' : 'Not enabled'}</p>
    {#if dnssec.error}<p class="error-text">{dnssec.error}</p>{/if}
  </section>

  <!-- CAA -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={caa.status} /> CAA Records</h4>
    {#if caa.records.length > 0}
      <div class="caa-list">
        {#each caa.records as r}
          <div class="caa-row"><code>{r.tag}</code> <span>{r.value}</span></div>
        {/each}
      </div>
    {:else}
      <p class="sub-detail">No CAA records — any CA can issue certificates for this domain.</p>
    {/if}
    {#if caa.error}<p class="error-text">{caa.error}</p>{/if}
  </section>

  <!-- NS -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={ns.status} /> Nameservers</h4>
    {#if ns.nameservers.length > 0}
      <div class="ns-list">
        {#each ns.nameservers as n}
          <span class="ns-chip">{n}</span>
        {/each}
      </div>
    {:else}
      <p class="error-text">{ns.error || 'No NS records found'}</p>
    {/if}
  </section>

  <!-- Domain Expiry -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={domainExpiry.status} /> Domain Expiration</h4>
    {#if domainExpiry.expirationDate}
      <p class="sub-detail">
        Expires {formatDate(domainExpiry.expirationDate)}
        {#if domainExpiry.daysRemaining != null}
          <span class="days-badge" class:warn={domainExpiry.daysRemaining <= 60} class:fail={domainExpiry.daysRemaining < 0}>
            ({domainExpiry.daysRemaining < 0 ? 'expired' : `${domainExpiry.daysRemaining} days remaining`})
          </span>
        {/if}
      </p>
    {:else}
      <p class="sub-detail">{domainExpiry.error || 'Expiration date not available'}</p>
    {/if}
  </section>

  <!-- Dangling DNS -->
  {#if danglingDns.records.length > 0}
    <section class="sub-section">
      <h4 class="sub-title"><CheckStatusIcon status={danglingDns.status} /> DNS Record Health</h4>
      {#if danglingDns.danglingCount === 0}
        <p class="sub-detail">All MX and NS hostnames resolve correctly</p>
      {:else}
        <p class="warn-text">{danglingDns.danglingCount} dangling record{danglingDns.danglingCount !== 1 ? 's' : ''} found</p>
        <div class="dangling-list">
          {#each danglingDns.records.filter(r => !r.resolves) as r}
            <div class="dangling-row">
              <span class="dangling-type">{r.type}</span>
              <code>{r.hostname}</code>
              <span class="dangling-status">does not resolve</span>
            </div>
          {/each}
        </div>
      {/if}
    </section>
  {/if}
</ResultCard>

<style>
  .sub-section {
    padding: 0.6rem 0;
    border-bottom: 1px solid var(--color-border);
  }

  .sub-section:last-child {
    border-bottom: none;
    padding-bottom: 0;
  }

  .sub-title {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--color-text);
    margin-bottom: 0.3rem;
  }

  .sub-detail {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
  }

  .error-text {
    color: var(--color-error);
    font-size: 0.8rem;
  }

  .caa-list {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .caa-row {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    font-size: 0.8rem;
    color: var(--color-text-secondary);
  }

  .caa-row code {
    background: var(--color-bg);
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
    font-size: 0.75rem;
    color: var(--color-text);
  }

  .ns-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
  }

  .ns-chip {
    display: inline-block;
    padding: 0.2rem 0.5rem;
    border-radius: 100px;
    font-size: 0.75rem;
    font-family: var(--font-mono);
    border: 1px solid var(--color-border);
    color: var(--color-text-secondary);
    background: var(--color-surface);
  }

  .days-badge {
    font-size: 0.75rem;
  }

  .days-badge.warn {
    color: var(--color-warning);
  }

  .days-badge.fail {
    color: var(--color-error);
  }

  .warn-text { font-size: 0.8rem; color: var(--color-warning); margin-bottom: 0.3rem; }
  .dangling-list { display: flex; flex-direction: column; gap: 0.2rem; }
  .dangling-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.75rem; color: var(--color-text-secondary); }
  .dangling-type { font-size: 0.7rem; font-weight: 600; color: var(--color-text-secondary); min-width: 24px; }
  .dangling-row code { background: var(--color-bg); padding: 0.05rem 0.3rem; border-radius: 3px; font-size: 0.75rem; }
  .dangling-status { color: var(--color-error); font-size: 0.7rem; margin-left: auto; }
</style>
