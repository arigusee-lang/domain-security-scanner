<script lang="ts">
  import type { CtLogsResult } from '../lib/types';
  import ResultCard from './ResultCard.svelte';

  export let data: CtLogsResult;

  let showAll = false;

  function formatDate(d: string): string {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }
</script>

<ResultCard title="Certificate Transparency" status={data.status}>
  {#if data.error}
    <p class="error-text">{data.error}</p>
  {:else}
    <p class="summary">{data.totalCerts} certificate{data.totalCerts !== 1 ? 's' : ''} found in CT logs</p>
    {#if data.recentCerts.length > 0}
      <div class="ct-table-wrap">
        <table class="ct-table">
          <thead><tr><th>Common Name</th><th>Issuer</th><th>Issued</th><th>Expires</th></tr></thead>
          <tbody>
            {#each (showAll ? data.recentCerts : data.recentCerts.slice(0, 5)) as cert}
              <tr>
                <td class="cn">{cert.commonName}</td>
                <td>{cert.issuerName}</td>
                <td>{formatDate(cert.notBefore)}</td>
                <td>{formatDate(cert.notAfter)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if data.recentCerts.length > 5}
        <button class="toggle-btn" on:click={() => showAll = !showAll}>
          {showAll ? 'Show less' : `Show all ${data.recentCerts.length}`}
        </button>
      {/if}
    {/if}
    <p class="source">Data from <a href="https://crt.sh/?q={encodeURIComponent('%.'+data.recentCerts[0]?.commonName?.replace('*.','') || '')}" target="_blank" rel="noopener">crt.sh</a></p>
  {/if}
</ResultCard>

<style>
  .error-text { color: var(--color-error); font-size: 0.85rem; }
  .summary { font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: 0.5rem; }
  .ct-table-wrap { overflow-x: auto; }
  .ct-table { width: 100%; border-collapse: collapse; font-size: 0.75rem; }
  .ct-table th {
    text-align: left; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.04em; color: var(--color-text-secondary); padding: 0.3rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }
  .ct-table td { padding: 0.35rem 0.5rem; color: var(--color-text-secondary); border-bottom: 1px solid var(--color-border); }
  .ct-table tr:last-child td { border-bottom: none; }
  .cn { font-family: var(--font-mono); color: var(--color-text); font-size: 0.75rem; }
  .toggle-btn {
    background: none; border: 1px solid var(--color-border); border-radius: var(--radius);
    color: var(--color-accent); font-family: var(--font-family); font-size: 0.75rem;
    padding: 0.2rem 0.6rem; cursor: pointer; margin-top: 0.4rem;
  }
  .toggle-btn:hover { background: rgba(0, 212, 170, 0.08); }
  .source { font-size: 0.7rem; color: var(--color-text-secondary); opacity: 0.6; margin-top: 0.4rem; }
</style>
