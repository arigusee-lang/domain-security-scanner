<script lang="ts">
  import type { HeadersResult } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let data: HeadersResult;

  $: presentCount = data.items.filter(i => i.present).length;
  $: subtitle = data.items.length > 0 ? `${presentCount} of ${data.items.length} headers present` : '';
</script>

<ResultCard title="Security Headers" status={data.status} {subtitle}>
  {#if data.items.length === 0}
    <p class="no-data">Headers could not be analyzed.</p>
  {:else}
    <div class="headers-table-wrap">
      <table class="headers-table">
        <thead>
          <tr>
            <th class="col-status"></th>
            <th>Header</th>
            <th>Value</th>
            <th>Note</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each data.items as item}
            <tr>
              <td class="icon-cell"><CheckStatusIcon status={item.status} /></td>
              <td class="header-name">{item.name}</td>
              <td class="header-value"><code>{item.value}</code></td>
              <td class="header-note">{item.explanation}</td>
              <td class="header-ref">
                {#if item.ref}
                  <a href={item.ref} target="_blank" rel="noopener noreferrer" class="ref-link" aria-label="Documentation for {item.name}">
                    MDN
                    <svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M3.5 1H11V8.5M11 1L1 11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  </a>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</ResultCard>

<style>
  .no-data { color: var(--color-text-secondary); font-size: 0.85rem; }

  .headers-table-wrap { overflow-x: auto; }

  .headers-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }

  .headers-table th {
    text-align: left;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--color-text-secondary);
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }

  .col-status { width: 28px; }

  .headers-table td {
    padding: 0.5rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
    vertical-align: middle;
  }

  .headers-table tr:last-child td { border-bottom: none; }

  .icon-cell { width: 28px; }

  .header-name {
    font-weight: 500;
    color: var(--color-text);
    white-space: nowrap;
  }

  .header-value code {
    background: var(--color-bg);
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    word-break: break-all;
  }

  .header-note {
    color: var(--color-text-secondary);
    font-size: 0.75rem;
  }

  .header-ref { white-space: nowrap; }

  .ref-link {
    display: inline-flex;
    align-items: center;
    gap: 0.15rem;
    font-size: 0.7rem;
    color: var(--color-accent);
    text-decoration: none;
    opacity: 0.75;
  }

  .ref-link:hover { opacity: 1; text-decoration: underline; }
</style>
