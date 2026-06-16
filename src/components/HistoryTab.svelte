<script lang="ts">
  import { onMount } from 'svelte';
  import { get, del } from '../lib/api';
  import { currentUser } from '../lib/authStore';

  interface ScanItem {
    id: string;
    domain: string;
    score: number | null;
    created_at: string;
    status: string;
  }

  let scans: ScanItem[] = [];
  let loading = true;
  let error = '';
  let page = 1;
  let totalPages = 1;
  let total = 0;
  let historyCap: number | null = null;

  $: plan = $currentUser?.plan;
  $: capReached = historyCap !== null && total >= historyCap;

  onMount(() => loadScans());

  async function loadScans() {
    loading = true;
    error = '';
    try {
      const res = await get<{
        scans: ScanItem[]; total: number; page: number; totalPages: number; historyCap?: number;
      }>(`/api/scans?page=${page}`);
      scans = res.scans;
      totalPages = res.totalPages;
      total = res.total;
      historyCap = res.historyCap ?? null;
    } catch (e: any) {
      error = e.message || 'Failed to load scans';
    } finally {
      loading = false;
    }
  }

  async function deleteScan(id: string) {
    try {
      await del(`/api/scans/${id}`);
      scans = scans.filter(s => s.id !== id);
    } catch (e: any) {
      error = e.message || 'Failed to delete scan';
    }
  }

  function prevPage() {
    if (page > 1) { page--; loadScans(); }
  }

  function nextPage() {
    if (page < totalPages) { page++; loadScans(); }
  }

  function formatDate(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
</script>

<div class="history-tab">
  {#if !loading && !error && capReached && historyCap !== null}
    <div class="cap-banner" role="note">
      <span>
        Showing the {historyCap} most recent scans on the
        <strong>{plan === 'free' ? 'Free' : plan === 'premium' ? 'Premium' : 'Premium+'}</strong> plan.
        Older entries are pruned automatically.
      </span>
      {#if plan === 'free'}
        <a class="upgrade-link" href="#/dashboard?tab=settings">Upgrade →</a>
      {/if}
    </div>
  {/if}

  {#if loading}
    <p class="status-msg">Loading scans…</p>
  {:else if error}
    <p class="error-msg">{error}</p>
  {:else if scans.length === 0}
    <p class="status-msg">No scans yet. Run a domain check to get started.</p>
  {:else}
    <table class="scan-table" aria-label="Scan history">
      <thead>
        <tr>
          <th>Domain</th>
          <th>Date</th>
          <th>Score</th>
          <th>Report</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each scans as scan (scan.id)}
          <tr>
            <td class="domain-cell">{scan.domain}</td>
            <td class="date-cell">{formatDate(scan.created_at)}</td>
            <td class="score-cell">{scan.score != null ? Math.round(scan.score) : '—'}</td>
            <td>
              <a class="report-link" href="/#/?domain={encodeURIComponent(scan.domain)}&scanId={scan.id}&view=history">View</a>
            </td>
            <td>
              <button class="delete-btn" on:click={() => deleteScan(scan.id)} aria-label="Delete scan for {scan.domain}">
                ✕
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>

    <div class="pagination">
      <button class="page-btn" disabled={page <= 1} on:click={prevPage}>← Prev</button>
      <span class="page-info">Page {page} of {totalPages}</span>
      <button class="page-btn" disabled={page >= totalPages} on:click={nextPage}>Next →</button>
    </div>
  {/if}
</div>

<style>
  .history-tab {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .status-msg {
    color: var(--color-text-secondary);
    font-size: 0.85rem;
    text-align: center;
    padding: 1.5rem 0;
  }

  .error-msg {
    color: var(--color-error);
    font-size: 0.85rem;
    text-align: center;
  }

  .scan-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }

  .scan-table th {
    text-align: left;
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }

  .scan-table td {
    padding: 0.5rem;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text);
  }

  .domain-cell {
    font-weight: 500;
    font-family: var(--font-mono);
    font-size: 0.75rem;
  }

  .date-cell {
    color: var(--color-text-secondary);
    font-size: 0.75rem;
  }

  .score-cell {
    font-weight: 600;
    font-family: var(--font-mono);
  }

  .report-link {
    font-size: 0.75rem;
    color: var(--color-accent);
    text-decoration: none;
  }

  .report-link:hover {
    text-decoration: underline;
  }

  .delete-btn {
    background: none;
    border: none;
    color: var(--color-text-secondary);
    cursor: pointer;
    font-size: 0.75rem;
    padding: 0.2rem 0.4rem;
    border-radius: 3px;
    transition: color var(--transition);
  }

  .delete-btn:hover {
    color: var(--color-error);
  }

  .pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
  }

  .page-btn {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    color: var(--color-text);
    font-size: 0.75rem;
    padding: 0.3rem 0.6rem;
    cursor: pointer;
    font-family: var(--font-family);
    transition: border-color var(--transition);
  }

  .page-btn:hover:not(:disabled) {
    border-color: var(--color-accent);
  }

  .page-btn:disabled {
    opacity: 0.4;
    cursor: default;
  }

  .page-info {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
  }

  .cap-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    background: rgba(255, 184, 77, 0.08);
    border: 1px solid rgba(255, 184, 77, 0.3);
    border-radius: var(--radius);
    color: var(--color-text-secondary);
    font-size: 0.75rem;
  }

  .cap-banner strong {
    color: var(--color-text);
    font-weight: 600;
  }

  .upgrade-link {
    color: var(--color-accent);
    font-weight: 600;
    text-decoration: none;
    white-space: nowrap;
  }

  .upgrade-link:hover {
    text-decoration: underline;
  }
</style>
