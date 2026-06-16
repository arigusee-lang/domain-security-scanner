<script lang="ts">
  import { onMount } from 'svelte';
  import { get, del } from '../lib/api';

  interface BatchItem {
    id: string;
    name: string | null;
    status: string;
    total_domains: number;
    completed_domains: number;
    created_at: string;
  }

  let batches: BatchItem[] = [];
  let loading = true;
  let error = '';
  let total = 0;
  let historyCap: number | null = null;

  $: capReached = historyCap !== null && historyCap > 0 && total >= historyCap;

  // Drill-down
  let selectedBatch: BatchItem | null = null;
  let batchDomains: any[] = [];
  let drillLoading = false;

  onMount(async () => {
    await loadBatches();
    // Auto-open the batch referenced in the URL hash (e.g. when returning from
    // a scan report that was opened from this tab).
    const params = new URLSearchParams(window.location.hash.replace(/^#\/dashboard\??/, ''));
    const batchIdFromUrl = params.get('batchId');
    if (batchIdFromUrl) {
      const target = batches.find(b => b.id === batchIdFromUrl);
      if (target) await selectBatch(target);
    }
  });

  async function loadBatches() {
    loading = true;
    error = '';
    try {
      const res = await get<{
        batches: BatchItem[]; total: number; historyCap?: number;
      }>('/api/batch');
      batches = res.batches;
      total = res.total;
      historyCap = res.historyCap ?? null;
    } catch (e: any) {
      error = e.message || 'Failed to load batch scans';
    } finally {
      loading = false;
    }
  }

  async function deleteBatch(id: string) {
    try {
      await del(`/api/batch/${id}`);
      batches = batches.filter(b => b.id !== id);
      if (selectedBatch?.id === id) selectedBatch = null;
    } catch (e: any) {
      error = e.message || 'Failed to delete batch';
    }
  }

  async function selectBatch(b: BatchItem) {
    if (selectedBatch?.id === b.id) { selectedBatch = null; return; }
    selectedBatch = b;
    drillLoading = true;
    try {
      const res = await get<any>(`/api/batch/${b.id}`);
      batchDomains = res.domains || [];
    } catch { batchDomains = []; }
    drillLoading = false;
  }

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString();
  }

  function goToNewBatch() {
    window.location.hash = '#/batch';
  }
</script>

<div class="batch-tab">
  <div class="tab-header">
    <button class="new-batch-btn" on:click={goToNewBatch}>+ New Batch</button>
  </div>

  {#if !loading && !error && capReached && historyCap !== null}
    <div class="cap-banner" role="note">
      Showing the {historyCap} most recent batch scans. Older entries are pruned automatically.
    </div>
  {/if}

  {#if loading}
    <p class="status-msg">Loading batch scans…</p>
  {:else if error}
    <p class="error-msg">{error}</p>
  {:else if batches.length === 0}
    <p class="status-msg">No batch scans yet.</p>
  {:else}
    <table class="batch-table" aria-label="Batch scans">
      <thead>
        <tr>
          <th>Name</th>
          <th>Status</th>
          <th>Domains</th>
          <th>Date</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each batches as batch (batch.id)}
          <tr class="batch-row" class:selected={selectedBatch?.id === batch.id} on:click={() => selectBatch(batch)}>
            <td class="name-cell">{batch.name || 'Untitled'}</td>
            <td>
              <span class="status-badge {batch.status}">{batch.status}</span>
            </td>
            <td class="count-cell">{batch.completed_domains}/{batch.total_domains}</td>
            <td class="date-cell">{formatDate(batch.created_at)}</td>
            <td>
              <button class="delete-btn" on:click|stopPropagation={() => deleteBatch(batch.id)} aria-label="Delete batch {batch.name || batch.id}">
                ✕
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>

    {#if selectedBatch}
    <div class="drill-panel">
      <div class="drill-header">
        <h4>{selectedBatch.name || 'Untitled'} — {batchDomains.length} domains</h4>
        <div class="drill-actions">
          <a class="csv-link" href="/api/batch/{selectedBatch.id}/csv" download>Download CSV</a>
          <button class="close-btn" on:click={() => selectedBatch = null}>✕</button>
        </div>
      </div>
      {#if drillLoading}
        <p class="status-msg">Loading…</p>
      {:else}
        <table class="batch-table domain-table">
          <thead><tr><th>Domain</th><th>Status</th><th>Score</th><th>Report</th></tr></thead>
          <tbody>
            {#each batchDomains as d (d.id)}
              <tr>
                <td class="name-cell">{d.domain}</td>
                <td><span class="status-badge {d.status}">{d.status}</span></td>
                <td>{d.scan?.score != null ? Math.round(d.scan.score) : '—'}</td>
                <td>{#if d.scan?.id}<a class="view-link" href="/#/?domain={encodeURIComponent(d.domain)}&scanId={d.scan.id}&view=history">View</a>{:else}—{/if}</td>
              </tr>
            {/each}
            {#if batchDomains.length === 0}<tr><td colspan="4" class="status-msg">No domains</td></tr>{/if}
          </tbody>
        </table>
      {/if}
    </div>
    {/if}
  {/if}
</div>

<style>
  .batch-tab {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .tab-header {
    display: flex;
    justify-content: flex-end;
  }

  .new-batch-btn {
    background: var(--color-accent);
    color: var(--color-bg);
    border: none;
    border-radius: var(--radius);
    padding: 0.4rem 0.8rem;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    font-family: var(--font-family);
    transition: background var(--transition);
  }

  .new-batch-btn:hover {
    background: var(--color-accent-hover);
  }

  .status-msg, .error-msg {
    text-align: center;
    font-size: 0.85rem;
    padding: 1.5rem 0;
  }

  .status-msg { color: var(--color-text-secondary); }
  .error-msg { color: var(--color-error); }

  .batch-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }

  .batch-table th {
    text-align: left;
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }

  .batch-table td {
    padding: 0.5rem;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text);
  }

  .name-cell { font-weight: 500; }
  .date-cell { color: var(--color-text-secondary); font-size: 0.75rem; }
  .count-cell { font-family: var(--font-mono); font-size: 0.75rem; }

  .status-badge {
    font-size: 0.65rem;
    font-weight: 600;
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    text-transform: uppercase;
  }

  .status-badge.completed { background: rgba(0, 212, 170, 0.1); color: var(--color-valid); }
  .status-badge.running { background: rgba(77, 166, 255, 0.1); color: var(--color-info); }
  .status-badge.pending { background: rgba(255, 184, 77, 0.1); color: var(--color-warning); }
  .status-badge.failed { background: rgba(255, 77, 106, 0.1); color: var(--color-error); }

  .delete-btn {
    background: none;
    border: none;
    color: var(--color-text-secondary);
    cursor: pointer;
    font-size: 0.75rem;
    padding: 0.2rem 0.4rem;
    border-radius: 3px;
  }

  .delete-btn:hover { color: var(--color-error); }

  .batch-row { cursor: pointer; transition: background var(--transition); }
  .batch-row:hover { background: rgba(255,255,255,0.03); }
  .batch-row.selected { background: rgba(255,255,255,0.03); }

  .drill-panel {
    background: var(--color-surface); border: 1px solid var(--color-border);
    border-radius: var(--radius); padding: 0.75rem; margin-top: 0.25rem;
  }
  .drill-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
  .drill-header h4 { font-size: 0.85rem; font-weight: 600; color: var(--color-text); margin: 0; }
  .drill-actions { display: flex; gap: 0.5rem; align-items: center; }
  .csv-link { font-size: 0.72rem; color: var(--color-accent); text-decoration: none; }
  .csv-link:hover { text-decoration: underline; }
  .close-btn { background: none; border: none; color: var(--color-text-secondary); cursor: pointer; font-size: 0.9rem; }
  .domain-table td { font-size: 0.75rem; }
  .view-link { color: var(--color-accent); text-decoration: none; font-size: 0.72rem; }
  .view-link:hover { text-decoration: underline; }

  .cap-banner {
    padding: 0.5rem 0.75rem;
    background: rgba(255, 184, 77, 0.08);
    border: 1px solid rgba(255, 184, 77, 0.3);
    border-radius: var(--radius);
    color: var(--color-text-secondary);
    font-size: 0.75rem;
  }
</style>
