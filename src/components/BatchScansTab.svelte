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

  onMount(() => loadBatches());

  async function loadBatches() {
    loading = true;
    error = '';
    try {
      const res = await get<{ batches: BatchItem[] }>('/api/batch');
      batches = res.batches;
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
    } catch (e: any) {
      error = e.message || 'Failed to delete batch';
    }
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
          <tr>
            <td class="name-cell">{batch.name || 'Untitled'}</td>
            <td>
              <span class="status-badge {batch.status}">{batch.status}</span>
            </td>
            <td class="count-cell">{batch.completed_domains}/{batch.total_domains}</td>
            <td class="date-cell">{formatDate(batch.created_at)}</td>
            <td>
              <button class="delete-btn" on:click={() => deleteBatch(batch.id)} aria-label="Delete batch {batch.name || batch.id}">
                ✕
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
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
</style>
