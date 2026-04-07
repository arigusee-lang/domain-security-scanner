<script lang="ts">
  import { onMount } from 'svelte';
  import { get, post, del, patch } from '../lib/api';

  interface ScheduleItem {
    id: string;
    name: string | null;
    domains_json: string;
    cron: string;
    enabled: number;
    last_run_at: string | null;
    next_run_at: string | null;
    created_at: string;
  }

  let schedules: ScheduleItem[] = [];
  let loading = true;
  let error = '';

  // Create form
  let showCreate = false;
  let newName = '';
  let newDomains = '';
  let newFrequency = 'daily';
  let creating = false;

  onMount(() => loadSchedules());

  async function loadSchedules() {
    loading = true;
    error = '';
    try {
      const res = await get<ScheduleItem[]>('/api/scheduled');
      schedules = res;
    } catch (e: any) {
      error = e.message || 'Failed to load schedules';
    } finally {
      loading = false;
    }
  }

  async function toggleSchedule(id: string) {
    try {
      await patch(`/api/scheduled/${id}/toggle`);
      schedules = schedules.map(s =>
        s.id === id ? { ...s, enabled: s.enabled ? 0 : 1 } : s
      );
    } catch (e: any) {
      error = e.message || 'Failed to toggle schedule';
    }
  }

  async function deleteSchedule(id: string) {
    try {
      await del(`/api/scheduled/${id}`);
      schedules = schedules.filter(s => s.id !== id);
    } catch (e: any) {
      error = e.message || 'Failed to delete schedule';
    }
  }

  const CRON_MAP: Record<string, string> = {
    daily: '0 9 * * *',
    weekly: '0 9 * * 1',
    monthly: '0 9 1 * *',
  };

  async function createSchedule() {
    const domains = newDomains.split('\n').map(d => d.trim()).filter(Boolean);
    if (domains.length === 0) { error = 'Enter at least one domain'; return; }
    creating = true;
    error = '';
    try {
      await post('/api/scheduled', {
        name: newName || null,
        domains,
        cron: CRON_MAP[newFrequency] || '0 9 * * *',
      });
      showCreate = false;
      newName = '';
      newDomains = '';
      await loadSchedules();
    } catch (e: any) {
      error = e.message || 'Failed to create schedule';
    } finally {
      creating = false;
    }
  }

  function getDomainCount(json: string): number {
    try { return JSON.parse(json).length; } catch { return 0; }
  }

  function formatDate(iso: string | null): string {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString();
  }
</script>

<div class="scheduled-tab">
  <div class="tab-header">
    <button class="create-btn" on:click={() => (showCreate = !showCreate)}>
      {showCreate ? 'Cancel' : '+ New Schedule'}
    </button>
  </div>

  {#if showCreate}
    <div class="create-form">
      <input class="form-input" type="text" placeholder="Schedule name (optional)" bind:value={newName} />
      <textarea class="form-textarea" placeholder="Domains (one per line)" bind:value={newDomains} rows="4"></textarea>
      <select class="form-select" bind:value={newFrequency}>
        <option value="daily">Daily</option>
        <option value="weekly">Weekly</option>
        <option value="monthly">Monthly</option>
      </select>
      <button class="submit-btn" on:click={createSchedule} disabled={creating}>
        {creating ? 'Creating…' : 'Create Schedule'}
      </button>
    </div>
  {/if}

  {#if error}
    <p class="error-msg">{error}</p>
  {/if}

  {#if loading}
    <p class="status-msg">Loading schedules…</p>
  {:else if schedules.length === 0 && !showCreate}
    <p class="status-msg">No scheduled scans yet.</p>
  {:else}
    <table class="schedule-table" aria-label="Scheduled scans">
      <thead>
        <tr>
          <th>Enabled</th>
          <th>Name</th>
          <th>Frequency</th>
          <th>Domains</th>
          <th>Last Run</th>
          <th>Next Run</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each schedules as sched (sched.id)}
          <tr>
            <td>
              <button
                class="toggle-btn"
                class:enabled={!!sched.enabled}
                on:click={() => toggleSchedule(sched.id)}
                aria-label="{sched.enabled ? 'Disable' : 'Enable'} schedule"
              >
                {sched.enabled ? '●' : '○'}
              </button>
            </td>
            <td class="name-cell">{sched.name || 'Untitled'}</td>
            <td class="freq-cell">{sched.cron}</td>
            <td class="count-cell">{getDomainCount(sched.domains_json)}</td>
            <td class="date-cell">{formatDate(sched.last_run_at)}</td>
            <td class="date-cell">{formatDate(sched.next_run_at)}</td>
            <td>
              <button class="delete-btn" on:click={() => deleteSchedule(sched.id)} aria-label="Delete schedule">✕</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .scheduled-tab {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .tab-header { display: flex; justify-content: flex-end; }

  .create-btn {
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

  .create-btn:hover { background: var(--color-accent-hover); }

  .create-form {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.75rem;
  }

  .form-input, .form-textarea, .form-select {
    background: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.5rem;
    font-size: 0.8rem;
    font-family: var(--font-family);
  }

  .form-textarea { resize: vertical; font-family: var(--font-mono); font-size: 0.75rem; }

  .submit-btn {
    align-self: flex-start;
    background: var(--color-accent);
    color: var(--color-bg);
    border: none;
    border-radius: var(--radius);
    padding: 0.4rem 0.8rem;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    font-family: var(--font-family);
  }

  .submit-btn:disabled { opacity: 0.5; cursor: default; }

  .status-msg, .error-msg {
    text-align: center;
    font-size: 0.85rem;
    padding: 1.5rem 0;
  }

  .status-msg { color: var(--color-text-secondary); }
  .error-msg { color: var(--color-error); }

  .schedule-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }

  .schedule-table th {
    text-align: left;
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.4rem 0.4rem;
    border-bottom: 1px solid var(--color-border);
  }

  .schedule-table td {
    padding: 0.4rem;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text);
  }

  .name-cell { font-weight: 500; }
  .freq-cell { font-size: 0.75rem; color: var(--color-text-secondary); }
  .count-cell { font-family: var(--font-mono); font-size: 0.75rem; }
  .date-cell { font-size: 0.7rem; color: var(--color-text-secondary); }

  .toggle-btn {
    background: none;
    border: none;
    font-size: 1rem;
    cursor: pointer;
    color: var(--color-text-secondary);
    padding: 0;
  }

  .toggle-btn.enabled { color: var(--color-valid); }

  .delete-btn {
    background: none;
    border: none;
    color: var(--color-text-secondary);
    cursor: pointer;
    font-size: 0.75rem;
    padding: 0.2rem 0.4rem;
  }

  .delete-btn:hover { color: var(--color-error); }
</style>
