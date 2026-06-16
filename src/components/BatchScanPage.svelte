<script lang="ts">
  import { onDestroy } from 'svelte';
  import { currentUser } from '../lib/authStore';
  import { post, get } from '../lib/api';

  let user: import('../lib/authStore').AuthUser | null = null;
  const unsub = currentUser.subscribe(v => (user = v));
  onDestroy(() => unsub());

  let domainsText = '';
  let batchName = '';
  let error = '';
  let batchId = '';
  let status = 'idle'; // idle | running | completed | failed
  let totalDomains = 0;
  let completedDomains = 0;
  let results: Array<{
    domain: string;
    status: string;
    scan?: { score: number | null } | null;
  }> = [];
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  function cleanup() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }
  onDestroy(cleanup);

  async function startBatch() {
    error = '';
    const domains = domainsText
      .split('\n')
      .map(d => d.trim().replace(/^https?:\/\//, '').split('/')[0])
      .filter(Boolean);

    if (domains.length === 0) {
      error = 'Enter at least one domain.';
      return;
    }
    if (domains.length > 500) {
      error = 'Maximum 500 domains per batch.';
      return;
    }

    status = 'running';
    totalDomains = domains.length;
    completedDomains = 0;
    results = [];

    try {
      const res = await post<{ id: string }>('/api/batch', {
        domains,
        name: batchName || undefined,
      });
      batchId = res.id;
      pollProgress();
    } catch (e: any) {
      error = e.message || 'Failed to start batch scan';
      status = 'failed';
    }
  }

  function pollProgress() {
    pollTimer = setInterval(async () => {
      try {
        const res = await get<{
          status: string;
          total_domains: number;
          completed_domains: number;
          domains: Array<{ domain: string; status: string; scan?: { score: number | null } | null }>;
        }>(`/api/batch/${batchId}`);

        completedDomains = res.completed_domains;
        totalDomains = res.total_domains;

        if (res.status === 'completed' || res.status === 'failed') {
          status = res.status;
          results = res.domains || [];
          cleanup();
        }
      } catch {
        // keep polling
      }
    }, 3000);
  }

  function downloadCsv() {
    window.open(`/api/batch/${batchId}/csv`, '_blank');
  }
</script>

{#if !user}
  <div class="auth-prompt">
    <p>Please <a href="/api/auth/google">sign in</a> to use batch scanning.</p>
  </div>
{:else}
  <div class="batch-page">
    <h1 class="page-title">Batch Domain Scan</h1>

    {#if status === 'idle'}
      <div class="form-section">
        <input
          class="name-input"
          type="text"
          placeholder="Batch name (optional)"
          bind:value={batchName}
        />
        <textarea
          class="domains-input"
          placeholder="Enter domains, one per line&#10;example.com&#10;another.org"
          bind:value={domainsText}
          rows="8"
        ></textarea>
        {#if error}
          <p class="error-msg" role="alert">{error}</p>
        {/if}
        <button class="start-btn" on:click={startBatch}>Start Batch Scan</button>
      </div>
    {/if}

    {#if status === 'running'}
      <div class="progress-section">
        <div class="progress-text">
          {completedDomains} of {totalDomains} domains scanned
        </div>
        <div class="progress-bar">
          <div
            class="progress-fill"
            style="width: {totalDomains > 0 ? (completedDomains / totalDomains) * 100 : 0}%"
          ></div>
        </div>
      </div>
    {/if}

    {#if status === 'completed' && results.length > 0}
      <div class="results-section">
        <div class="results-header">
          <span class="results-count">{results.length} domains scanned</span>
          <button class="csv-btn" on:click={downloadCsv}>Download CSV</button>
        </div>
        <table class="results-table" aria-label="Batch scan results">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Status</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody>
            {#each results as row}
              <tr>
                <td class="domain-cell">{row.domain}</td>
                <td>
                  <span class="status-badge {row.status}">{row.status}</span>
                </td>
                <td class="score-cell">{row.scan?.score != null ? Math.round(row.scan.score) : '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    {#if status === 'failed'}
      <p class="error-msg">{error || 'Batch scan failed.'}</p>
    {/if}
  </div>
{/if}

<style>
  .auth-prompt {
    text-align: center;
    padding: 3rem 0;
    color: var(--color-text-secondary);
    font-size: 0.9rem;
  }

  .batch-page {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .page-title {
    font-size: 1.3rem;
    font-weight: 700;
    color: var(--color-text);
  }

  .form-section {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .name-input {
    background: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.6rem 0.8rem;
    font-size: 0.85rem;
    font-family: var(--font-family);
  }

  .name-input:focus {
    border-color: var(--color-accent);
    outline: none;
  }

  .domains-input {
    background: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.6rem 0.8rem;
    font-size: 0.8rem;
    font-family: var(--font-mono);
    resize: vertical;
  }

  .domains-input:focus {
    border-color: var(--color-accent);
    outline: none;
  }

  .error-msg {
    color: var(--color-error);
    font-size: 0.8rem;
  }

  .start-btn {
    align-self: flex-start;
    background: var(--color-accent);
    color: var(--color-bg);
    border: none;
    border-radius: var(--radius);
    padding: 0.6rem 1.2rem;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    font-family: var(--font-family);
    transition: background var(--transition);
  }

  .start-btn:hover { background: var(--color-accent-hover); }

  .progress-section {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 1rem;
  }

  .progress-text {
    font-size: 0.85rem;
    color: var(--color-text);
    margin-bottom: 0.5rem;
    font-weight: 500;
  }

  .progress-bar {
    height: 6px;
    background: var(--color-border);
    border-radius: 3px;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background: var(--color-accent);
    border-radius: 3px;
    transition: width 0.3s ease;
  }

  .results-section {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .results-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .results-count {
    font-size: 0.85rem;
    color: var(--color-text);
    font-weight: 500;
  }

  .csv-btn {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    color: var(--color-accent);
    font-size: 0.75rem;
    padding: 0.3rem 0.6rem;
    cursor: pointer;
    font-family: var(--font-family);
    transition: border-color var(--transition);
  }

  .csv-btn:hover { border-color: var(--color-accent); }

  .results-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }

  .results-table th {
    text-align: left;
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }

  .results-table td {
    padding: 0.5rem;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text);
  }

  .domain-cell {
    font-family: var(--font-mono);
    font-size: 0.75rem;
  }

  .score-cell { font-weight: 600; font-family: var(--font-mono); }

  .status-badge {
    font-size: 0.65rem;
    font-weight: 600;
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    text-transform: uppercase;
  }

  .status-badge.completed { background: rgba(0, 212, 170, 0.1); color: var(--color-valid); }
  .status-badge.failed { background: rgba(255, 77, 106, 0.1); color: var(--color-error); }
  .status-badge.pending { background: rgba(255, 184, 77, 0.1); color: var(--color-warning); }
  .status-badge.running { background: rgba(77, 166, 255, 0.1); color: var(--color-info); }
</style>
