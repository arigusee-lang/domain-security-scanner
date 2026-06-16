<script lang="ts">
  import { onMount } from 'svelte';
  import { get } from '../lib/api';
  import ScoreBadge from './ScoreBadge.svelte';

  export let reportId = '';

  let loading = true;
  let error = '';
  let report: {
    domain: string;
    created_at: string;
    score: number | null;
    result_json: string | null;
  } | null = null;

  onMount(async () => {
    if (!reportId) {
      error = 'Report not found or expired.';
      loading = false;
      return;
    }
    try {
      report = await get(`/api/reports/${reportId}`);
    } catch (e: any) {
      if (e.status === 404) {
        error = 'Report not found or expired.';
      } else {
        error = e.message || 'Failed to load report.';
      }
    } finally {
      loading = false;
    }
  });

  function formatDate(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleDateString() + ' at ' +
      d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
</script>

<div class="report-page">
  {#if loading}
    <p class="status-msg">Loading report…</p>
  {:else if error}
    <div class="error-state">
      <p class="error-icon">🔒</p>
      <p class="error-text">{error}</p>
    </div>
  {:else if report}
    <div class="report-content">
      <div class="report-header">
        <h1 class="report-title">{report.domain}</h1>
        <p class="report-date">
          Scanned on {formatDate(report.created_at)}
        </p>
      </div>

      {#if report.score != null}
        <div class="score-section">
          <ScoreBadge score={report.score} breakdown={{}} />
        </div>
      {/if}

      <div class="report-details">
        <p class="detail-note">
          This is a shared report. Full interactive results are
          available to the report owner.
        </p>
      </div>
    </div>
  {/if}
</div>

<style>
  .report-page {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .status-msg {
    text-align: center;
    color: var(--color-text-secondary);
    font-size: 0.85rem;
    padding: 2rem 0;
  }

  .error-state {
    text-align: center;
    padding: 3rem 0;
  }

  .error-icon {
    font-size: 2rem;
    margin-bottom: 0.5rem;
  }

  .error-text {
    color: var(--color-text-secondary);
    font-size: 0.9rem;
  }

  .report-content {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .report-header {
    text-align: center;
  }

  .report-title {
    font-size: 1.3rem;
    font-weight: 700;
    color: var(--color-text);
    font-family: var(--font-mono);
  }

  .report-date {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    margin-top: 0.25rem;
  }

  .score-section {
    display: flex;
    justify-content: center;
  }

  .report-details {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 1rem;
  }

  .detail-note {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    text-align: center;
  }
</style>
