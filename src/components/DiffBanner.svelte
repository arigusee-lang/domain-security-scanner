<script lang="ts">
  export let diff: {
    previousScanDate: string | null;
    summary: {
      newIssues: number;
      resolvedIssues: number;
      totalChanges: number;
    };
  };

  $: dateStr = diff.previousScanDate
    ? new Date(diff.previousScanDate).toLocaleDateString()
    : 'unknown';
</script>

<div class="diff-banner" role="status" aria-label="Changes since last scan">
  <span class="change-count">{diff.summary.totalChanges} change{diff.summary.totalChanges !== 1 ? 's' : ''}</span>
  since last scan ({dateStr})
  {#if diff.summary.newIssues > 0 || diff.summary.resolvedIssues > 0}
    —
    {#if diff.summary.newIssues > 0}
      <span class="new-issues">{diff.summary.newIssues} new issue{diff.summary.newIssues !== 1 ? 's' : ''}</span>
    {/if}
    {#if diff.summary.newIssues > 0 && diff.summary.resolvedIssues > 0}, {/if}
    {#if diff.summary.resolvedIssues > 0}
      <span class="resolved-issues">{diff.summary.resolvedIssues} resolved</span>
    {/if}
  {/if}
</div>

<style>
  .diff-banner {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.5rem 0.75rem;
    font-size: 0.8rem;
    color: var(--color-text-secondary);
  }

  .change-count {
    font-weight: 600;
    color: var(--color-info);
  }

  .new-issues {
    color: var(--color-error);
    font-weight: 500;
  }

  .resolved-issues {
    color: var(--color-valid);
    font-weight: 500;
  }
</style>
