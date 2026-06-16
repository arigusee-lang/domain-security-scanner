<script lang="ts">
  export let score: number = 0;
  export let breakdown: Record<string, { earned: number; max: number }> = {};

  let showTooltip = false;

  $: roundedScore = Math.round(score);
  $: scoreColor = (() => {
    if (roundedScore >= 85) return 'green';
    if (roundedScore >= 70) return 'blue';
    if (roundedScore >= 55) return 'yellow';
    if (roundedScore >= 35) return 'orange';
    return 'red';
  })();

  $: breakdownEntries = Object.entries(breakdown);
</script>

<div
  class="score-badge-wrap"
  on:mouseenter={() => (showTooltip = true)}
  on:mouseleave={() => (showTooltip = false)}
  on:focus={() => (showTooltip = true)}
  on:blur={() => (showTooltip = false)}
  role="button"
  tabindex="0"
  aria-label="Security score {roundedScore} out of 100"
>
  <div class="badge {scoreColor}">
    <span class="score-value">{roundedScore}</span>
    <span class="score-out-of">/ 100</span>
  </div>

  {#if showTooltip && breakdownEntries.length > 0}
    <div class="tooltip" role="tooltip">
      <div class="tooltip-title">Score Breakdown</div>
      {#each breakdownEntries as [category, { earned, max }]}
        <div class="tooltip-row">
          <span class="tooltip-cat">{category}</span>
          <span class="tooltip-val">{earned}/{max}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .score-badge-wrap {
    position: relative;
    display: inline-flex;
    cursor: default;
  }

  .badge {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 80px;
    height: 80px;
    border-radius: 50%;
    border: 3px solid currentColor;
    background: var(--color-surface);
    transition: border-color var(--transition);
  }

  .badge.green { color: var(--color-valid); }
  .badge.blue { color: var(--color-info); }
  .badge.yellow { color: var(--color-warning); }
  .badge.orange { color: #f0883e; }
  .badge.red { color: var(--color-error); }

  .score-value {
    font-size: 1.6rem;
    font-weight: 700;
    line-height: 1;
  }

  .score-out-of {
    font-size: 0.65rem;
    opacity: 0.7;
    margin-top: 2px;
  }

  .tooltip {
    position: absolute;
    top: calc(100% + 8px);
    left: 50%;
    transform: translateX(-50%);
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.6rem 0.75rem;
    min-width: 200px;
    z-index: 50;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  }

  .tooltip-title {
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--color-text);
    margin-bottom: 0.4rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .tooltip-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.7rem;
    padding: 0.15rem 0;
    color: var(--color-text-secondary);
  }

  .tooltip-cat {
    text-transform: capitalize;
  }

  .tooltip-val {
    font-family: var(--font-mono);
    color: var(--color-text);
  }
</style>
