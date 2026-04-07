<script lang="ts">
  export let remediation: {
    summary: string;
    steps: string[];
    effort: string;
    impact: string;
    ref: string;
  };

  let open = false;
  let copyFeedback = '';

  function toggle() {
    open = !open;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggle();
    }
  }

  async function copyText(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copyFeedback = 'Copied!';
      setTimeout(() => (copyFeedback = ''), 1500);
    } catch {
      copyFeedback = 'Failed to copy';
      setTimeout(() => (copyFeedback = ''), 1500);
    }
  }

  $: effortClass = remediation.effort === 'low' ? 'badge-green'
    : remediation.effort === 'medium' ? 'badge-yellow' : 'badge-red';

  $: impactClass = remediation.impact === 'high' ? 'badge-green'
    : remediation.impact === 'medium' ? 'badge-yellow' : 'badge-red';
</script>

<div class="remediation-panel">
  <button
    class="toggle-btn"
    on:click={toggle}
    on:keydown={handleKeydown}
    aria-expanded={open}
    aria-controls="remediation-content"
  >
    <span class="toggle-icon" aria-hidden="true">{open ? '▾' : '▸'}</span>
    <span class="toggle-label">How to fix</span>
    <span class="effort-badge {effortClass}">Effort: {remediation.effort}</span>
    <span class="impact-badge {impactClass}">Impact: {remediation.impact}</span>
  </button>

  {#if open}
    <div class="content" id="remediation-content">
      <p class="summary">{remediation.summary}</p>

      <ol class="steps">
        {#each remediation.steps as step, i}
          <li class="step">
            <span class="step-text">{step}</span>
            {#if step.includes('TXT') || step.includes('CNAME') || step.includes('MX') || step.includes('v=') || step.includes('Header')}
              <button
                class="copy-btn"
                on:click={() => copyText(step)}
                aria-label="Copy step {i + 1}"
              >
                {copyFeedback || 'Copy'}
              </button>
            {/if}
          </li>
        {/each}
      </ol>

      {#if remediation.ref}
        <a class="ref-link" href={remediation.ref} target="_blank" rel="noopener noreferrer">
          Learn more ↗
        </a>
      {/if}
    </div>
  {/if}
</div>

<style>
  .remediation-panel {
    margin-top: 0.5rem;
    border-top: 1px solid var(--color-border);
    padding-top: 0.4rem;
  }

  .toggle-btn {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    background: none;
    border: none;
    color: var(--color-accent);
    font-size: 0.75rem;
    font-weight: 600;
    cursor: pointer;
    padding: 0.2rem 0;
    font-family: var(--font-family);
  }

  .toggle-btn:hover {
    opacity: 0.85;
  }

  .toggle-icon {
    font-size: 0.65rem;
    width: 0.8rem;
  }

  .effort-badge, .impact-badge {
    font-size: 0.6rem;
    font-weight: 500;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    text-transform: capitalize;
  }

  .badge-green { background: rgba(0, 212, 170, 0.15); color: var(--color-valid); }
  .badge-yellow { background: rgba(255, 184, 77, 0.15); color: var(--color-warning); }
  .badge-red { background: rgba(255, 77, 106, 0.15); color: var(--color-error); }

  .content {
    padding: 0.5rem 0 0.25rem 1.2rem;
  }

  .summary {
    font-size: 0.8rem;
    color: var(--color-text);
    margin-bottom: 0.5rem;
  }

  .steps {
    padding-left: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .step {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    line-height: 1.5;
    display: flex;
    align-items: flex-start;
    gap: 0.4rem;
  }

  .step-text {
    flex: 1;
    word-break: break-word;
  }

  .copy-btn {
    flex-shrink: 0;
    font-size: 0.6rem;
    padding: 0.15rem 0.4rem;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 3px;
    color: var(--color-text-secondary);
    cursor: pointer;
    font-family: var(--font-family);
    transition: border-color var(--transition);
  }

  .copy-btn:hover {
    border-color: var(--color-accent);
    color: var(--color-accent);
  }

  .ref-link {
    display: inline-block;
    margin-top: 0.4rem;
    font-size: 0.7rem;
    color: var(--color-accent);
    text-decoration: none;
  }

  .ref-link:hover {
    text-decoration: underline;
  }
</style>
