<script lang="ts">
  import type { CheckStatus } from '../lib/types';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let title: string;
  export let status: CheckStatus;
  export let expanded: boolean = false;
  export let subtitle: string = '';

  const id = `rc-${title.replace(/\s+/g, '-').toLowerCase()}`;

  function toggle() {
    expanded = !expanded;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggle();
    }
  }
</script>

<div class="result-card">
  <button
    class="card-header"
    on:click={toggle}
    on:keydown={handleKeydown}
    aria-expanded={expanded}
    aria-controls={id}
  >
    <CheckStatusIcon {status} />
    <span class="card-title">{title}</span>
    {#if subtitle}
      <span class="card-subtitle">{subtitle}</span>
    {/if}
    <span class="chevron" class:open={expanded} aria-hidden="true"></span>
  </button>
  {#if expanded}
    <div class="card-body" {id} role="region" aria-label="{title} details">
      <slot />
    </div>
  {/if}
</div>

<style>
  .result-card {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }

  .card-header {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.85rem 1.1rem;
    background: none;
    border: none;
    color: var(--color-text);
    font-family: var(--font-family);
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    text-align: left;
    transition: background var(--transition);
  }

  .card-header:hover {
    background: rgba(255, 255, 255, 0.03);
  }

  .card-title {
    flex-shrink: 0;
  }

  .card-subtitle {
    flex: 1;
    font-size: 0.75rem;
    font-weight: 400;
    color: var(--color-text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .chevron {
    display: inline-block;
    width: 0;
    height: 0;
    border-top: 5px solid transparent;
    border-bottom: 5px solid transparent;
    border-left: 7px solid var(--color-text-secondary);
    transition: transform var(--transition);
    flex-shrink: 0;
  }

  .chevron.open {
    transform: rotate(90deg);
  }

  .card-body {
    padding: 0 1.1rem 1.1rem;
  }
</style>
