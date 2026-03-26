<script lang="ts">
  import type { CheckStatus } from '../lib/types';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let status: CheckStatus;
  export let title: string;
  export let detail: string = '';
  export let ref: string = '';
  export let compact: boolean = false;

  $: isIssue = status === 'fail' || status === 'warn';
  $: useCompact = compact || !isIssue;

  $: refLabel = (() => {
    if (!ref) return '';
    if (ref.includes('rfc-editor.org')) {
      const m = ref.match(/rfc(\d+)/);
      const s = ref.match(/#section-(.+)$/);
      return m ? `RFC ${m[1]}${s ? ' §' + s[1] : ''}` : 'RFC';
    }
    if (ref.includes('developer.mozilla.org')) return 'MDN';
    if (ref.includes('owasp.org')) return 'OWASP';
    return 'Docs';
  })();
</script>

{#if useCompact}
  <div class="check-compact {status}">
    <CheckStatusIcon {status} />
    <span class="compact-title">{title}</span>
    {#if detail}<span class="compact-detail">— {detail}</span>{/if}
    {#if ref}
      <a class="ref-link" href={ref} target="_blank" rel="noopener noreferrer">
        {refLabel}
        <svg class="ext-icon" width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M3.5 1H11V8.5M11 1L1 11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </a>
    {/if}
  </div>
{:else}
  <div class="check-item {status}">
    <div class="header">
      <CheckStatusIcon {status} />
      <span class="title">{title}</span>
    </div>
    {#if detail}
      <p class="detail">{detail}</p>
    {/if}
    {#if ref}
      <a class="ref-link-full" href={ref} target="_blank" rel="noopener noreferrer">
        {refLabel}
        <svg class="ext-icon" width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M3.5 1H11V8.5M11 1L1 11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </a>
    {/if}
    <slot />
  </div>
{/if}

<style>
  .check-compact {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.2rem 0;
    font-size: 0.8rem;
    flex-wrap: wrap;
  }

  .compact-title { color: var(--color-text); font-weight: 500; }
  .compact-detail { color: var(--color-text-secondary); font-size: 0.75rem; }

  .ref-link {
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
    margin-left: auto;
    font-size: 0.7rem;
    color: var(--color-accent);
    text-decoration: none;
    opacity: 0.75;
    transition: opacity 150ms ease;
  }
  .ref-link:hover { opacity: 1; text-decoration: underline; }

  .check-item {
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.55rem 0.8rem;
    border-left: 3px solid transparent;
  }

  .check-item.warn { border-left-color: var(--color-warning); }
  .check-item.fail { border-left-color: var(--color-error); }

  .header {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .title {
    font-weight: 600;
    font-size: 0.825rem;
    color: var(--color-text);
  }

  .detail {
    font-size: 0.775rem;
    color: var(--color-text-secondary);
    line-height: 1.5;
    margin-top: 0.2rem;
  }

  .ref-link-full {
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
    margin-top: 0.25rem;
    font-size: 0.72rem;
    color: var(--color-accent);
    text-decoration: none;
    opacity: 0.8;
    transition: opacity 150ms ease;
  }
  .ref-link-full:hover { opacity: 1; text-decoration: underline; }

  .ext-icon { flex-shrink: 0; }
</style>
