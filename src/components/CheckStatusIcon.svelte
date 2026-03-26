<script lang="ts">
  import type { CheckStatus } from '../lib/types';
  export let status: CheckStatus;
</script>

<span class="status-icon {status}" aria-label={status === 'pass' ? 'Pass' : status === 'warn' ? 'Warning' : status === 'fail' ? 'Fail' : 'Info'}>
  {#if status === 'pass'}
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="8" fill="var(--color-valid)"/>
      <path d="M4.5 8L7 10.5L11.5 5.5" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  {:else if status === 'warn'}
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M8 1L15.5 14H0.5L8 1Z" fill="var(--color-warning)"/>
      <path d="M8 6V10" stroke="#1a1a2e" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="8" cy="12.5" r="1" fill="#1a1a2e"/>
    </svg>
  {:else if status === 'fail'}
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="8" fill="var(--color-invalid)"/>
      <path d="M5 5L11 11M11 5L5 11" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/>
    </svg>
  {:else}
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="8" fill="var(--color-info)"/>
      <path d="M8 7V11" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="8" cy="4.5" r="1" fill="#fff"/>
    </svg>
  {/if}
</span>

<style>
  .status-icon {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
    line-height: 1;
  }
</style>
