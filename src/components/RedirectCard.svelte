<script lang="ts">
  import type { RedirectResult } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckItem from './CheckItem.svelte';

  export let data: RedirectResult;

  $: subtitle = data.httpsRedirect ? 'HTTPS redirect active' : '';
</script>

<ResultCard title="HTTPS & Redirects" status={data.status} {subtitle}>
  {#if data.error}
    <p class="error-text">{data.error}</p>
  {:else}
    <div class="items-stack">
      {#each data.items as item}
        <CheckItem status={item.status} title={item.check} detail={item.detail} ref={item.ref || ''} />
      {/each}
    </div>
  {/if}
</ResultCard>

<style>
  .error-text { color: var(--color-error); font-size: 0.85rem; }
  .items-stack { display: flex; flex-direction: column; gap: 0.35rem; }
</style>
