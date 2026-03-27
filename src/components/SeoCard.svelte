<script lang="ts">
  import type { SeoResult } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckItem from './CheckItem.svelte';

  export let data: SeoResult;

  $: passCount = data.items.filter(i => i.status === 'pass').length;
  $: subtitle = data.items.length > 0 ? `${passCount} of ${data.items.length} checks passed` : '';
</script>

<ResultCard title="SEO Basics" status={data.status} {subtitle}>
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
