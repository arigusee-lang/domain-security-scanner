<script lang="ts">
  import { onMount } from 'svelte';
  import DomainCheckerPage from './DomainCheckerPage.svelte';
  import SecurityTxtPage from './SecurityTxtPage.svelte';

  export let currentPath = '/';

  function updateRoute() {
    const hash = window.location.hash.replace('#', '') || '/';
    currentPath = hash.split('?')[0];
  }

  onMount(() => {
    updateRoute();
    window.addEventListener('hashchange', updateRoute);
    return () => window.removeEventListener('hashchange', updateRoute);
  });
</script>

{#if currentPath === '/security-txt'}
  <SecurityTxtPage />
{:else}
  <DomainCheckerPage />
{/if}
