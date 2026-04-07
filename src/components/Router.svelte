<script lang="ts">
  import { onMount } from 'svelte';
  import DomainCheckerPage from './DomainCheckerPage.svelte';
  import SecurityTxtPage from './SecurityTxtPage.svelte';
  import TermsPage from './TermsPage.svelte';
  import PrivacyPage from './PrivacyPage.svelte';
  import RefundPage from './RefundPage.svelte';
  import ContactPage from './ContactPage.svelte';
  import DashboardPage from './DashboardPage.svelte';
  import BatchScanPage from './BatchScanPage.svelte';
  import ReportPage from './ReportPage.svelte';

  export let currentPath = '/';
  let routeParam = '';

  function updateRoute() {
    const hash = window.location.hash.replace('#', '') || '/';
    const path = hash.split('?')[0];
    currentPath = path;

    // Extract route params for /report/:id
    const reportMatch = path.match(/^\/report\/(.+)$/);
    if (reportMatch) {
      routeParam = reportMatch[1];
      currentPath = '/report';
    } else {
      routeParam = '';
    }
  }

  onMount(() => {
    updateRoute();
    window.addEventListener('hashchange', updateRoute);
    return () => window.removeEventListener('hashchange', updateRoute);
  });
</script>

{#if currentPath === '/security-txt'}
  <SecurityTxtPage />
{:else if currentPath === '/terms'}
  <TermsPage />
{:else if currentPath === '/privacy'}
  <PrivacyPage />
{:else if currentPath === '/refund'}
  <RefundPage />
{:else if currentPath === '/contact'}
  <ContactPage />
{:else if currentPath === '/dashboard'}
  <DashboardPage />
{:else if currentPath === '/batch'}
  <BatchScanPage />
{:else if currentPath === '/report'}
  <ReportPage reportId={routeParam} />
{:else}
  <DomainCheckerPage />
{/if}
