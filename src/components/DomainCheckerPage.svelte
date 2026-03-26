<script lang="ts">
  import { onMount } from 'svelte';
  import DomainInput from './DomainInput.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import SummaryBar from './SummaryBar.svelte';
  import SecurityTxtCard from './SecurityTxtCard.svelte';
  import HeadersCard from './HeadersCard.svelte';
  import EmailSecurityCard from './EmailSecurityCard.svelte';
  import DnsSecurityCard from './DnsSecurityCard.svelte';
  import SslCard from './SslCard.svelte';
  import CtLogsCard from './CtLogsCard.svelte';
  import RedirectCard from './RedirectCard.svelte';
  import SeoCard from './SeoCard.svelte';
  import ReputationCard from './ReputationCard.svelte';
  import { fetchDomainCheck } from '../lib/domainCheckApi';
  import type { DomainCheckResult } from '../lib/types';

  let result: DomainCheckResult | null = null;
  let loading = false;
  let errorMessage = '';
  let domainInput: DomainInput;

  $: summaryChecks = result ? [
    { label: 'security.txt', status: result.securityTxt.status },
    { label: 'Headers', status: result.headers.status },
    { label: 'SPF', status: result.spf.status },
    { label: 'DMARC', status: result.dmarc.status },
    { label: 'DKIM', status: result.dkim.status },
    { label: 'DNSSEC', status: result.dnssec.status },
    { label: 'CAA', status: result.caa.status },
    { label: 'SSL/TLS', status: result.ssl.status },
    { label: 'Redirects', status: result.redirects.status },
    { label: 'Reputation', status: result.blacklist.status },
  ] : [];

  onMount(() => {
    document.title = 'Domain Security Checker — Headers, SPF, DMARC, DKIM, DNSSEC & security.txt';
    const meta = document.querySelector('meta[name="description"]');
    if (meta) meta.setAttribute('content', 'Free domain security checker. Analyze HTTP headers, SPF, DMARC, DKIM, DNSSEC, CAA, SSL/TLS, and security.txt compliance in one scan.');

    // Check for domain in hash query
    const hash = window.location.hash;
    const match = hash.match(/[?&]domain=([^&]+)/);
    if (match) {
      const domain = decodeURIComponent(match[1]);
      domainInput?.setDomain(domain);
      runCheck(domain);
    }
  });

  async function runCheck(domain: string) {
    result = null;
    errorMessage = '';
    loading = true;

    // Update URL
    window.location.hash = `#/?domain=${encodeURIComponent(domain)}`;

    try {
      result = await fetchDomainCheck(domain);
    } catch (err: any) {
      errorMessage = err.message || 'An unexpected error occurred. Please try again.';
    } finally {
      loading = false;
    }
  }

  function handleCheck(e: CustomEvent<{ domain: string }>) {
    runCheck(e.detail.domain);
  }
</script>

<div class="checker-page">
  <div class="hero">
    <h1 class="title">Domain Security Checker</h1>
    <p class="subtitle">Check headers, email auth, DNS security, SSL, and security.txt in one scan</p>
  </div>

  <DomainInput bind:this={domainInput} on:check={handleCheck} />

  {#if loading}
    <div class="loading-wrap">
      <LoadingSpinner />
      <p class="loading-text">Checking DNS records…</p>
    </div>
  {/if}

  {#if errorMessage}
    <div class="error-banner" role="alert">
      <p>{errorMessage}</p>
    </div>
  {/if}

  {#if result}
    <SummaryBar checks={summaryChecks} />

    <div class="results-stack">
      <SecurityTxtCard data={result.securityTxt} />
      <HeadersCard data={result.headers} />
      <EmailSecurityCard
        spf={result.spf}
        dmarc={result.dmarc}
        dkim={result.dkim}
        mx={result.mx}
      />
      <DnsSecurityCard
        dnssec={result.dnssec}
        caa={result.caa}
        ns={result.ns}
        domainExpiry={result.domainExpiry}
        danglingDns={result.danglingDns}
      />
      <SslCard data={result.ssl} />
      <CtLogsCard data={result.ctLogs} />
      <ReputationCard
        safeBrowsing={result.safeBrowsing}
        urlhaus={result.urlhaus}
        blacklist={result.blacklist}
      />
      <RedirectCard data={result.redirects} />
      <SeoCard data={result.seo} />
    </div>
  {/if}
</div>

<style>
  .checker-page {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .hero {
    text-align: center;
    margin-bottom: 0.5rem;
  }

  .title {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--color-text);
    letter-spacing: -0.02em;
  }

  .subtitle {
    color: var(--color-text-secondary);
    font-size: 0.875rem;
    margin-top: 0.35rem;
  }

  .loading-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.3rem;
  }

  .loading-text {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
  }

  .error-banner {
    background: rgba(255, 77, 106, 0.1);
    border: 1px solid var(--color-error);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    color: var(--color-error);
    font-size: 0.875rem;
  }

  .results-stack {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
</style>
