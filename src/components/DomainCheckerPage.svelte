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
  import { runAllChecks } from '../lib/domainCheckApi';

  let dns: any = null;
  let web: any = null;
  let expiry: any = null;
  let ct: any = null;
  let redirects: any = null;
  let seo: any = null;
  let reputation: any = null;

  let loading = false;
  let pendingCount = 0;
  let errorMessage = '';
  let domainInput: DomainInput;

  $: hasAny = dns || web || expiry || ct || redirects || seo || reputation;

  $: allDone = !loading;
  $: coreLoaded = !!(dns && web);

  $: summaryChecks = [
    ...(web?.securityTxt ? [{ label: 'security.txt', status: web.securityTxt.status }] : []),
    ...(web?.headers?.items?.length ? [{ label: 'Headers', status: web.headers.status }] : []),
    ...(dns?.spf ? [{ label: 'SPF', status: dns.spf.status }] : []),
    ...(dns?.dmarc ? [{ label: 'DMARC', status: dns.dmarc.status }] : []),
    ...(dns?.dnssec ? [{ label: 'DNSSEC', status: dns.dnssec.status }] : []),
    ...(web?.ssl ? [{ label: 'SSL/TLS', status: web.ssl.status }] : []),
    ...(redirects ? [{ label: 'Redirects', status: redirects.status }] : []),
    ...(dns?.blacklist ? [{ label: 'Blacklist', status: dns.blacklist.status }] : []),
  ];

  // Track which groups failed
  let failedGroups: string[] = [];

  onMount(() => {
    document.title = 'Domain Security Checker — Headers, SPF, DMARC, DKIM, DNSSEC & security.txt';
    const meta = document.querySelector('meta[name="description"]');
    if (meta) meta.setAttribute('content', 'Free domain security checker.');
    const hash = window.location.hash;
    const match = hash.match(/[?&]domain=([^&]+)/);
    if (match) {
      const d = decodeURIComponent(match[1]);
      domainInput?.setDomain(d);
      runCheck(d, false);
    }
  });

  // Track errors per group
  let groupErrors: Record<string, string> = {};

  const GROUP_LABELS: Record<string, string> = {
    dns: 'Email & DNS checks (SPF, DMARC, DKIM, DNSSEC, CAA, MX, NS, Blacklist)',
    web: 'Web checks (security.txt, headers, SSL/TLS)',
    expiry: 'Domain expiration (RDAP)',
    ct: 'Certificate Transparency (crt.sh)',
    redirects: 'HTTPS & Redirects',
    seo: 'SEO Basics',
    reputation: 'Domain Reputation',
  };

  async function runCheck(domain: string, noCache: boolean) {
    dns = web = expiry = ct = redirects = seo = reputation = null;
    groupErrors = {};
    failedGroups = [];
    errorMessage = '';
    loading = true;
    pendingCount = 7;
    window.location.hash = `#/?domain=${encodeURIComponent(domain)}`;

    await runAllChecks(domain, noCache,
      (key, data) => {
        if (key === 'dns') dns = data;
        else if (key === 'web') web = data;
        else if (key === 'expiry') expiry = data;
        else if (key === 'ct') ct = data;
        else if (key === 'redirects') redirects = data;
        else if (key === 'seo') seo = data;
        else if (key === 'reputation') reputation = data;
        pendingCount--;
        if (pendingCount <= 0) loading = false;
      },
      (key, err) => {
        const msg = err?.message || 'Request timed out';
        groupErrors[key] = msg;
        groupErrors = groupErrors; // trigger reactivity
        failedGroups = [...failedGroups, key];
        pendingCount--;
        if (pendingCount <= 0) loading = false;
      }
    );
  }

  function handleCheck(e: CustomEvent<{ domain: string; noCache: boolean }>) {
    runCheck(e.detail.domain, e.detail.noCache);
  }
</script>

<div class="checker-page">
  <div class="hero">
    <h1 class="title">Domain Security Checker</h1>
    <p class="subtitle">Comprehensive security audit for any domain — free, instant, no signup</p>
    <div class="check-tags">
      <span class="tag">SPF</span>
      <span class="tag">DMARC</span>
      <span class="tag">DKIM</span>
      <span class="tag">DNSSEC</span>
      <span class="tag">SSL/TLS</span>
      <span class="tag">Headers</span>
      <span class="tag">CAA</span>
      <span class="tag">Blacklist</span>
      <span class="tag">HTTPS</span>
      <span class="tag">SEO</span>
      <span class="tag">security.txt</span>
    </div>
  </div>

  <DomainInput bind:this={domainInput} on:check={handleCheck} />

  {#if loading && !hasAny}
    <div class="loading-wrap">
      <LoadingSpinner />
      <p class="loading-text">Running checks…</p>
    </div>
  {/if}

  {#if errorMessage && !hasAny}
    <div class="error-banner" role="alert"><p>{errorMessage}</p></div>
  {/if}

  {#if hasAny}
    {#if !loading && coreLoaded && summaryChecks.length > 0}
      <SummaryBar checks={summaryChecks} />
    {/if}

    <div class="results-stack">
      {#if web}
        <SecurityTxtCard data={web.securityTxt} />
        <HeadersCard data={web.headers} />
        <SslCard data={web.ssl} />
      {:else if groupErrors.web}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.web}</span>
            <p class="error-card-detail">{groupErrors.web}</p>
          </div>
        </div>
      {:else if loading}
        <div class="section-loading"><span class="dot-pulse"></span> Checking security.txt, headers, SSL…</div>
      {/if}

      {#if dns}
        <EmailSecurityCard spf={dns.spf} dmarc={dns.dmarc} dkim={dns.dkim} mx={dns.mx} />
        <DnsSecurityCard dnssec={dns.dnssec} caa={dns.caa} ns={dns.ns}
          domainExpiry={expiry || { status: 'info', expirationDate: null, daysRemaining: null, error: groupErrors.expiry || (loading ? 'Loading…' : 'Check failed') }}
          danglingDns={dns.danglingDns} />
      {:else if groupErrors.dns}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.dns}</span>
            <p class="error-card-detail">{groupErrors.dns}</p>
          </div>
        </div>
      {:else if loading}
        <div class="section-loading"><span class="dot-pulse"></span> Checking DNS records…</div>
      {/if}

      {#if ct}
        <CtLogsCard data={ct} />
      {:else if groupErrors.ct}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.ct}</span>
            <p class="error-card-detail">{groupErrors.ct}</p>
          </div>
        </div>
      {/if}

      {#if reputation || dns?.blacklist}
        <ReputationCard
          safeBrowsing={reputation?.safeBrowsing || { status: 'info', safe: null, threats: [], error: groupErrors.reputation || '' }}
          urlhaus={reputation?.urlhaus || { status: 'info', listed: false, urlCount: 0, error: groupErrors.reputation || '' }}
          blacklist={dns?.blacklist || { status: 'info', ip: null, providers: [] }}
        />
      {:else if groupErrors.reputation && !dns?.blacklist}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.reputation}</span>
            <p class="error-card-detail">{groupErrors.reputation}</p>
          </div>
        </div>
      {/if}

      {#if redirects}
        <RedirectCard data={redirects} />
      {:else if groupErrors.redirects}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.redirects}</span>
            <p class="error-card-detail">{groupErrors.redirects}</p>
          </div>
        </div>
      {/if}

      {#if seo}
        <SeoCard data={seo} />
      {:else if groupErrors.seo}
        <div class="error-card">
          <span class="error-card-icon">✗</span>
          <div>
            <span class="error-card-title">{GROUP_LABELS.seo}</span>
            <p class="error-card-detail">{groupErrors.seo}</p>
          </div>
        </div>
      {/if}

      {#if loading && hasAny}
        <div class="section-loading"><span class="dot-pulse"></span> Still loading some checks…</div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .checker-page { display: flex; flex-direction: column; gap: 1rem; }
  .hero { text-align: center; margin-bottom: 0.5rem; }
  .title { font-size: 1.5rem; font-weight: 700; color: var(--color-text); letter-spacing: -0.02em; }
  .subtitle { color: var(--color-text-secondary); font-size: 0.875rem; margin-top: 0.35rem; }
  .check-tags { display: flex; flex-wrap: wrap; justify-content: center; gap: 0.35rem; margin-top: 0.6rem; }
  .tag {
    font-size: 0.65rem; font-weight: 500; letter-spacing: 0.03em;
    padding: 0.15rem 0.5rem; border-radius: 100px;
    border: 1px solid var(--color-border); color: var(--color-text-secondary);
    background: var(--color-surface);
  }
  .loading-wrap { display: flex; flex-direction: column; align-items: center; gap: 0.3rem; }
  .loading-text { font-size: 0.8rem; color: var(--color-text-secondary); }
  .error-banner { background: rgba(255, 77, 106, 0.1); border: 1px solid var(--color-error); border-radius: var(--radius); padding: 0.75rem 1rem; color: var(--color-error); font-size: 0.875rem; }
  .results-stack { display: flex; flex-direction: column; gap: 0.75rem; }
  .section-loading {
    display: flex; align-items: center; gap: 0.5rem; justify-content: center;
    padding: 0.75rem; font-size: 0.8rem; color: var(--color-text-secondary);
    background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-lg);
  }
  .error-card {
    display: flex; align-items: flex-start; gap: 0.6rem;
    padding: 0.75rem 1rem;
    background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-lg);
    border-left: 3px solid var(--color-error);
  }
  .error-card-icon { color: var(--color-error); font-size: 0.9rem; flex-shrink: 0; margin-top: 0.1rem; }
  .error-card-title { font-size: 0.85rem; font-weight: 600; color: var(--color-text); }
  .error-card-detail { font-size: 0.75rem; color: var(--color-text-secondary); margin-top: 0.15rem; }
  .dot-pulse {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: var(--color-accent); animation: pulse 1s ease-in-out infinite;
  }
  @keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
</style>
