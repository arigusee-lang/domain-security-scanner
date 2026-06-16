<script lang="ts">
  import type { SafeBrowsingResult, UrlhausResult, BlacklistResult, InfrastructureResult, CheckStatus } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let safeBrowsing: SafeBrowsingResult;
  export let urlhaus: UrlhausResult;
  export let blacklist: BlacklistResult;
  export let infrastructure: InfrastructureResult | null | undefined = null;

  function worst(...statuses: CheckStatus[]): CheckStatus {
    const order: Record<CheckStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
    return statuses.reduce((a, b) => order[a] <= order[b] ? a : b);
  }

  // Legacy fallback: pre-Phase-A scans kept ip/cdnProvider on blacklist.
  $: hasIp = !!(infrastructure?.ip ?? (blacklist as any)?.ip);
  $: cdnProvider = infrastructure?.cdnProvider ?? (blacklist as any)?.cdnProvider ?? null;
  $: domainProviders = blacklist.providers.filter(p => p.type === 'domain');
  $: ipProviders = blacklist.providers.filter(p => p.type === 'ip');
  $: overall = worst(safeBrowsing.status, urlhaus.status, blacklist.status);

  const THREAT_LABELS: Record<string, string> = {
    MALWARE: "Malware",
    SOCIAL_ENGINEERING: "Phishing / Social Engineering",
    UNWANTED_SOFTWARE: "Unwanted Software",
    POTENTIALLY_HARMFUL_APPLICATION: "Potentially Harmful",
  };

  const PROVIDER_URLS: Record<string, string> = {
    "Spamhaus ZEN": "https://www.spamhaus.org/zen/",
    "Barracuda": "https://www.barracudacentral.org/lookups",
    "SpamCop": "https://www.spamcop.net/",
    "SORBS": "http://www.sorbs.net/",
    "UCEPROTECT L1": "https://www.uceprotect.net/en/",
    "Spamhaus DBL": "https://www.spamhaus.org/dbl/",
    "SURBL": "https://surbl.org/",
  };
</script>

<ResultCard title="Domain Reputation" status={overall}>
  <!-- Safe Browsing -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={safeBrowsing.status} /> <a class="ref-link" href="https://transparencyreport.google.com/safe-browsing/search" target="_blank" rel="noopener">Google Safe Browsing</a></h4>
    {#if safeBrowsing.error}
      <p class="note">{safeBrowsing.error}</p>
    {:else if safeBrowsing.safe === true}
      <p class="sub-detail">No threats detected</p>
    {:else if safeBrowsing.safe === false}
      <div class="threat-list">
        {#each safeBrowsing.threats as t}
          <span class="threat-tag">{THREAT_LABELS[t.threatType] || t.threatType}</span>
        {/each}
      </div>
    {/if}
  </section>

  <!-- URLhaus -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={urlhaus.status} /> <a class="ref-link" href="https://urlhaus.abuse.ch/" target="_blank" rel="noopener">URLhaus (abuse.ch)</a></h4>
    {#if urlhaus.error}
      <p class="note">{urlhaus.error}</p>
    {:else if urlhaus.listed}
      <p class="warn-text">Domain found in malware URL database ({urlhaus.urlCount} URL{urlhaus.urlCount !== 1 ? 's' : ''})</p>
    {:else}
      <p class="sub-detail">Not listed in malware URL database</p>
    {/if}
  </section>

  <!-- Blacklists -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={blacklist.status} /> <a class="ref-link" href="https://www.dnsbl.info/" target="_blank" rel="noopener">Blacklists (DNSBL)</a></h4>
    {#if blacklist.error}
      <p class="note">{blacklist.error}</p>
    {:else if hasIp}
      {#if domainProviders.length > 0}
        <p class="bl-section-label">Domain-based</p>
        <div class="bl-list">
          {#each domainProviders as p}
            <div class="bl-row">
              <span class="bl-dot" class:listed={p.listed} aria-hidden="true"></span>
              {#if PROVIDER_URLS[p.provider]}
                <a class="ref-link" href={PROVIDER_URLS[p.provider]} target="_blank" rel="noopener">{p.provider}</a>
              {:else}
                <span>{p.provider}</span>
              {/if}
              <span class="bl-status">{p.listed ? 'Listed' : 'Clear'}</span>
            </div>
          {/each}
        </div>
      {/if}

      {#if cdnProvider}
        <p class="bl-section-label">IP-based</p>
        <p class="note">Not applicable — {cdnProvider} edge IPs are shared across many domains, so per-IP DNSBL results don't reflect this domain specifically.</p>
      {:else if ipProviders.length > 0}
        <p class="bl-section-label">IP-based</p>
        <div class="bl-list">
          {#each ipProviders as p}
            <div class="bl-row">
              <span class="bl-dot" class:listed={p.listed} aria-hidden="true"></span>
              {#if PROVIDER_URLS[p.provider]}
                <a class="ref-link" href={PROVIDER_URLS[p.provider]} target="_blank" rel="noopener">{p.provider}</a>
              {:else}
                <span>{p.provider}</span>
              {/if}
              <span class="bl-status">{p.listed ? 'Listed' : 'Clear'}</span>
            </div>
          {/each}
        </div>
      {/if}
    {:else}
      <p class="note">Could not determine domain IP</p>
    {/if}
  </section>
</ResultCard>

<style>
  .sub-section { padding: 0.6rem 0; border-bottom: 1px solid var(--color-border); }
  .sub-section:last-child { border-bottom: none; padding-bottom: 0; }
  .sub-title {
    display: flex; align-items: center; gap: 0.4rem;
    font-size: 0.85rem; font-weight: 600; color: var(--color-text); margin-bottom: 0.3rem;
  }
  .sub-detail { font-size: 0.8rem; color: var(--color-text-secondary); }
  .note { font-size: 0.75rem; color: var(--color-text-secondary); opacity: 0.7; }
  .warn-text { font-size: 0.8rem; color: var(--color-warning); }
  .threat-list { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .threat-tag {
    display: inline-block; padding: 0.15rem 0.5rem; border-radius: 100px;
    font-size: 0.7rem; background: rgba(255, 77, 106, 0.12); color: var(--color-error);
    border: 1px solid rgba(255, 77, 106, 0.25);
  }
  .bl-list { display: flex; flex-direction: column; gap: 0.2rem; }
  .bl-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; color: var(--color-text-secondary); }
  .bl-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-valid); flex-shrink: 0; }
  .bl-dot.listed { background: var(--color-error); }
  .bl-status { margin-left: auto; font-size: 0.7rem; }
  .bl-section-label { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--color-text-secondary); margin: 0.5rem 0 0.2rem; }
  .ref-link { color: inherit; text-decoration: none; }
  .ref-link:hover { text-decoration: underline; color: var(--color-accent); }
</style>
