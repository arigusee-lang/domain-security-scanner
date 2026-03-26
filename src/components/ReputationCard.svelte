<script lang="ts">
  import type { SafeBrowsingResult, UrlhausResult, BlacklistResult, CheckStatus } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckStatusIcon from './CheckStatusIcon.svelte';

  export let safeBrowsing: SafeBrowsingResult;
  export let urlhaus: UrlhausResult;
  export let blacklist: BlacklistResult;

  function worst(...statuses: CheckStatus[]): CheckStatus {
    const order: Record<CheckStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
    return statuses.reduce((a, b) => order[a] <= order[b] ? a : b);
  }

  $: overall = worst(safeBrowsing.status, urlhaus.status, blacklist.status);

  const THREAT_LABELS: Record<string, string> = {
    MALWARE: "Malware",
    SOCIAL_ENGINEERING: "Phishing / Social Engineering",
    UNWANTED_SOFTWARE: "Unwanted Software",
    POTENTIALLY_HARMFUL_APPLICATION: "Potentially Harmful",
  };
</script>

<ResultCard title="Domain Reputation" status={overall}>
  <!-- Safe Browsing -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={safeBrowsing.status} /> Google Safe Browsing</h4>
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
    <h4 class="sub-title"><CheckStatusIcon status={urlhaus.status} /> URLhaus (abuse.ch)</h4>
    {#if urlhaus.error}
      <p class="note">{urlhaus.error}</p>
    {:else if urlhaus.listed}
      <p class="warn-text">Domain found in malware URL database ({urlhaus.urlCount} URL{urlhaus.urlCount !== 1 ? 's' : ''})</p>
    {:else}
      <p class="sub-detail">Not listed in malware URL database</p>
    {/if}
  </section>

  <!-- Blacklist (moved from EmailSecurityCard) -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={blacklist.status} /> Blacklists (DNSBL)</h4>
    {#if blacklist.error}
      <p class="note">{blacklist.error}</p>
    {:else if blacklist.ip}
      <p class="bl-ip">IP: <code>{blacklist.ip}</code></p>
      <div class="bl-list">
        {#each blacklist.providers as p}
          <div class="bl-row">
            <span class="bl-dot" class:listed={p.listed} aria-hidden="true"></span>
            <span>{p.provider}</span>
            <span class="bl-status">{p.listed ? 'Listed' : 'Clear'}</span>
          </div>
        {/each}
      </div>
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
  .bl-ip { font-size: 0.8rem; color: var(--color-text-secondary); margin-bottom: 0.3rem; }
  .bl-ip code { background: var(--color-bg); padding: 0.05rem 0.3rem; border-radius: 3px; font-size: 0.75rem; }
  .bl-list { display: flex; flex-direction: column; gap: 0.2rem; }
  .bl-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; color: var(--color-text-secondary); }
  .bl-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-valid); flex-shrink: 0; }
  .bl-dot.listed { background: var(--color-error); }
  .bl-status { margin-left: auto; font-size: 0.7rem; }
</style>
