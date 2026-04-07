<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let config = {
    checks: {
      securityTxt: true, headers: true, spf: true, dmarc: true,
      dkim: true, dnssec: true, caa: true, mx: true, ns: true,
      ssl: true, domainExpiry: true, blacklist: true, ctLogs: true,
      redirects: true, seo: true, reputation: true, danglingDns: true,
    },
    noCache: false,
    crtShFirst: false,
  };

  const dispatch = createEventDispatcher();

  let open = false;

  const sections = [
    { label: 'DNS', keys: ['spf', 'dmarc', 'dkim', 'dnssec', 'caa', 'mx', 'ns', 'danglingDns'] },
    { label: 'Email', keys: [] as string[] },
    { label: 'Web', keys: ['ssl', 'headers', 'securityTxt', 'redirects', 'seo'] },
    { label: 'Reputation', keys: ['blacklist', 'reputation', 'ctLogs', 'domainExpiry'] },
  ];

  const checkLabels: Record<string, string> = {
    securityTxt: 'security.txt', headers: 'Security Headers', spf: 'SPF',
    dmarc: 'DMARC', dkim: 'DKIM', dnssec: 'DNSSEC', caa: 'CAA',
    mx: 'MX Records', ns: 'Nameservers', ssl: 'SSL/TLS',
    domainExpiry: 'Domain Expiry', blacklist: 'Blacklist', ctLogs: 'CT Logs',
    redirects: 'Redirects/HTTPS', seo: 'SEO Basics', reputation: 'Safe Browsing & URLhaus',
    danglingDns: 'Dangling DNS',
  };

  function togglePanel() {
    open = !open;
  }

  function handleChange() {
    dispatch('change', config);
  }

  function resetDefaults() {
    const keys = Object.keys(config.checks) as (keyof typeof config.checks)[];
    keys.forEach(k => (config.checks[k] = true));
    config.noCache = false;
    config.crtShFirst = false;
    config = config;
    handleChange();
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') open = false;
  }
</script>

<div class="config-panel-wrap" on:keydown={handleKeydown}>
  <button
    class="gear-btn"
    on:click={togglePanel}
    aria-label="Scan configuration"
    aria-expanded={open}
    title="Configure checks"
  >
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  </button>

  {#if open}
    <div class="panel" role="dialog" aria-label="Scan configuration">
      <div class="panel-header">
        <span class="panel-title">Check Configuration</span>
        <button class="reset-btn" on:click={resetDefaults}>Reset to defaults</button>
      </div>

      {#each sections as section}
        {#if section.keys.length > 0}
          <div class="section">
            <span class="section-label">{section.label}</span>
            <div class="checks-grid">
              {#each section.keys as key}
                <label class="check-label">
                  <input
                    type="checkbox"
                    bind:checked={config.checks[key]}
                    on:change={handleChange}
                  />
                  <span>{checkLabels[key] || key}</span>
                </label>
              {/each}
            </div>
          </div>
        {/if}
      {/each}

      <div class="section">
        <label class="check-label no-cache-label">
          <input type="checkbox" bind:checked={config.noCache} on:change={handleChange} />
          <span>Skip cache (fresh scan)</span>
        </label>
        {#if import.meta.env.DEV}
          <label class="check-label">
            <input type="checkbox" bind:checked={config.crtShFirst} on:change={handleChange} />
            <span>Use crt.sh first (dev)</span>
          </label>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .config-panel-wrap {
    position: relative;
    display: inline-flex;
  }

  .gear-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    color: var(--color-text-secondary);
    padding: 0.5rem;
    cursor: pointer;
    transition: color var(--transition), border-color var(--transition);
  }

  .gear-btn:hover {
    color: var(--color-accent);
    border-color: var(--color-accent);
  }

  .panel {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.75rem;
    min-width: 260px;
    z-index: 50;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.6rem;
    padding-bottom: 0.4rem;
    border-bottom: 1px solid var(--color-border);
  }

  .panel-title {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--color-text);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .reset-btn {
    font-size: 0.65rem;
    color: var(--color-accent);
    background: none;
    border: none;
    cursor: pointer;
    font-family: var(--font-family);
  }

  .reset-btn:hover {
    text-decoration: underline;
  }

  .section {
    margin-bottom: 0.5rem;
  }

  .section-label {
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--color-text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    display: block;
    margin-bottom: 0.3rem;
  }

  .checks-grid {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .check-label {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.75rem;
    color: var(--color-text);
    cursor: pointer;
  }

  .check-label input {
    accent-color: var(--color-accent);
    cursor: pointer;
  }

  .no-cache-label {
    padding-top: 0.3rem;
    border-top: 1px solid var(--color-border);
  }
</style>
