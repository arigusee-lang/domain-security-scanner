<script lang="ts">
  import type { SpfResult, DmarcResult, DkimResult, MxResult, CheckStatus } from '../lib/types';
  import ResultCard from './ResultCard.svelte';
  import CheckStatusIcon from './CheckStatusIcon.svelte';
  import CheckItem from './CheckItem.svelte';

  export let spf: SpfResult;
  export let dmarc: DmarcResult;
  export let dkim: DkimResult;
  export let mx: MxResult;

  let showDkimSelectors = false;

  function worst(...statuses: CheckStatus[]): CheckStatus {
    const order: Record<CheckStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
    return statuses.reduce((a, b) => order[a] <= order[b] ? a : b);
  }

  // Domain doesn't accept email — no MX records or RFC 7505 Null MX.
  // hasMail flag comes from server; fall back to record count for older payloads.
  $: noMail = mx.hasMail === false || mx.records.length === 0 || !!mx.nullMx;

  $: overall = noMail
    ? 'info' as CheckStatus
    : worst(spf.status, dmarc.status, dkim.status, mx.status);

  $: subtitle = noMail
    ? (mx.nullMx ? 'Domain rejects email (Null MX)' : 'Domain does not accept email')
    : [
        spf.record ? `SPF: ${spf.status}` : 'No SPF',
        dmarc.record ? `DMARC: ${dmarc.status}` : 'No DMARC',
        `DKIM: ${dkim.foundCount}/${dkim.totalChecked}`,
      ].join(' · ');
</script>

<ResultCard title="Email Security" status={overall} {subtitle}>
  {#if noMail}
    <div class="no-mail-banner" role="note">
      <strong>This domain does not appear to accept email.</strong>
      {#if mx.nullMx}
        It publishes a Null MX record (RFC 7505), which explicitly tells senders to reject any mail addressed here.
      {:else}
        No MX records were found, so no mail server is configured.
      {/if}
      SPF and DMARC are still useful for preventing spoofing of the domain in outbound mail.
    </div>
  {/if}

  <!-- SPF -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={spf.status} /> SPF</h4>
    {#if spf.record}
      <code class="raw-record">{spf.record}</code>
    {/if}
    {#if spf.error}
      <p class="error-text">{spf.error}</p>
    {/if}
    {#if spf.notice && !noMail}
      <p class="notice-text">{spf.notice}</p>
    {/if}
    {#if spf.validations.length > 0}
      <div class="items-stack">
        {#each spf.validations as v}
          <CheckItem status={v.status} title={v.check} detail={v.detail} ref={v.ref || ''} />
        {/each}
      </div>
    {/if}
    {#if spf.mechanisms.length > 0}
      <details class="mech-details">
        <summary>Mechanism breakdown ({spf.dnsLookupCount} DNS lookups)</summary>
        <div class="mech-list">
          {#each spf.mechanisms as m}
            <div class="mech-row"><code>{m.mechanism}</code> <span class="mech-desc">{m.description}</span></div>
          {/each}
        </div>
      </details>
    {/if}
  </section>

  <!-- DMARC -->
  <section class="sub-section">
    <h4 class="sub-title"><CheckStatusIcon status={dmarc.status} /> DMARC</h4>
    {#if dmarc.record}
      <code class="raw-record">{dmarc.record}</code>
    {/if}
    {#if dmarc.error}
      <p class="error-text">{dmarc.error}</p>
    {/if}
    {#if dmarc.notice && !noMail}
      <p class="notice-text">{dmarc.notice}</p>
    {/if}
    {#if dmarc.validations.length > 0}
      <div class="items-stack">
        {#each dmarc.validations as v}
          <CheckItem status={v.status} title={v.check} detail={v.detail} ref={v.ref || ''} />
        {/each}
      </div>
    {/if}

    {#if dmarc.ruaUris && dmarc.ruaUris.length > 0}
      <div class="uri-list">
        <span class="uri-label">rua</span>
        {#each dmarc.ruaUris as u}
          <span class="uri-chip" class:external={u.external} class:unauth={u.external && u.authorized === false} title={u.external && u.authorized === false ? `External destination ${u.domain} did not publish ${dmarc.record ? '<from-domain>' : ''}._report._dmarc.${u.domain} — RFC 7489 §7.1` : (u.external ? 'External destination — authorization confirmed' : '')}>
            {u.email ?? u.uri}{#if u.external}<span class="ext-badge">{u.authorized === false ? '⚠ unauthorized' : 'external'}</span>{/if}
          </span>
        {/each}
      </div>
    {/if}
    {#if dmarc.rufUris && dmarc.rufUris.length > 0}
      <div class="uri-list">
        <span class="uri-label">ruf</span>
        {#each dmarc.rufUris as u}
          <span class="uri-chip" class:external={u.external} class:unauth={u.external && u.authorized === false} title={u.external && u.authorized === false ? `External destination ${u.domain} did not publish authorization record — RFC 7489 §7.1` : (u.external ? 'External destination — authorization confirmed' : '')}>
            {u.email ?? u.uri}{#if u.external}<span class="ext-badge">{u.authorized === false ? '⚠ unauthorized' : 'external'}</span>{/if}
          </span>
        {/each}
      </div>
    {/if}
    {#if dmarc.tags.length > 0}
      {@const hasIssues = dmarc.tags.some(t => t.status === 'fail' || t.status === 'warn')}
      <details class="mech-details" open={hasIssues}>
        <summary>Tag breakdown{hasIssues ? ' — issues detected' : ''}</summary>
        <div class="mech-list">
          {#each dmarc.tags as t}
            <div class="mech-row tag-row tag-{t.status ?? 'ok'}">
              <code class="tag-code">{t.tag}{t.value ? `=${t.value}` : ''}</code>
              <span class="mech-desc">{t.description}</span>
              {#if t.issue}
                <span class="tag-issue">— {t.issue}</span>
              {/if}
            </div>
          {/each}
        </div>
      </details>
    {/if}
  </section>

  <!-- DKIM -->
  {#if !noMail}
    <section class="sub-section">
      <h4 class="sub-title"><CheckStatusIcon status={dkim.status} /> DKIM</h4>
      <p class="dkim-summary">{dkim.foundCount} of {dkim.totalChecked} common selectors found</p>
      <button class="toggle-btn" on:click={() => showDkimSelectors = !showDkimSelectors}>
        {showDkimSelectors ? 'Hide' : 'Show'} selectors
      </button>
      {#if showDkimSelectors}
        <div class="selector-list">
          {#each dkim.selectors as s}
            <div class="selector-row">
              <span class="sel-dot" class:found={s.found} aria-hidden="true"></span>
              <code>{s.selector}</code>
              <span class="sel-service">{s.service}</span>
              <span class="sel-status">{s.found ? 'found' : '—'}</span>
            </div>
          {/each}
        </div>
      {/if}
      <p class="dkim-note">Partial check — common selectors only. Custom selectors may exist.
        <a class="ref-link" href="https://www.rfc-editor.org/rfc/rfc6376" target="_blank" rel="noopener noreferrer">RFC 6376 <svg class="ext-icon" width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M3.5 1H11V8.5M11 1L1 11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
      </p>
    </section>
  {/if}

  <!-- MX -->
  {#if !noMail}
    <section class="sub-section">
      <h4 class="sub-title"><CheckStatusIcon status={mx.status} /> MX Records</h4>
      {#if mx.nullMx}
        <p class="no-data">Null MX record present (priority 0, target <code>.</code>) — domain explicitly rejects incoming email per RFC 7505.</p>
      {:else if mx.records.length > 0}
        <div class="mx-table-wrap">
          <table class="mx-table">
            <thead><tr><th>Priority</th><th>Target</th></tr></thead>
            <tbody>
              {#each mx.records as r}
                <tr><td>{r.priority}</td><td>{r.exchange}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="no-data">No MX records found — domain likely does not receive email.</p>
      {/if}
    </section>
  {/if}
</ResultCard>

<style>
  .sub-section { padding: 0.7rem 0; border-bottom: 1px solid var(--color-border); }
  .sub-section:last-child { border-bottom: none; padding-bottom: 0; }
  .sub-title { display: flex; align-items: center; gap: 0.4rem; font-size: 0.9rem; font-weight: 600; color: var(--color-text); margin-bottom: 0.5rem; }
  .raw-record { display: block; background: var(--color-bg); border: 1px solid var(--color-border); border-left: 3px solid var(--color-accent); border-radius: var(--radius); padding: 0.4rem 0.6rem; font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text-secondary); word-break: break-all; margin-bottom: 0.5rem; }
  .error-text { color: var(--color-error); font-size: 0.8rem; }
  .items-stack { display: flex; flex-direction: column; gap: 0.4rem; margin-bottom: 0.4rem; }
  .mech-details { margin-top: 0.4rem; font-size: 0.8rem; }
  .mech-details summary { cursor: pointer; color: var(--color-accent); font-size: 0.8rem; }
  .mech-list { margin-top: 0.3rem; display: flex; flex-direction: column; gap: 0.2rem; }
  .mech-row { display: flex; align-items: baseline; gap: 0.5rem; font-size: 0.75rem; flex-wrap: wrap; }
  .mech-row code { background: var(--color-bg); padding: 0.05rem 0.3rem; border-radius: 3px; font-size: 0.75rem; color: var(--color-text); }
  .mech-desc { color: var(--color-text-secondary); }

  /* rua/ruf URI chips */
  .uri-list {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.35rem;
    margin: 0.4rem 0 0.2rem;
    font-size: 0.75rem;
  }
  .uri-label {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    text-transform: lowercase;
    color: var(--color-text-secondary);
    opacity: 0.7;
    margin-right: 0.15rem;
  }
  .uri-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
    background: var(--color-bg);
    border: 1px solid var(--color-border);
    font-family: var(--font-mono);
    font-size: 0.72rem;
    color: var(--color-text);
  }
  .uri-chip.external {
    border-color: rgba(91, 192, 222, 0.4);
    background: rgba(91, 192, 222, 0.06);
  }
  .uri-chip.unauth {
    border-color: rgba(255, 184, 77, 0.5);
    background: rgba(255, 184, 77, 0.1);
    color: var(--color-warning);
  }
  .ext-badge {
    font-size: 0.6rem;
    font-family: var(--font-family);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.05rem 0.35rem;
    border-radius: 999px;
    background: rgba(91, 192, 222, 0.18);
    color: var(--color-info);
    font-weight: 600;
  }
  .uri-chip.unauth .ext-badge {
    background: rgba(255, 184, 77, 0.2);
    color: var(--color-warning);
  }

  /* Tag-row syntax highlighting (DMARC tag breakdown) */
  .tag-row.tag-warn .tag-code {
    background: rgba(255, 184, 77, 0.12);
    border-left: 2px solid var(--color-warning);
    color: var(--color-warning);
  }
  .tag-row.tag-fail .tag-code {
    background: rgba(255, 77, 106, 0.12);
    border-left: 2px solid var(--color-error);
    color: var(--color-error);
  }
  .tag-issue {
    font-size: 0.7rem;
    color: var(--color-text-secondary);
    flex-basis: 100%;
    margin-left: 0.5rem;
  }
  .tag-row.tag-warn .tag-issue { color: var(--color-warning); opacity: 0.85; }
  .tag-row.tag-fail .tag-issue { color: var(--color-error); opacity: 0.85; }
  .dkim-summary { font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: 0.3rem; }
  .toggle-btn { background: none; border: 1px solid var(--color-border); border-radius: var(--radius); color: var(--color-accent); font-family: var(--font-family); font-size: 0.75rem; padding: 0.2rem 0.6rem; cursor: pointer; transition: background var(--transition); }
  .toggle-btn:hover { background: rgba(0, 212, 170, 0.08); }
  .selector-list { margin-top: 0.4rem; display: flex; flex-direction: column; gap: 0.2rem; }
  .selector-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.75rem; color: var(--color-text-secondary); }
  .sel-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-border); flex-shrink: 0; }
  .sel-dot.found { background: var(--color-valid); }
  .sel-service { color: var(--color-text-secondary); opacity: 0.7; }
  .sel-status { margin-left: auto; font-size: 0.7rem; }
  .dkim-note { font-size: 0.7rem; color: var(--color-text-secondary); opacity: 0.6; margin-top: 0.3rem; }
  .ref-link { display: inline-flex; align-items: center; gap: 0.15rem; color: var(--color-accent); text-decoration: none; opacity: 0.75; font-size: 0.7rem; }
  .ref-link:hover { opacity: 1; text-decoration: underline; }
  .ext-icon { flex-shrink: 0; }
  .mx-table-wrap { overflow-x: auto; }
  .mx-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .mx-table th { text-align: left; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--color-text-secondary); padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--color-border); }
  .mx-table td { padding: 0.35rem 0.5rem; color: var(--color-text-secondary); }
  .no-data { color: var(--color-text-secondary); font-size: 0.8rem; }
  .no-data code { background: var(--color-bg); padding: 0.05rem 0.3rem; border-radius: 3px; font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text); }
  .no-mail-banner {
    background: rgba(91, 192, 222, 0.08);
    border: 1px solid rgba(91, 192, 222, 0.3);
    border-left: 3px solid var(--color-info);
    border-radius: var(--radius);
    padding: 0.6rem 0.8rem;
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    line-height: 1.5;
    margin-bottom: 0.5rem;
  }
  .no-mail-banner strong { color: var(--color-text); display: block; margin-bottom: 0.2rem; }
  .notice-text {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    background: rgba(91, 192, 222, 0.06);
    border-left: 2px solid var(--color-info);
    padding: 0.3rem 0.5rem;
    margin: 0.3rem 0;
    border-radius: 3px;
    line-height: 1.5;
  }
</style>
