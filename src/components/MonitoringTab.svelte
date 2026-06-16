<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { currentUser } from '../lib/authStore';
  import {
    getMonitoringDomains, addMonitoringDomain, removeMonitoringDomain,
    getMonitoringAlerts, updateMonitoringDomainSettings, getMonitoringDomainStatus
  } from '../lib/api';

  let user: import('../lib/authStore').AuthUser | null = null;
  const unsubUser = currentUser.subscribe(v => { user = v; });
  onDestroy(() => unsubUser());

  let domains: any[] = [];
  let limits = { max: 0, used: 0 };
  let loading = true;

  // Add form
  let showAddForm = false;
  let newDomain = '';
  let addError = '';
  let addingDomain = false;
  const MONS = [
    { id: 'ssl', label: 'SSL & Certificates', desc: 'Expiry, issuer change, CT policy, CT logs (new certs, unknown CA)' },
    { id: 'domain_expiry', label: 'Domain Expiry', desc: 'Registration expiry via RDAP' },
    { id: 'security_txt_expiry', label: 'security.txt', desc: 'Expires field, file availability' },
    { id: 'blacklist', label: 'Blacklist', desc: 'Domain-based DNSBL (Spamhaus, SURBL)' },
    { id: 'caa_dnssec', label: 'CAA / DNSSEC', desc: 'CAA record changes, DNSSEC toggle' },
    { id: 'headers', label: 'Security Headers', desc: 'HSTS, CSP, X-Content-Type-Options disappearance' },
  ];
  const FREE_IDS: string[] = [];
  let selMon: Record<string, boolean> = {};
  let addEmail = true;
  let addSev = 'warn';

  function resetAdd() {
    newDomain = ''; addError = '';
    selMon = {};
    for (const m of MONS) selMon[m.id] = true;
    addEmail = true; addSev = 'warn';
  }

  // Settings popup
  let popupDomain: any = null;
  let popEmail = true;
  let popSev = 'warn';
  let popMons: Record<string, boolean> = {};
  let popLoading = false;

  // Drill-down
  let selDomain: any = null;
  let dAlerts: any[] = [];
  let dTotal = 0;
  let dPage = 1;

  async function loadDomains() {
    try { const r = await getMonitoringDomains(); domains = r.domains; limits = r.limits; } catch { domains = []; }
  }

  async function handleAdd() {
    if (!newDomain.trim()) return;
    addError = ''; addingDomain = true;
    try {
      const types = Object.entries(selMon).filter(([,v]) => v).map(([k]) => k);
      if (types.length === 0) { addError = 'Select at least one monitor'; addingDomain = false; return; }
      await addMonitoringDomain(newDomain.trim(), { monitorTypes: types, emailEnabled: addEmail, minSeverity: addSev });
      showAddForm = false; resetAdd(); await loadDomains();
    } catch (e: any) { addError = e?.message || 'Failed'; }
    addingDomain = false;
  }

  async function handleRemove(id: string, e: MouseEvent) {
    e.stopPropagation();
    try { await removeMonitoringDomain(id); if (selDomain?.id === id) selDomain = null; await loadDomains(); } catch {}
  }

  async function openSettings(d: any, e: MouseEvent) {
    e.stopPropagation();
    popupDomain = d; popLoading = true;
    popEmail = d.emailEnabled !== false;
    popSev = d.minSeverity || 'warn';
    popMons = {};
    try {
      const status = await getMonitoringDomainStatus(d.id);
      for (const m of MONS) popMons[m.id] = false;
      for (const m of status.monitors) {
        // Map internal ssl_expiry/ct_logs to UI 'ssl' group
        if (m.type === 'ssl_expiry' || m.type === 'ct_logs') {
          if (m.enabled) popMons['ssl'] = true;
        } else {
          popMons[m.type] = m.enabled;
        }
      }
    } catch {
      for (const m of MONS) popMons[m.id] = true;
    }
    popLoading = false;
  }

  async function saveSettings() {
    if (!popupDomain) return;
    const raw = Object.entries(popMons).filter(([,v]) => v).map(([k]) => k);
    // Expand 'ssl' to internal types
    const enabled: string[] = [];
    for (const t of raw) {
      if (t === 'ssl') { enabled.push('ssl_expiry', 'ct_logs'); }
      else { enabled.push(t); }
    }
    try { await updateMonitoringDomainSettings(popupDomain.id, { emailEnabled: popEmail, minSeverity: popSev, enabledMonitors: enabled }); await loadDomains(); } catch {}
    popupDomain = null;
  }

  async function selectRow(d: any) {
    if (selDomain?.id === d.id) { selDomain = null; return; }
    selDomain = d; dPage = 1; await loadAlerts(d.domain);
  }

  async function loadAlerts(domain: string) {
    try { const r = await getMonitoringAlerts({ page: dPage, limit: 10, domain }); dAlerts = r.alerts; dTotal = r.pagination.total; } catch { dAlerts = []; dTotal = 0; }
  }

  function fmt(d: string | null): string { if (!d) return '—'; return new Date(d).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
  function sc(s: string | null): string { return s === 'critical' ? 'st-c' : s === 'warn' ? 'st-w' : s === 'pass' ? 'st-p' : 'st-n'; }
  function ac(s: string): string { return s === 'critical' ? 'a-c' : s === 'warn' ? 'a-w' : s === 'resolved' ? 'a-r' : 'a-i'; }
  $: free = user?.plan === 'free';
  $: aPages = Math.max(1, Math.ceil(dTotal / 10));

  onMount(async () => { resetAdd(); await loadDomains(); loading = false; });
</script>

{#if loading}<p class="ld">Loading…</p>
{:else}
<div class="mt">
  <div class="top">
    <span class="lim">{limits.used} / {limits.max} domains</span>
    <button class="abtn" on:click={() => { showAddForm = !showAddForm; if (showAddForm) resetAdd(); }}>{showAddForm ? 'Cancel' : '+ Add'}</button>
  </div>

  {#if showAddForm}
  <div class="addp">
    <input type="text" placeholder="example.com" bind:value={newDomain} class="inp" />
    <div class="mg">{#each MONS as m}<label class="mc"><input type="checkbox" bind:checked={selMon[m.id]} /><span class="ml">{m.label}<span class="md">{m.desc}</span></span></label>{/each}</div>
    <div class="nr"><label><input type="checkbox" bind:checked={addEmail} /> Email</label><label>Severity: <select bind:value={addSev}><option value="info">Info</option><option value="warn">Warn</option><option value="critical">Critical</option></select></label></div>
    {#if addError}<p class="err">{addError}</p>{/if}
    <button class="sbtn" on:click={handleAdd} disabled={addingDomain || !newDomain.trim()}>{addingDomain ? 'Adding…' : 'Start Monitoring'}</button>
  </div>
  {/if}

  <details class="ib">
    <summary class="it">What do we monitor?</summary>
    <div class="ig">
      <div class="ii"><span class="in">SSL & Certificates</span><span class="id">Expiry alerts (30/14/7/1 days), issuer changes, CT policy compliance (Chrome/Apple), CT log monitoring for unauthorized certs</span></div>
      <div class="ii"><span class="in">Domain Expiry</span><span class="id">Registration expiry via RDAP (90/30/7 days)</span></div>
      <div class="ii"><span class="in">security.txt</span><span class="id">Expires field (30/7 days), file availability</span></div>
      <div class="ii"><span class="in">Blacklist</span><span class="id">Domain-based DNSBL (Spamhaus DBL, SURBL) — listing/delisting</span></div>
      <div class="ii"><span class="in">CAA / DNSSEC</span><span class="id">CAA record changes/removal, DNSSEC toggle</span></div>
      <div class="ii"><span class="in">Security Headers</span><span class="id">HSTS/CSP disappearance (critical), other headers (warn)</span></div>
    </div>
  </details>

  <div class="tw"><table class="tbl">
    <thead><tr><th>Domain</th><th>Monitors</th><th>Alerts</th><th>Last Check</th><th>Status</th><th></th></tr></thead>
    <tbody>
      {#each domains as d (d.id)}
        <tr class="row" class:sel={selDomain?.id === d.id} on:click={() => selectRow(d)}>
          <td class="dn">{d.domain}</td><td>{d.monitorsCount}</td><td>{d.activeAlertsCount}</td><td>{fmt(d.lastCheckAt)}</td>
          <td><span class="sb {sc(d.overallStatus)}">{d.overallStatus ?? '…'}</span></td>
          <td class="acts"><button class="gear" on:click={(e) => openSettings(d, e)} title="Settings">⚙</button><button class="rm" on:click={(e) => handleRemove(d.id, e)} title="Remove">✕</button></td>
        </tr>
      {/each}
      {#if domains.length === 0}<tr><td colspan="6" class="em">No domains monitored yet.</td></tr>{/if}
    </tbody>
  </table></div>

  <!-- Drill-down panel -->
  {#if selDomain}
  <div class="drill">
    <div class="dh"><h4>{selDomain.domain} — Alerts</h4><button class="cls" on:click={() => selDomain = null}>✕</button></div>
    {#each dAlerts as a (a.id)}
      <div class="ar"><span class="as {ac(a.severity)}">{a.severity}</span><span class="atx">{a.title}</span><span class="ad">{fmt(a.created_at)}</span></div>
    {/each}
    {#if dAlerts.length === 0}<p class="em">No alerts for this domain.</p>{/if}
    {#if dTotal > 10}
    <div class="pg">
      <button disabled={dPage <= 1} on:click|stopPropagation={() => { dPage--; loadAlerts(selDomain.domain); }}>←</button>
      <span>{dPage}/{aPages}</span>
      <button disabled={dPage >= aPages} on:click|stopPropagation={() => { dPage++; loadAlerts(selDomain.domain); }}>→</button>
    </div>
    {/if}
  </div>
  {/if}

  <!-- Settings popup -->
  {#if popupDomain}
  <div class="ov" on:click={() => popupDomain = null}></div>
  <div class="pop">
    <h4>Settings — {popupDomain.domain}</h4>
    {#if popLoading}<p class="ld">Loading…</p>
    {:else}
      <div class="psec"><span class="plbl">Monitors</span>
        <div class="mg">{#each MONS as m}<label class="mc"><input type="checkbox" bind:checked={popMons[m.id]} />{m.label}</label>{/each}</div>
      </div>
      <div class="psec"><span class="plbl">Notifications</span>
        <label class="pl"><input type="checkbox" bind:checked={popEmail} /> Email notifications</label>
        <label class="pl">Min severity: <select bind:value={popSev}><option value="info">Info</option><option value="warn">Warning</option><option value="critical">Critical</option></select></label>
      </div>
      <div class="pa"><button class="sbtn" on:click={saveSettings}>Save</button><button class="cbtn" on:click={() => popupDomain = null}>Cancel</button></div>
    {/if}
  </div>
  {/if}
</div>
{/if}

<style>
  .mt{display:flex;flex-direction:column;gap:.75rem}
  .top{display:flex;justify-content:space-between;align-items:center}
  .lim{font-size:.8rem;color:var(--color-text-secondary)}
  .abtn{padding:.3rem .6rem;font-size:.75rem;background:var(--color-accent);color:#fff;border:none;border-radius:var(--radius);cursor:pointer;font-family:var(--font-family)}
  .addp{background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius);padding:.6rem;display:flex;flex-direction:column;gap:.4rem}
  .inp{padding:.35rem .5rem;font-size:.78rem;background:var(--color-bg);border:1px solid var(--color-border);border-radius:var(--radius);color:var(--color-text);font-family:var(--font-family)}
  .mg{display:flex;flex-direction:column;gap:.35rem}
  .mc{display:flex;align-items:flex-start;gap:.2rem;font-size:.72rem;color:var(--color-text);cursor:pointer}
  .mc.dis{opacity:.45;cursor:default}
  .ml{display:flex;flex-direction:column;line-height:1.3}
  .md{font-size:.6rem;color:var(--color-text-secondary);font-weight:normal}
  .pro{font-size:.55rem;background:var(--color-accent);color:#fff;padding:.02rem .2rem;border-radius:999px;margin-left:.15rem}
  .nr{display:flex;gap:.8rem;align-items:center;font-size:.72rem;color:var(--color-text)}
  .nr select{padding:.15rem .3rem;font-size:.72rem;background:var(--color-bg);border:1px solid var(--color-border);border-radius:var(--radius);color:var(--color-text);font-family:var(--font-family)}
  .err{color:#ef4444;font-size:.72rem;margin:0}
  .sbtn{padding:.3rem .6rem;font-size:.75rem;background:var(--color-accent);color:#fff;border:none;border-radius:var(--radius);cursor:pointer;font-family:var(--font-family)}
  .sbtn:disabled{opacity:.5}
  .cbtn{padding:.3rem .6rem;font-size:.75rem;background:var(--color-surface);color:var(--color-text);border:1px solid var(--color-border);border-radius:var(--radius);cursor:pointer;font-family:var(--font-family)}
  .tw{overflow-x:auto}
  .tbl{width:100%;border-collapse:collapse;font-size:.75rem}
  .tbl th{text-align:left;padding:.35rem .4rem;color:var(--color-text-secondary);border-bottom:1px solid var(--color-border);font-weight:600;font-size:.7rem}
  .tbl td{padding:.35rem .4rem;border-bottom:1px solid var(--color-border);color:var(--color-text)}
  .row{cursor:pointer;transition:background .1s}
  .row:hover{background:rgba(255,255,255,.03)}
  .row.sel{background:rgba(255,255,255,.03)}
  .dn{font-family:var(--font-mono);font-size:.75rem}
  .sb{font-size:.65rem;padding:.15rem .4rem;border-radius:3px;font-weight:600;text-transform:uppercase}
  .st-p{background:rgba(0,212,170,.1);color:var(--color-valid)}.st-w{background:rgba(255,184,77,.1);color:var(--color-warning)}.st-c{background:rgba(255,77,106,.1);color:var(--color-error)}.st-n{background:rgba(255,255,255,.05);color:var(--color-text-secondary)}
  .acts{display:flex;gap:.3rem;align-items:center}
  .gear,.rm{background:none;border:none;color:var(--color-text-secondary);cursor:pointer;font-size:.85rem;padding:.1rem}
  .gear:hover{color:var(--color-text)}.rm:hover{color:#ef4444}
  .drill{background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius);padding:.6rem}
  .dh{display:flex;justify-content:space-between;align-items:center;margin-bottom:.4rem}
  .dh h4{font-size:.82rem;font-weight:600;color:var(--color-text);margin:0}
  .cls{background:none;border:none;color:var(--color-text-secondary);cursor:pointer;font-size:.9rem}
  .ar{display:flex;align-items:center;gap:.35rem;padding:.2rem 0;font-size:.7rem;border-bottom:1px solid var(--color-border)}
  .as{font-size:.55rem;padding:.05rem .25rem;border-radius:999px;font-weight:600;text-transform:uppercase;white-space:nowrap}
  .a-c{background:#fee2e2;color:#991b1b}.a-w{background:#fef9c3;color:#854d0e}.a-i{background:#dbeafe;color:#1e40af}.a-r{background:#dcfce7;color:#166534}
  .atx{flex:1;color:var(--color-text)}.ad{color:var(--color-text-secondary);white-space:nowrap;font-size:.65rem}
  .pg{display:flex;align-items:center;justify-content:center;gap:.4rem;font-size:.7rem;color:var(--color-text-secondary);padding:.2rem 0}
  .pg button{padding:.15rem .35rem;font-size:.65rem;background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius);color:var(--color-text);cursor:pointer}
  .pg button:disabled{opacity:.4}
  .ov{position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:100}
  .pop{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius-lg);padding:1rem;z-index:101;min-width:320px;display:flex;flex-direction:column;gap:.6rem}
  .pop h4{font-size:.85rem;font-weight:600;color:var(--color-text);margin:0}
  .psec{display:flex;flex-direction:column;gap:.3rem}
  .plbl{font-size:.72rem;font-weight:600;color:var(--color-text-secondary);text-transform:uppercase;letter-spacing:.03em}
  .pl{display:flex;align-items:center;gap:.4rem;font-size:.78rem;color:var(--color-text)}
  .pl select{padding:.2rem .4rem;font-size:.75rem;background:var(--color-bg);border:1px solid var(--color-border);border-radius:var(--radius);color:var(--color-text);font-family:var(--font-family)}
  .pa{display:flex;gap:.4rem;margin-top:.3rem}
  .ld,.em{text-align:center;color:var(--color-text-secondary);font-size:.78rem;padding:.75rem 0}
  .ib{background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius);margin-bottom:.25rem}
  .it{padding:.4rem .6rem;font-size:.75rem;font-weight:600;color:var(--color-text-secondary);cursor:pointer;list-style:none}
  .it::-webkit-details-marker{display:none}
  .it::before{content:'▸ ';font-size:.7rem}
  details[open] .it::before{content:'▾ '}
  .ig{display:grid;grid-template-columns:1fr 1fr;gap:.3rem .6rem;padding:0 .6rem .5rem}
  .ii{display:flex;flex-direction:column;gap:.05rem}
  .in{font-size:.7rem;font-weight:600;color:var(--color-text)}
  .id{font-size:.62rem;color:var(--color-text-secondary);line-height:1.3}
</style>
