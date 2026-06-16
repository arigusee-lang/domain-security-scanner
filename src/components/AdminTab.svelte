<script lang="ts">
  import { onMount } from 'svelte';
  import { getAdminUsers, getAdminStats, updateUserPlan, getUserScans, getAuditLog, getUserNotifications, getAdminUserMonitoredDomains } from '../lib/api';

  interface UserItem {
    id: string; email: string; name: string | null; provider: string;
    plan: string; role: string; created_at: string; last_login_at: string | null;
  }

  let users: UserItem[] = [];
  let total = 0;
  let page = 1;
  let limit = 20;
  let search = '';
  let planFilter = '';
  let stats: { total: number; byPlan: { free: number; premium: number; premium_plus: number } } | null = null;
  let loading = true;

  // Drill-down state
  let selectedUser: UserItem | null = null;
  let drillTab: 'scans' | 'monitored' | 'notifications' = 'scans';
  let drillScans: any[] = [];
  let drillScansTotal = 0;
  let drillScansPage = 1;
  let drillNotifications: any[] = [];
  let drillNotifTotal = 0;
  let drillNotifPage = 1;
  let drillMonitoredDomains: any[] = [];
  let drillLoading = false;

  async function loadStats() {
    try { stats = await getAdminStats(); } catch { /* ignore */ }
  }

  async function loadUsers() {
    loading = true;
    try {
      const res = await getAdminUsers({ page, limit, search: search || undefined, plan: planFilter || undefined });
      users = res.users;
      total = res.total;
    } catch { users = []; total = 0; }
    loading = false;
  }

  async function handlePlanChange(userId: string, newPlan: string) {
    try {
      await updateUserPlan(userId, newPlan);
      await loadUsers();
      await loadStats();
    } catch { /* ignore */ }
  }

  async function selectUser(u: UserItem) {
    selectedUser = u;
    drillTab = 'scans';
    drillScansPage = 1;
    drillNotifPage = 1;
    await loadDrillScans();
  }

  function closeDetail() { selectedUser = null; }

  async function loadDrillScans() {
    if (!selectedUser) return;
    drillLoading = true;
    try {
      const res = await getUserScans(selectedUser.id, { page: drillScansPage, limit: 10 });
      drillScans = res.scans; drillScansTotal = res.total;
    } catch { drillScans = []; drillScansTotal = 0; }
    drillLoading = false;
  }

  async function loadDrillNotifications() {
    if (!selectedUser) return;
    drillLoading = true;
    try {
      const res = await getUserNotifications(selectedUser.id, { page: drillNotifPage, limit: 10 });
      drillNotifications = res.notifications; drillNotifTotal = res.total;
    } catch { drillNotifications = []; drillNotifTotal = 0; }
    drillLoading = false;
  }

  function switchDrillTab(tab: 'scans' | 'monitored' | 'notifications') {
    drillTab = tab;
    if (tab === 'scans') loadDrillScans();
    else if (tab === 'monitored') loadDrillMonitored();
    else if (tab === 'notifications') loadDrillNotifications();
  }

  async function loadDrillMonitored() {
    if (!selectedUser) return;
    drillLoading = true;
    try {
      const res = await getAdminUserMonitoredDomains(selectedUser.id);
      drillMonitoredDomains = res.domains;
    } catch { drillMonitoredDomains = []; }
    drillLoading = false;
  }

  let searchTimer: ReturnType<typeof setTimeout>;
  function onSearchInput() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { page = 1; loadUsers(); }, 300);
  }

  function onPlanFilterChange() { page = 1; loadUsers(); }

  $: totalPages = Math.max(1, Math.ceil(total / limit));

  function prevPage() { if (page > 1) { page--; loadUsers(); } }
  function nextPage() { if (page < totalPages) { page++; loadUsers(); } }

  function fmtDate(d: string | null): string {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  onMount(() => { loadStats(); loadUsers(); });
</script>

<div class="admin-tab">
  <!-- Stats -->
  {#if stats}
    <div class="stats-row">
      <div class="stat-card">
        <span class="stat-value">{stats.total}</span>
        <span class="stat-label">Total Users</span>
      </div>
      <div class="stat-card">
        <span class="stat-value">{stats.byPlan.free}</span>
        <span class="stat-label">Free</span>
      </div>
      <div class="stat-card">
        <span class="stat-value">{stats.byPlan.premium}</span>
        <span class="stat-label">Premium</span>
      </div>
      <div class="stat-card">
        <span class="stat-value">{stats.byPlan.premium_plus}</span>
        <span class="stat-label">Premium+</span>
      </div>
    </div>
  {/if}

  <!-- Filters -->
  <div class="filters">
    <input class="search-input" type="text" placeholder="Search by email or name…" bind:value={search} on:input={onSearchInput} />
    <select class="plan-select" bind:value={planFilter} on:change={onPlanFilterChange}>
      <option value="">All plans</option>
      <option value="free">Free</option>
      <option value="premium">Premium</option>
      <option value="premium_plus">Premium+</option>
    </select>
  </div>

  <!-- Users table -->
  {#if loading}
    <p class="loading-msg">Loading…</p>
  {:else}
    <div class="table-wrap">
      <table class="users-table">
        <thead>
          <tr>
            <th>Email</th><th>Name</th><th>Provider</th><th>Plan</th><th>Registered</th><th>Last Login</th>
          </tr>
        </thead>
        <tbody>
          {#each users as u (u.id)}
            <tr class="user-row" class:selected={selectedUser?.id === u.id} on:click={() => selectUser(u)}>
              <td>{u.email}</td>
              <td>{u.name || '—'}</td>
              <td class="provider-cell">{u.provider}</td>
              <td>
                <select
                  class="plan-dropdown"
                  value={u.plan}
                  on:click|stopPropagation
                  on:change={(e) => handlePlanChange(u.id, e.currentTarget.value)}
                >
                  <option value="free">free</option>
                  <option value="premium">premium</option>
                  <option value="premium_plus">premium_plus</option>
                </select>
              </td>
              <td>{fmtDate(u.created_at)}</td>
              <td>{fmtDate(u.last_login_at)}</td>
            </tr>
          {/each}
          {#if users.length === 0}
            <tr><td colspan="6" class="empty-msg">No users found</td></tr>
          {/if}
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    <div class="pagination">
      <button disabled={page <= 1} on:click={prevPage}>← Prev</button>
      <span>Page {page} of {totalPages} ({total} users)</span>
      <button disabled={page >= totalPages} on:click={nextPage}>Next →</button>
    </div>
  {/if}

  <!-- Drill-down panel -->
  {#if selectedUser}
    <div class="drill-panel">
      <div class="drill-header">
        <h3>{selectedUser.email}</h3>
        <button class="close-btn" on:click={closeDetail}>✕</button>
      </div>
      <div class="drill-tabs">
        <button class:active={drillTab === 'scans'} on:click={() => switchDrillTab('scans')}>Scan History</button>
        <button class:active={drillTab === 'monitored'} on:click={() => switchDrillTab('monitored')}>Monitored Domains</button>
        <button class:active={drillTab === 'notifications'} on:click={() => switchDrillTab('notifications')}>Notifications</button>
      </div>

      {#if drillLoading}
        <p class="loading-msg">Loading…</p>
      {:else if drillTab === 'scans'}
        <table class="drill-table">
          <thead><tr><th>Domain</th><th>Date</th><th>Score</th><th>Report</th></tr></thead>
          <tbody>
            {#each drillScans as s (s.id)}
              <tr>
                <td class="domain-cell">{s.domain}</td>
                <td>{fmtDate(s.created_at)}</td>
                <td>{s.score != null ? Math.round(s.score) : '—'}</td>
                <td><a class="view-link" href="/#/?domain={encodeURIComponent(s.domain)}&scanId={s.id}&view=history">View</a></td>
              </tr>
            {/each}
            {#if drillScans.length === 0}<tr><td colspan="4" class="empty-msg">No scans</td></tr>{/if}
          </tbody>
        </table>
        <div class="pagination">
          <button disabled={drillScansPage <= 1} on:click={() => { drillScansPage--; loadDrillScans(); }}>← Prev</button>
          <span>Page {drillScansPage} of {Math.max(1, Math.ceil(drillScansTotal / 10))}</span>
          <button disabled={drillScansPage >= Math.ceil(drillScansTotal / 10)} on:click={() => { drillScansPage++; loadDrillScans(); }}>Next →</button>
        </div>
      {:else if drillTab === 'monitored'}
        <table class="drill-table">
          <thead><tr><th>Domain</th><th>Monitors</th><th>Alerts (24h)</th><th>Added</th></tr></thead>
          <tbody>
            {#each drillMonitoredDomains as d (d.id)}
              <tr>
                <td class="domain-cell">{d.domain}</td>
                <td>{d.monitors_count}</td>
                <td>{d.alerts_count}</td>
                <td>{fmtDate(d.created_at)}</td>
              </tr>
            {/each}
            {#if drillMonitoredDomains.length === 0}<tr><td colspan="4" class="empty-msg">No monitored domains</td></tr>{/if}
          </tbody>
        </table>
      {:else if drillTab === 'notifications'}
        <table class="drill-table">
          <thead><tr><th>Type</th><th>Status</th><th>Domain</th><th>Error</th><th>Created</th><th>Sent</th></tr></thead>
          <tbody>
            {#each drillNotifications as n (n.id)}
              <tr><td>{n.type}</td><td>{n.status}</td><td>{n.domain || '—'}</td><td>{n.error || '—'}</td><td>{fmtDate(n.created_at)}</td><td>{fmtDate(n.sent_at)}</td></tr>
            {/each}
            {#if drillNotifications.length === 0}<tr><td colspan="6" class="empty-msg">No notifications</td></tr>{/if}
          </tbody>
        </table>
        <div class="pagination">
          <button disabled={drillNotifPage <= 1} on:click={() => { drillNotifPage--; loadDrillNotifications(); }}>← Prev</button>
          <span>Page {drillNotifPage} of {Math.max(1, Math.ceil(drillNotifTotal / 10))}</span>
          <button disabled={drillNotifPage >= Math.ceil(drillNotifTotal / 10)} on:click={() => { drillNotifPage++; loadDrillNotifications(); }}>Next →</button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .admin-tab { display: flex; flex-direction: column; gap: 1rem; }

  .stats-row {
    display: flex; gap: 0.75rem; flex-wrap: wrap;
  }
  .stat-card {
    background: var(--color-surface); border: 1px solid var(--color-border);
    border-radius: var(--radius); padding: 0.75rem 1rem;
    display: flex; flex-direction: column; min-width: 100px;
  }
  .stat-value { font-size: 1.3rem; font-weight: 700; color: var(--color-text); }
  .stat-label { font-size: 0.7rem; color: var(--color-text-secondary); margin-top: 0.15rem; }

  .filters { display: flex; gap: 0.5rem; flex-wrap: wrap; }
  .search-input {
    flex: 1; min-width: 180px; padding: 0.4rem 0.6rem; font-size: 0.8rem;
    background: var(--color-surface); border: 1px solid var(--color-border);
    border-radius: var(--radius); color: var(--color-text);
    font-family: var(--font-family);
  }
  .plan-select, .plan-dropdown {
    padding: 0.4rem 0.5rem; font-size: 0.8rem;
    background: var(--color-surface); border: 1px solid var(--color-border);
    border-radius: var(--radius); color: var(--color-text);
    font-family: var(--font-family); cursor: pointer;
  }

  .table-wrap { overflow-x: auto; }
  .users-table, .drill-table {
    width: 100%; border-collapse: collapse; font-size: 0.78rem;
  }
  .users-table th, .drill-table th {
    text-align: left; padding: 0.4rem 0.5rem; color: var(--color-text-secondary);
    border-bottom: 1px solid var(--color-border); font-weight: 600;
  }
  .users-table td, .drill-table td {
    padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--color-border);
    color: var(--color-text);
  }
  .user-row { cursor: pointer; transition: background var(--transition); }
  .user-row:hover { background: var(--color-surface); }
  .user-row.selected { background: var(--color-surface); }
  .provider-cell { text-transform: capitalize; }

  .pagination {
    display: flex; align-items: center; justify-content: center; gap: 0.75rem;
    font-size: 0.78rem; color: var(--color-text-secondary);
  }
  .pagination button {
    padding: 0.3rem 0.6rem; font-size: 0.75rem;
    background: var(--color-surface); border: 1px solid var(--color-border);
    border-radius: var(--radius); color: var(--color-text); cursor: pointer;
    font-family: var(--font-family);
  }
  .pagination button:disabled { opacity: 0.4; cursor: default; }

  .drill-panel {
    background: var(--color-surface); border: 1px solid var(--color-border);
    border-radius: var(--radius); padding: 1rem; margin-top: 0.5rem;
  }
  .drill-header { display: flex; justify-content: space-between; align-items: center; }
  .drill-header h3 { font-size: 0.9rem; font-weight: 600; color: var(--color-text); margin: 0; }
  .close-btn {
    background: none; border: none; color: var(--color-text-secondary);
    font-size: 1rem; cursor: pointer;
  }
  .drill-tabs {
    display: flex; gap: 0; border-bottom: 1px solid var(--color-border); margin: 0.5rem 0;
  }
  .drill-tabs button {
    background: none; border: none; border-bottom: 2px solid transparent;
    color: var(--color-text-secondary); font-size: 0.75rem; font-weight: 500;
    padding: 0.4rem 0.6rem; cursor: pointer; font-family: var(--font-family);
  }
  .drill-tabs button.active { color: var(--color-accent); border-bottom-color: var(--color-accent); }

  .loading-msg, .empty-msg {
    text-align: center; color: var(--color-text-secondary); font-size: 0.8rem; padding: 1rem 0;
  }
  .domain-cell { font-family: var(--font-mono); font-size: 0.75rem; }
  .view-link { color: var(--color-accent); text-decoration: none; font-size: 0.75rem; }
  .view-link:hover { text-decoration: underline; }
</style>
