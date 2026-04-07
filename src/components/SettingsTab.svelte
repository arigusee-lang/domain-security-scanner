<script lang="ts">
  import { onDestroy } from 'svelte';
  import { currentUser } from '../lib/authStore';

  let user: import('../lib/authStore').AuthUser | null = null;
  const unsub = currentUser.subscribe(v => (user = v));
  onDestroy(() => unsub());
</script>

<div class="settings-tab">
  {#if user}
    <div class="section">
      <h3 class="section-title">Account</h3>
      <div class="info-row">
        <span class="info-label">Email</span>
        <span class="info-value">{user.email}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Name</span>
        <span class="info-value">{user.name || '—'}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Plan</span>
        <span class="info-value plan-badge">{user.plan}</span>
      </div>
    </div>

    <div class="section">
      <h3 class="section-title">Webhooks</h3>
      <p class="placeholder">Webhook management coming soon.</p>
    </div>

    <div class="section">
      <h3 class="section-title">Shared Links</h3>
      <p class="placeholder">Shared link management coming soon.</p>
    </div>
  {/if}
</div>

<style>
  .settings-tab {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .section {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
  }

  .section-title {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--color-text);
    margin-bottom: 0.5rem;
  }

  .info-row {
    display: flex;
    justify-content: space-between;
    padding: 0.3rem 0;
    font-size: 0.8rem;
    border-bottom: 1px solid var(--color-border);
  }

  .info-row:last-child { border-bottom: none; }

  .info-label {
    color: var(--color-text-secondary);
  }

  .info-value {
    color: var(--color-text);
    font-weight: 500;
  }

  .plan-badge {
    text-transform: capitalize;
    color: var(--color-accent);
  }

  .placeholder {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
  }
</style>
