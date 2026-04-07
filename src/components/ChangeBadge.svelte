<script lang="ts">
  export let severity: 'critical' | 'warn' | 'resolved' | 'info' = 'info';

  $: label = severity === 'critical' ? 'New issue'
    : severity === 'warn' ? 'New issue'
    : severity === 'resolved' ? 'Resolved'
    : 'Changed';

  $: icon = severity === 'critical' || severity === 'warn' ? '🔴'
    : severity === 'resolved' ? '🟢'
    : '🔵';
</script>

<span class="change-badge {severity}" aria-label="{label}">
  <span class="badge-icon" aria-hidden="true">{icon}</span>
  <span class="badge-text">{label}</span>
</span>

<style>
  .change-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
    font-size: 0.6rem;
    font-weight: 600;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }

  .change-badge.critical,
  .change-badge.warn {
    background: rgba(255, 77, 106, 0.1);
    color: var(--color-error);
  }

  .change-badge.resolved {
    background: rgba(0, 212, 170, 0.1);
    color: var(--color-valid);
  }

  .change-badge.info {
    background: rgba(77, 166, 255, 0.1);
    color: var(--color-info);
  }

  .badge-icon {
    font-size: 0.55rem;
  }
</style>
