<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  const dispatch = createEventDispatcher<{ check: { domain: string; noCache: boolean; crtShFirst: boolean } }>();

  let domain = '';
  let error = '';
  let noCache = false;
  let crtShFirst = false;
  const isDev = window.location.hostname === 'localhost';

  export function setDomain(d: string) {
    domain = d;
  }

  function handleSubmit() {
    error = '';
    const trimmed = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!trimmed) {
      error = 'Please enter a domain.';
      return;
    }
    domain = trimmed;
    dispatch('check', { domain: trimmed, noCache, crtShFirst });
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') handleSubmit();
  }
</script>

<div class="domain-input-wrap">
  <div class="input-row">
    <label for="domain-input" class="sr-only">Enter a domain</label>
    <input
      id="domain-input"
      class="domain-input"
      type="text"
      placeholder="example.com"
      aria-label="Domain to check"
      bind:value={domain}
      on:keydown={handleKeydown}
    />
    <button class="check-btn" on:click={handleSubmit}>Check</button>
  </div>
  {#if isDev}
    <label class="dev-toggle">
      <input type="checkbox" bind:checked={noCache} />
      <span>Skip cache (dev)</span>
    </label>
    <label class="dev-toggle">
      <input type="checkbox" bind:checked={crtShFirst} />
      <span>Use crt.sh first (dev)</span>
    </label>
  {/if}
  {#if error}
    <p class="error-msg" role="alert">{error}</p>
  {/if}
</div>

<style>
  .domain-input-wrap {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .input-row {
    display: flex;
    gap: 0.5rem;
  }

  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0;
  }

  .domain-input {
    flex: 1;
    background: var(--color-bg);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 0.7rem 0.9rem;
    font-family: var(--font-family);
    font-size: 0.9rem;
    transition: border-color var(--transition);
  }

  .domain-input:focus {
    border-color: var(--color-accent);
    outline: none;
  }

  .domain-input::placeholder {
    color: var(--color-text-secondary);
  }

  .check-btn {
    background: var(--color-accent);
    color: var(--color-bg);
    border: none;
    border-radius: var(--radius);
    padding: 0.7rem 1.5rem;
    font-family: var(--font-family);
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition);
    white-space: nowrap;
  }

  .check-btn:hover {
    background: var(--color-accent-hover);
  }

  .error-msg {
    color: var(--color-error);
    font-size: 0.8rem;
  }

  .dev-toggle {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.7rem;
    color: var(--color-text-secondary);
    opacity: 0.6;
    cursor: pointer;
  }

  .dev-toggle input {
    accent-color: var(--color-accent);
    cursor: pointer;
  }
</style>
