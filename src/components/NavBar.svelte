<script lang="ts">
  export let theme: 'dark' | 'light' = 'dark';
  export let currentPath: string = '/';

  import { createEventDispatcher } from 'svelte';
  const dispatch = createEventDispatcher<{ toggleTheme: void }>();
</script>

<nav class="navbar" aria-label="Main navigation">
  <a class="nav-brand" href="/#/" class:active={currentPath === '/' || currentPath === ''}>
    Domain Security Checker
  </a>
  <div class="nav-links">
    <a class="nav-link" href="/#/security-txt" class:active={currentPath === '/security-txt'}>
      security.txt
    </a>
    <button class="theme-toggle" on:click={() => dispatch('toggleTheme')} aria-label="Toggle {theme === 'dark' ? 'light' : 'dark'} theme">
      {#if theme === 'dark'}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
        </svg>
      {:else}
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
      {/if}
    </button>
  </div>
</nav>

<style>
  .navbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 0 1rem;
    border-bottom: 1px solid var(--color-border);
    margin-bottom: 1.5rem;
  }

  .nav-brand {
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--color-text);
    text-decoration: none;
    transition: color var(--transition);
  }

  .nav-brand:hover {
    color: var(--color-accent);
  }

  .nav-brand.active {
    color: var(--color-accent);
  }

  .nav-links {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .nav-link {
    font-size: 0.8rem;
    color: var(--color-text-secondary);
    text-decoration: none;
    padding: 0.25rem 0.5rem;
    border-radius: var(--radius);
    transition: color var(--transition);
  }

  .nav-link:hover {
    color: var(--color-text);
  }

  .nav-link.active {
    color: var(--color-accent);
  }

  .theme-toggle {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    color: var(--color-text-secondary);
    padding: 0.35rem;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: color var(--transition), border-color var(--transition);
  }

  .theme-toggle:hover {
    color: var(--color-accent);
    border-color: var(--color-accent);
  }
</style>
