<script lang="ts">
  import NavBar from './components/NavBar.svelte';
  import Router from './components/Router.svelte';
  import { onMount } from 'svelte';

  let theme: 'dark' | 'light' = 'dark';
  let currentPath = '/';

  onMount(() => {
    const saved = localStorage.getItem('theme');
    if (saved === 'light' || saved === 'dark') {
      theme = saved;
    } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
      theme = 'light';
    }
    document.documentElement.setAttribute('data-theme', theme);
  });

  function toggleTheme() {
    theme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }
</script>

<div class="container">
  <NavBar {theme} {currentPath} on:toggleTheme={toggleTheme} />
  <Router bind:currentPath />
</div>
