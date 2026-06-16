<script lang="ts">
  import type { InfrastructureResult, SslResult } from '../lib/types';

  export let infrastructure: InfrastructureResult | null | undefined = null;
  // Legacy fallback: scans saved before the Phase A split kept ip/cdnProvider
  // inside `blacklist`. Accept either shape so historical scans still render.
  export let blacklist: any = null;
  export let ssl: SslResult | null | undefined = null;

  $: legacy = blacklist && (blacklist.ip || blacklist.ips || blacklist.cdnProvider) ? blacklist : null;
  $: ips = (infrastructure?.ips && infrastructure.ips.length > 0)
    ? infrastructure.ips
    : (legacy?.ips && legacy.ips.length > 0)
      ? legacy.ips
      : (infrastructure?.ip
          ? [infrastructure.ip]
          : (legacy?.ip ? [legacy.ip] : []));
  $: primaryIp = ips[0] ?? null;
  $: cdnProvider = infrastructure?.cdnProvider ?? legacy?.cdnProvider ?? null;
  $: cdnProviders = (infrastructure?.cdnProviders && infrastructure.cdnProviders.length > 0)
    ? infrastructure.cdnProviders
    : (legacy?.cdnProviders ?? (cdnProvider ? [cdnProvider] : []));
  $: multipleCdns = cdnProviders.length > 1;
  $: multipleEdges = ips.length > 1;
  $: visible = !!primaryIp;

  $: edges = ssl?.edges ?? null;
  $: edgeSamples = edges?.samples ?? [];
  $: edgeValidSamples = edgeSamples.filter((s) => !s.error);
  $: edgeFailedCount = edges?.failedIps?.length ?? 0;

  $: certLine = (() => {
    if (!edges || edgeValidSamples.length === 0) return null;
    const n = edgeValidSamples.length;
    if (edges.consistency === 'consistent') {
      return { kind: 'pass' as const, text: `Cert: same across all ${n} edge${n !== 1 ? 's' : ''}` };
    }
    if (edges.consistency === 'rollout') {
      const min = edges.minDaysRemaining;
      const max = edges.maxDaysRemaining;
      const dayRange = (min != null && max != null && min !== max)
        ? ` (earliest expires in ${min}d, latest in ${max}d)`
        : '';
      return { kind: 'info' as const, text: `Cert rotation in progress: ${edges.distinctFingerprints} versions co-exist${dayRange}` };
    }
    if (edges.consistency === 'inconsistent') {
      const bad = edgeValidSamples.filter((s) => !s.sanMatch || !s.chainOk);
      const detail = bad.length === 1 ? `1 edge serves invalid cert` : `${bad.length} edges serve invalid cert`;
      return { kind: 'fail' as const, text: detail };
    }
    return null;
  })();

  $: title =
    multipleCdns ? `Behind multiple CDNs (${cdnProviders.join(', ')})` :
    cdnProvider ? `Behind ${cdnProvider} CDN` :
    multipleEdges ? 'Multiple origins' :
    'Direct origin';

  $: detail =
    multipleEdges
      ? `${ips.length} IP${ips.length !== 1 ? 's' : ''} observed across public resolvers`
      : (cdnProvider
          ? `Origin IP belongs to ${cdnProvider}'s edge network`
          : '');
</script>

{#if visible}
  <div class="infra-banner" class:cdn={cdnProvider} role="status">
    <span class="infra-icon" aria-hidden="true">
      {#if cdnProvider}
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <path d="M4.5 13a3.5 3.5 0 010-7 4.5 4.5 0 018.94-1.05A3.5 3.5 0 0114 13H4.5z"
                stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/>
        </svg>
      {:else}
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <rect x="2" y="3" width="12" height="4" rx="1" stroke="currentColor" stroke-width="1.3"/>
          <rect x="2" y="9" width="12" height="4" rx="1" stroke="currentColor" stroke-width="1.3"/>
          <circle cx="4.5" cy="5" r="0.6" fill="currentColor"/>
          <circle cx="4.5" cy="11" r="0.6" fill="currentColor"/>
        </svg>
      {/if}
    </span>
    <div class="infra-content">
      <div class="infra-header">
        <span class="infra-title">{title}</span>
        {#if certLine && certLine.kind === 'pass'}
          <span class="cert-line cert-pass">
            ✓ {certLine.text}{#if edgeFailedCount > 0} · {edgeFailedCount} probe{edgeFailedCount !== 1 ? 's' : ''} failed{/if}
          </span>
        {/if}
      </div>
      {#if multipleEdges}
        <span class="infra-detail">{detail}</span>
        <details class="ip-details">
          <summary>Show {ips.length} IPs</summary>
          <div class="ip-list">
            {#each ips as ip}
              <code>{ip}</code>
            {/each}
          </div>
        </details>
      {:else}
        <span class="infra-detail">
          {#if cdnProvider}
            Origin IP <code>{primaryIp}</code> belongs to {cdnProvider}'s edge network
          {:else}
            IP <code>{primaryIp}</code>
          {/if}
        </span>
      {/if}
      {#if certLine && certLine.kind !== 'pass'}
        <span class="cert-line cert-{certLine.kind}">
          {#if certLine.kind === 'fail'}⚠ {/if}{certLine.text}{#if edgeFailedCount > 0} · {edgeFailedCount} probe{edgeFailedCount !== 1 ? 's' : ''} failed{/if}
        </span>
      {/if}
    </div>
  </div>
{/if}

<style>
  .infra-banner {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    padding: 0.6rem 0.85rem;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-left: 3px solid var(--color-info);
    border-radius: var(--radius-lg);
    color: var(--color-text);
  }
  .infra-icon {
    color: var(--color-info);
    flex-shrink: 0;
    margin-top: 0.1rem;
  }
  .infra-content {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
    flex: 1;
  }
  .infra-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 0.75rem;
    flex-wrap: wrap;
  }
  .infra-title {
    font-size: 0.85rem;
    font-weight: 600;
  }
  .infra-detail {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
  }
  .infra-detail code,
  .ip-list code {
    font-family: var(--font-mono);
    background: var(--color-bg);
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
    font-size: 0.72rem;
  }
  .ip-details {
    margin-top: 0.2rem;
    font-size: 0.72rem;
    color: var(--color-text-secondary);
  }
  .ip-details summary {
    cursor: pointer;
    user-select: none;
    display: inline-block;
  }
  .ip-details summary:hover {
    color: var(--color-text);
  }
  .ip-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
    margin-top: 0.3rem;
  }
  .cert-line {
    margin-top: 0.25rem;
    font-size: 0.74rem;
    font-weight: 500;
  }
  .cert-pass { color: var(--color-valid); }
  .cert-info { color: var(--color-info); }
  .cert-fail { color: var(--color-error); }
</style>
