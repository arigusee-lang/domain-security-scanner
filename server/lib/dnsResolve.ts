import dns from "node:dns/promises";
import { Resolver } from "node:dns/promises";
import { createLogger } from "./logger.js";

const log = createLogger("dns");

const DEFAULT_TIMEOUT_MS = 5000;
const RESET_COOLDOWN_MS = 1000;

/** Public DNS resolvers used for multi-resolver A-record probing. */
export const PUBLIC_RESOLVERS: Array<{ name: string; servers: string[] }> = [
  { name: "Google", servers: ["8.8.8.8", "8.8.4.4"] },
  { name: "Cloudflare", servers: ["1.1.1.1", "1.0.0.1"] },
  { name: "Quad9", servers: ["9.9.9.9", "149.112.112.112"] },
  { name: "OpenDNS", servers: ["208.67.222.222", "208.67.220.220"] },
];

export interface ResolverProbeResult {
  resolver: string;
  ips: string[];
  error?: string;
}

export interface MultiResolverResult {
  /** Union of unique IPs observed across resolvers (in insertion order). */
  ips: string[];
  /** Per-resolver detail (useful for diagnostics / future regional mapping). */
  details: ResolverProbeResult[];
  /** Number of resolvers that returned at least one IP. */
  successCount: number;
}

/**
 * Resolve A records for a domain in parallel via several public DNS resolvers.
 * Different resolvers (and EDNS Client Subnet behavior) often return distinct
 * edge IPs for CDN-fronted domains — the union gives a representative sample
 * of edges a real client might land on.
 */
export async function resolveMultiResolver(
  domain: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<MultiResolverResult> {
  const probes = await Promise.allSettled(
    PUBLIC_RESOLVERS.map(async ({ name, servers }): Promise<ResolverProbeResult> => {
      const r = new Resolver({ timeout: timeoutMs, tries: 1 });
      r.setServers(servers);
      try {
        const ips = await withTimeout(r.resolve4(domain), timeoutMs);
        return { resolver: name, ips };
      } catch (err: any) {
        return { resolver: name, ips: [], error: err?.code || err?.message || "error" };
      }
    }),
  );

  const details: ResolverProbeResult[] = probes.map((p) =>
    p.status === "fulfilled" ? p.value : { resolver: "unknown", ips: [], error: "rejected" },
  );

  const seen = new Set<string>();
  const ips: string[] = [];
  for (const d of details) {
    for (const ip of d.ips) {
      if (!seen.has(ip)) {
        seen.add(ip);
        ips.push(ip);
      }
    }
  }

  const successCount = details.filter((d) => d.ips.length > 0).length;
  return { ips, details, successCount };
}

let lastResetAt = 0;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); }
    );
  });
}

// c-ares caches its server list and UDP sockets at process init. After laptop
// sleep, VPN reconnect, or any network interface change those sockets go stale
// and dns.resolve* hangs until our outer timeout. Re-applying the server list
// forces c-ares to drop its state and recreate the sockets. Debounced so that
// a burst of concurrent timeouts in one scan only resets once.
function resetCares(): void {
  const now = Date.now();
  if (now - lastResetAt < RESET_COOLDOWN_MS) return;
  lastResetAt = now;
  try {
    const servers = dns.getServers();
    if (servers.length > 0) {
      dns.setServers(servers);
      log.warn({ servers: servers.length }, "c-ares timeout — reset servers and retrying once");
    }
  } catch (err: any) {
    log.warn({ err: err?.message || err }, "failed to reset c-ares servers");
  }
}

/**
 * Run a c-ares DNS query with a timeout. On the first timeout, reset c-ares
 * once (in case its sockets went stale after sleep/network change) and retry
 * exactly once. Any non-timeout error, or a timeout on the retry, is thrown.
 */
export async function safeResolve<T>(fn: () => Promise<T>, timeoutMs: number = DEFAULT_TIMEOUT_MS): Promise<T> {
  try {
    return await withTimeout(fn(), timeoutMs);
  } catch (err: any) {
    if (err?.message !== "timeout") throw err;
    resetCares();
    return withTimeout(fn(), timeoutMs);
  }
}
