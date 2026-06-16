/**
 * Checks whether an IP address falls within private/reserved ranges.
 * Blocks RFC 1918, loopback, link-local, and IPv6 equivalents.
 *
 * Exported for callers that already hold an IP (e.g. per-IP TLS probes from
 * a multi-resolver DNS sweep) and don't want to re-resolve via assertSafeHostname.
 */
export function isBlockedIp(ip: string): boolean {
  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
  const v4Mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4Mapped) {
    return isBlockedIpv4(v4Mapped[1]);
  }

  if (ip.includes(":")) {
    return isBlockedIpv6(ip);
  }

  return isBlockedIpv4(ip);
}

function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return true; // malformed ? block
  const nums = parts.map(Number);
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return true;

  const [a, b] = nums;

  // 10.0.0.0/8
  if (a === 10) return true;
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  // 127.0.0.0/8 (loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (link-local)
  if (a === 169 && b === 254) return true;
  // 0.0.0.0
  if (nums.every((n) => n === 0)) return true;

  return false;
}

function expandIpv6(ip: string): string {
  const halves = ip.split("::");
  if (halves.length > 2) return "0000:0000:0000:0000:0000:0000:0000:0000";

  let groups: string[];
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves[1] ? halves[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    const middle = Array(missing).fill("0000");
    groups = [...left, ...middle, ...right];
  } else {
    groups = ip.split(":");
  }

  return groups.map((g) => g.padStart(4, "0")).join(":");
}

function isBlockedIpv6(ip: string): boolean {
  const normalized = expandIpv6(ip).toLowerCase();

  // ::1 (loopback)
  if (normalized === "0000:0000:0000:0000:0000:0000:0000:0001") return true;
  // :: (all zeros)
  if (/^0{4}(:0{4}){7}$/.test(normalized)) return true;
  // fc00::/7 (unique local) � first byte fc or fd
  const firstByte = parseInt(normalized.slice(0, 2), 16);
  if (firstByte >= 0xfc && firstByte <= 0xfd) return true;
  // fe80::/10 (link-local) � first 10 bits are 1111111010
  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") ||
      normalized.startsWith("fea") || normalized.startsWith("feb")) return true;

  return false;
}

import dns from "node:dns/promises";
import tls from "node:tls";
import { safeResolve } from "./dnsResolve.js";

/**
 * Resolves a hostname and verifies none of its IPs are in blocked ranges.
 * Throws an error with `code: "SSRF_BLOCKED"` if any IP is private/reserved,
 * or `code: "DNS_FAILURE"` if the hostname cannot be resolved.
 */
export async function assertSafeHostname(hostname: string): Promise<void> {
  let addresses: string[];
  try {
    const v4 = await safeResolve(() => dns.resolve4(hostname), 4000).catch(() => [] as string[]);
    const v6 = await safeResolve(() => dns.resolve6(hostname), 4000).catch(() => [] as string[]);
    addresses = [...v4, ...v6];
  } catch {
    const err = new Error("Could not resolve domain.");
    (err as any).code = "DNS_FAILURE";
    throw err;
  }

  if (addresses.length === 0) {
    const err = new Error("Could not resolve domain.");
    (err as any).code = "DNS_FAILURE";
    throw err;
  }

  for (const ip of addresses) {
    if (isBlockedIp(ip)) {
      const err = new Error("Restricted address.");
      (err as any).code = "SSRF_BLOCKED";
      throw err;
    }
  }
}

const MAX_SSRF_REDIRECTS = 5;

/**
 * Drop-in replacement for global `fetch` that checks the target hostname
 * against private/reserved IP ranges before making the request.
 * Handles redirects manually to IP-check each hop (prevents TOCTOU bypass).
 * Accepts the same arguments as `fetch`.
 */
export async function ssrfSafeFetch(
  input: string | URL | Request,
  init?: RequestInit,
): Promise<Response> {
  const url = typeof input === "string" ? new URL(input) : input instanceof URL ? input : new URL(input.url);
  await assertSafeHostname(url.hostname);

  // If caller already handles redirects manually, just pass through
  if (init?.redirect === "manual") {
    return fetch(input, init);
  }

  // Otherwise, override to manual and handle redirects ourselves with IP checks
  const response = await fetch(input, { ...init, redirect: "manual" });

  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location) return response;

    const redirectUrl = new URL(location, url);
    return ssrfSafeFetchWithRedirects(redirectUrl.toString(), init, 1);
  }

  return response;
}

async function ssrfSafeFetchWithRedirects(
  url: string,
  init: RequestInit | undefined,
  count: number,
): Promise<Response> {
  if (count > MAX_SSRF_REDIRECTS) {
    throw new Error("Too many redirects");
  }

  const parsed = new URL(url);
  await assertSafeHostname(parsed.hostname);

  const response = await fetch(url, { ...init, redirect: "manual" });

  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location) return response;

    const redirectUrl = new URL(location, url);
    return ssrfSafeFetchWithRedirects(redirectUrl.toString(), init, count + 1);
  }

  return response;
}

/**
 * SSRF-safe wrapper around `tls.connect`.
 * Resolves the hostname first and blocks private/reserved IPs.
 */
export function ssrfSafeTlsConnect(
  options: tls.ConnectionOptions & { host: string },
): Promise<tls.TLSSocket> {
  return new Promise(async (resolve, reject) => {
    try {
      await assertSafeHostname(options.host);
    } catch (err) {
      reject(err);
      return;
    }
    const socket = tls.connect(options, () => resolve(socket));
    socket.on("error", reject);
  });
}

/**
 * Pre-warm the OS DNS cache for a domain.
 * Call once before firing parallel checks to avoid cold-resolver timeouts.
 * Returns the resolved IPv4 address (or null on failure). Silently swallows errors.
 */
const _dnsWarmCache = new Map<string, { ip: string | null; ts: number }>();
const DNS_WARM_TTL = 60_000; // 1 minute

export async function warmDns(hostname: string, timeoutMs = 5000): Promise<string | null> {
  const cached = _dnsWarmCache.get(hostname);
  if (cached && Date.now() - cached.ts < DNS_WARM_TTL) return cached.ip;
  try {
    const result = await safeResolve(() => dns.resolve4(hostname), timeoutMs);
    const ip = result?.[0] ?? null;
    _dnsWarmCache.set(hostname, { ip, ts: Date.now() });
    return ip;
  } catch {
    _dnsWarmCache.set(hostname, { ip: null, ts: Date.now() });
    return null;
  }
}
