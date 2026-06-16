/**
 * Redis-backed TTL cache.
 *
 * Two-window model: every entry has a `freshUntil` timestamp (the primary TTL)
 * and the Redis key itself lives until `staleUntil` (optional, longer). Normal
 * reads return null past `freshUntil`; `cacheGetMaybeStale()` returns the value
 * regardless and flags it as stale — useful for "fall back to last known good
 * result when upstream is down."
 *
 * Falls back to no-op when Redis is unreachable or `initCache` was never called
 * with a live connection — callers just see misses and the system stays hot.
 */
import type { Redis } from "ioredis";

interface CacheEnvelope<T> {
  data: T;
  setAt: number;
  freshUntil: number;
}

let client: Redis | null = null;
let prefix = "cache:";

const DEFAULT_FRESH_TTL_MS = 5 * 60 * 1000;

export function initCache(redis: Redis | null, options?: { prefix?: string }): void {
  client = redis;
  if (options?.prefix !== undefined) prefix = options.prefix;
}

function ready(): Redis | null {
  if (!client) return null;
  if (client.status !== "ready") return null;
  return client;
}

// Some cached payloads contain Node Buffers (e.g. raw TLS cert bytes for SCT
// parsing). Plain JSON.stringify turns those into `{type:"Buffer",data:[...]}`
// that JSON.parse cannot round-trip back to a real Buffer — callers would lose
// methods like `.indexOf` / `.readUInt16BE`. The replacer/reviver below tag
// Buffers with `{__b:<base64>}` so we get them back as real Buffer instances.
function replacer(_key: string, value: unknown): unknown {
  if (value && typeof value === "object" && (value as any).type === "Buffer" && Array.isArray((value as any).data)) {
    return { __b: Buffer.from((value as any).data).toString("base64") };
  }
  if (Buffer.isBuffer(value)) {
    return { __b: value.toString("base64") };
  }
  return value;
}

function reviver(_key: string, value: unknown): unknown {
  if (value && typeof value === "object" && typeof (value as any).__b === "string" && Object.keys(value as any).length === 1) {
    return Buffer.from((value as any).__b, "base64");
  }
  return value;
}

function parse<T>(raw: string | null): CacheEnvelope<T> | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw, reviver) as CacheEnvelope<T>;
  } catch {
    return null;
  }
}

export async function cacheGet<T>(key: string): Promise<T | null> {
  const r = ready();
  if (!r) return null;
  try {
    const env = parse<T>(await r.get(prefix + key));
    if (!env) return null;
    if (Date.now() > env.freshUntil) return null;
    return env.data;
  } catch {
    return null;
  }
}

/** Like cacheGet, but also returns the entry's age in ms. Returns null on miss or stale. */
export async function cacheGetWithAge<T>(key: string): Promise<{ data: T; ageMs: number } | null> {
  const r = ready();
  if (!r) return null;
  try {
    const env = parse<T>(await r.get(prefix + key));
    if (!env) return null;
    const now = Date.now();
    if (now > env.freshUntil) return null;
    return { data: env.data, ageMs: now - env.setAt };
  } catch {
    return null;
  }
}

/**
 * Read the cache entry whether fresh or stale. Use when upstream failed and you
 * want last-known-good data. `isStale` is true past the freshness window.
 */
export async function cacheGetMaybeStale<T>(
  key: string,
): Promise<{ data: T; ageMs: number; isStale: boolean } | null> {
  const r = ready();
  if (!r) return null;
  try {
    const env = parse<T>(await r.get(prefix + key));
    if (!env) return null;
    const now = Date.now();
    return { data: env.data, ageMs: now - env.setAt, isStale: now > env.freshUntil };
  } catch {
    return null;
  }
}

/**
 * Store a value. `freshTtlMs` is how long it stays "fresh" (visible to
 * cacheGet/cacheGetWithAge). If `staleTtlMs` is provided and larger, the key
 * lives longer in Redis and remains accessible via cacheGetMaybeStale — letting
 * callers degrade gracefully when upstream is down.
 */
export async function cacheSet<T>(
  key: string,
  data: T,
  freshTtlMs: number = DEFAULT_FRESH_TTL_MS,
  staleTtlMs?: number,
): Promise<void> {
  const r = ready();
  if (!r) return;
  try {
    const setAt = Date.now();
    const envelope: CacheEnvelope<T> = {
      data,
      setAt,
      freshUntil: setAt + freshTtlMs,
    };
    const totalTtlMs = Math.max(freshTtlMs, staleTtlMs ?? freshTtlMs);
    await r.set(prefix + key, JSON.stringify(envelope, replacer), "PX", totalTtlMs);
  } catch {
    // best-effort — cache failures must never break the request
  }
}
