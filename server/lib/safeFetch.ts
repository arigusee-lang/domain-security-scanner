import dns from "node:dns/promises";
import { isBlockedIp } from "./ipCheck.js";
import type { ProxyFetchResponse, ProxyFetchError } from "../types.js";

const MAX_REDIRECTS = 3;
const TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 100 * 1024; // 100 KB

/**
 * Safely converts any thrown error into a ProxyFetchError.
 */
function toProxyError(err: any): ProxyFetchError {
  if (err && typeof err === "object" && err.error) {
    return {
      success: false as const,
      error: err.error,
      message: err.message || "An error occurred.",
      ...(err.httpStatus ? { httpStatus: err.httpStatus } : {}),
    };
  }
  return {
    success: false as const,
    error: "internal",
    message: err?.message || "An unexpected error occurred.",
  };
}

/**
 * Resolves a hostname and checks all IPs against blocked ranges.
 * Returns the first non-blocked IP, or throws with "ssrf_blocked" / "dns_failure".
 */
async function resolveAndCheck(hostname: string): Promise<void> {
  let addresses: string[];
  try {
    const result = await dns.resolve4(hostname).catch(() => []);
    const result6 = await dns.resolve6(hostname).catch(() => []);
    addresses = [...result, ...result6];
  } catch {
    throw { error: "dns_failure" as const, message: "Could not resolve domain." };
  }

  if (addresses.length === 0) {
    throw { error: "dns_failure" as const, message: "Could not resolve domain." };
  }

  for (const ip of addresses) {
    if (isBlockedIp(ip)) {
      throw { error: "ssrf_blocked" as const, message: "Restricted address." };
    }
  }
}

/**
 * Fetches a URL with SSRF protections: DNS check, redirect IP checks,
 * timeout, and body size limit.
 */
async function fetchWithProtection(
  url: string,
  redirectChain: string[],
  redirectCount: number
): Promise<{ body: string; contentType: string; finalUrl: string; redirectChain: string[] }> {
  const parsed = new URL(url);

  if (parsed.protocol !== "https:") {
    throw { error: "ssrf_blocked" as const, message: "Only HTTPS is allowed." };
  }

  await resolveAndCheck(parsed.hostname);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, {
      signal: controller.signal,
      redirect: "manual",
      headers: { "User-Agent": "security-txt-validator/1.0" },
    });
  } catch (err: any) {
    clearTimeout(timer);
    if (err?.name === "AbortError") {
      throw { error: "timeout" as const, message: "Remote server timed out." };
    }
    throw { error: "dns_failure" as const, message: "Could not resolve domain." };
  } finally {
    clearTimeout(timer);
  }

  // Handle redirects manually so we can IP-check each hop
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location) {
      throw { error: "http_error" as const, message: `Redirect without Location header.`, httpStatus: response.status };
    }

    if (redirectCount >= MAX_REDIRECTS) {
      throw { error: "too_many_redirects" as const, message: "Too many redirects." };
    }

    const redirectUrl = new URL(location, url).toString();
    redirectChain.push(redirectUrl);
    return fetchWithProtection(redirectUrl, redirectChain, redirectCount + 1);
  }

  if (!response.ok) {
    throw { error: "http_error" as const, message: `HTTP ${response.status}`, httpStatus: response.status };
  }

  // Check Content-Type early — reject HTML/non-text responses before reading body
  const contentType = response.headers.get("content-type") || "";
  if (contentType && !contentType.includes("text/plain")) {
    throw { error: "invalid_content_type" as const, message: `Expected text/plain, got ${contentType.split(";")[0].trim()}` };
  }

  // Read body with size limit
  const reader = response.body?.getReader();
  if (!reader) {
    throw { error: "http_error" as const, message: "Empty response body." };
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > MAX_BODY_BYTES) {
      reader.cancel();
      throw { error: "size_limit" as const, message: "Response exceeds 100 KB limit." };
    }
    chunks.push(value);
  }

  const decoder = new TextDecoder();
  const body = chunks.map((c) => decoder.decode(c, { stream: true })).join("") + decoder.decode();

  return { body, contentType, finalUrl: url, redirectChain };
}

/**
 * SSRF-safe fetch for security.txt files.
 * Tries /.well-known/security.txt first, falls back to /security.txt.
 * Validates Content-Type contains text/plain.
 */
export async function safeFetch(domain: string): Promise<ProxyFetchResponse | ProxyFetchError> {
  const wellKnownUrl = `https://${domain}/.well-known/security.txt`;
  const fallbackUrl = `https://${domain}/security.txt`;

  let result: { body: string; contentType: string; finalUrl: string; redirectChain: string[] };
  let wellKnownFound = true;
  let fallbackUsed = false;

  // Also handle invalid_content_type from fetchWithProtection as "not a security.txt"
  try {
    result = await fetchWithProtection(wellKnownUrl, [], 0);
  } catch (err: any) {
    if (err?.error === "http_error" && err?.httpStatus === 404) {
      wellKnownFound = false;
      fallbackUsed = true;
      try {
        result = await fetchWithProtection(fallbackUrl, [], 0);
      } catch (fallbackErr: any) {
        if (fallbackErr?.error === "http_error" && fallbackErr?.httpStatus === 404) {
          return { success: false, error: "not_found", message: "No security.txt file found." };
        }
        if (fallbackErr?.error === "invalid_content_type") {
          return { success: false, error: "not_found", message: "No security.txt file found (server returned HTML instead)." };
        }
        return toProxyError(fallbackErr);
      }
    } else if (err?.error === "invalid_content_type") {
      // Well-known returned non-text, try fallback
      wellKnownFound = false;
      fallbackUsed = true;
      try {
        result = await fetchWithProtection(fallbackUrl, [], 0);
      } catch (fallbackErr: any) {
        return { success: false, error: "not_found", message: "No security.txt file found (server returned HTML instead)." };
      }
    } else {
      return toProxyError(err);
    }
  }

  // Safety net: verify Content-Type (should already be checked in fetchWithProtection)
  if (!result.contentType.includes("text/plain")) {
    return {
      success: false,
      error: "invalid_content_type",
      message: `Expected text/plain, got ${result.contentType.split(";")[0].trim() || "unknown"}`,
    };
  }

  return {
    success: true,
    content: result.body,
    contentType: result.contentType,
    fetchedFrom: result.finalUrl,
    redirectChain: result.redirectChain,
    wellKnownFound,
    fallbackUsed,
  };
}

import https from "node:https";
import tls from "node:tls";
import type { SafeFetchWithHeadersResponse } from "../types.js";
import type { TlsCertInfo } from "../types.js";

/**
 * Connects to the domain via TLS and extracts the peer certificate.
 */
function extractTlsCert(hostname: string, timeoutMs: number): Promise<TlsCertInfo | null> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: timeoutMs, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      socket.destroy();
      if (!cert || !cert.valid_from) { resolve(null); return; }
      const validFrom = new Date(cert.valid_from).toISOString();
      const validTo = new Date(cert.valid_to).toISOString();
      const daysRemaining = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
      const sans: string[] = cert.subjectaltname
        ? cert.subjectaltname.split(",").map((s: string) => s.trim().replace(/^DNS:/, ""))
        : [];
      resolve({
        issuer: String(cert.issuer?.O || cert.issuer?.CN || "Unknown"),
        subject: String(cert.subject?.CN || "Unknown"),
        validFrom,
        validTo,
        daysRemaining,
        sans,
      });
    });
    socket.on("error", () => { socket.destroy(); resolve(null); });
    socket.on("timeout", () => { socket.destroy(); resolve(null); });
  });
}

/**
 * SSRF-safe fetch that also captures HTTP response headers and TLS certificate info.
 * Used by the domain check API to avoid a second HTTP request.
 */
export async function safeFetchWithHeaders(
  domain: string,
  timeoutMs: number = 8000
): Promise<SafeFetchWithHeadersResponse | ProxyFetchError> {
  // Run TLS cert extraction in parallel with the normal fetch
  const [fetchResult, tlsCert] = await Promise.all([
    safeFetch(domain),
    extractTlsCert(domain, timeoutMs),
  ]);

  if (!fetchResult.success) {
    return fetchResult;
  }

  // Fetch security headers from the domain's root page (not security.txt)
  let responseHeaders: Record<string, string> = {};
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const headRes = await fetch(`https://${domain}/`, {
      method: "HEAD",
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "security-txt-validator/1.0" },
    });
    clearTimeout(timer);
    headRes.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });
  } catch {
    // Headers extraction is best-effort
  }

  return {
    success: true,
    content: fetchResult.content,
    contentType: fetchResult.contentType,
    fetchedFrom: fetchResult.fetchedFrom,
    redirectChain: fetchResult.redirectChain,
    wellKnownFound: fetchResult.wellKnownFound,
    fallbackUsed: fetchResult.fallbackUsed,
    responseHeaders,
    tlsCert,
  };
}
