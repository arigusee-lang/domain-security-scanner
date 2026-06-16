import tls from "node:tls";
import { isBlockedIp } from "./ipCheck.js";
import { createLogger } from "./logger.js";
import type {
  TlsEdgeSample,
  TlsEdgesConsistency,
  TlsEdgesResult,
} from "../types.js";

const log = createLogger("tls-edge");

/** Cap on per-domain edge samples — diminishing returns past this. */
const DEFAULT_MAX_SAMPLES = 5;

function placeholderSample(ip: string, error: string): TlsEdgeSample {
  return {
    ip,
    fingerprint: "",
    issuer: "",
    notAfter: "",
    daysRemaining: 0,
    sanMatch: false,
    chainOk: false,
    error,
  };
}

/**
 * Open a TLS connection to a *specific* IP with SNI=hostname and extract leaf
 * certificate details. Unlike `extractTlsCert` (which lets Node resolve the
 * hostname itself), this lets us probe each edge of a CDN/multi-IP setup.
 *
 * Returns a sample with `error` set on failure — never rejects.
 */
export function probeOneEdge(
  ip: string,
  hostname: string,
  timeoutMs: number,
): Promise<TlsEdgeSample> {
  return new Promise((resolve) => {
    if (isBlockedIp(ip)) {
      resolve(placeholderSample(ip, "private/reserved IP"));
      return;
    }

    let done = false;
    const finish = (s: TlsEdgeSample) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch { /* ignore */ }
      resolve(s);
    };

    const socket = tls.connect(
      {
        host: ip,
        port: 443,
        servername: hostname,
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          if (!cert || !cert.valid_from) {
            finish(placeholderSample(ip, "no certificate returned"));
            return;
          }
          const fingerprint = String(cert.fingerprint256 || "")
            .replace(/:/g, "")
            .toLowerCase();
          const issuer = String(cert.issuer?.O || cert.issuer?.CN || "Unknown");
          const notAfter = new Date(cert.valid_to).toISOString();
          const daysRemaining = Math.floor(
            (new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000,
          );
          // checkServerIdentity returns an Error when the hostname doesn't match,
          // or undefined when it does. Cast is needed because Node's type
          // declarations expect `PeerCertificate` (we already have one).
          const idErr = tls.checkServerIdentity(hostname, cert as tls.PeerCertificate);
          const sanMatch = !idErr;
          // authorizationError is populated when chain validation fails, even
          // when rejectUnauthorized is false.
          const chainOk = !socket.authorizationError;
          finish({
            ip,
            fingerprint,
            issuer,
            notAfter,
            daysRemaining,
            sanMatch,
            chainOk,
          });
        } catch (err: any) {
          finish(placeholderSample(ip, err?.message || "probe error"));
        }
      },
    );

    socket.on("error", (err) => finish(placeholderSample(ip, err?.message || "connect error")));
    socket.on("timeout", () => finish(placeholderSample(ip, "timeout")));
  });
}

function deriveConsistency(samples: TlsEdgeSample[]): TlsEdgesConsistency {
  const valid = samples.filter((s) => !s.error);
  if (valid.length < 2) return "unknown";
  if (!valid.every((s) => s.sanMatch && s.chainOk)) return "inconsistent";
  const distinct = new Set(valid.map((s) => s.fingerprint)).size;
  return distinct === 1 ? "consistent" : "rollout";
}

/**
 * Probe each IP (caller supplies the list, usually from `checkInfrastructure`)
 * and aggregate per-edge certificate observations.
 *
 * The caller controls the input set — this checker doesn't resolve DNS itself,
 * which avoids duplicating the multi-resolver sweep that already runs in the
 * infrastructure check.
 */
export async function probeMultiEdge(
  domain: string,
  ips: string[],
  timeoutMs: number,
  maxSamples: number = DEFAULT_MAX_SAMPLES,
): Promise<TlsEdgesResult> {
  const candidateIps = Array.from(new Set(ips)).slice(0, maxSamples);

  if (candidateIps.length === 0) {
    return emptyResult();
  }

  const samples = await Promise.all(
    candidateIps.map((ip) => probeOneEdge(ip, domain, timeoutMs)),
  );

  return aggregateSamples(samples);
}

function emptyResult(): TlsEdgesResult {
  return {
    samples: [],
    failedIps: [],
    distinctFingerprints: 0,
    minDaysRemaining: null,
    maxDaysRemaining: null,
    allSanMatch: false,
    allChainOk: false,
    consistency: "unknown",
  };
}

function aggregateSamples(samples: TlsEdgeSample[]): TlsEdgesResult {
  const valid = samples.filter((s) => !s.error);
  const failedIps = samples.filter((s) => s.error).map((s) => s.ip);

  const fingerprints = new Set(valid.map((s) => s.fingerprint));
  const days = valid.map((s) => s.daysRemaining);
  const minDays = days.length > 0 ? Math.min(...days) : null;
  const maxDays = days.length > 0 ? Math.max(...days) : null;

  const allSanMatch = valid.length > 0 && valid.every((s) => s.sanMatch);
  const allChainOk = valid.length > 0 && valid.every((s) => s.chainOk);

  if (failedIps.length > 0) {
    log.debug({ failedIps }, "some edge probes failed");
  }

  return {
    samples,
    failedIps,
    distinctFingerprints: fingerprints.size,
    minDaysRemaining: minDays,
    maxDaysRemaining: maxDays,
    allSanMatch,
    allChainOk,
    consistency: deriveConsistency(samples),
  };
}
