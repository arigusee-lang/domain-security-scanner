/**
 * Registry of known Certificate Transparency logs with operators.
 * Loads dynamically from Google's official log list on startup,
 * falls back to a built-in 2026 snapshot.
 */

export interface KnownCtLog {
  logId: string; // hex-encoded SHA-256 of log public key
  name: string;
  operator: string;
}

// Built-in fallback (2026 logs only)
const BUILTIN_LOGS: KnownCtLog[] = [
  { logId: "0e5794bcf3aea93e331b2c9907b3f790df9bc23d713225dd21a925ac61c54e21", name: "Google Argon2026h1", operator: "Google" },
  { logId: "d76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b3017317c0c8c56977", name: "Google Argon2026h2", operator: "Google" },
  { logId: "969764bf555897adf743876837084277e9f03ad5f6a4f3366e46a43f0fcaa9c6", name: "Google Xenon2026h1", operator: "Google" },
  { logId: "d809553b944f7affc816196f944f85abb0f8fc5e8755260f15d12e72bb454b14", name: "Google Xenon2026h2", operator: "Google" },
  { logId: "cb38f715897c84a1445f5bc1ddfbc96ef29a59cd470a690585b0cb14c31458e7", name: "Cloudflare Nimbus2026", operator: "Cloudflare" },
  { logId: "1986d4c728aa6ffeba036f782a4d0191aace2d72310faece5d70412d254cc7d4", name: "Let's Encrypt Oak2026h1", operator: "Let's Encrypt" },
  { logId: "acab30706cebec8431f413d2f4915f111e422443b1f2a68c4f3c2b3ba71e02c3", name: "Let's Encrypt Oak2026h2", operator: "Let's Encrypt" },
  { logId: "6411c46ca412eca7891ca2022e00bcab4f2807d41e3527abeafed503c97dcdf0", name: "DigiCert Wyvern2026h1", operator: "DigiCert" },
  { logId: "c2317e574519a345ee7f38deb29041ebc7c2215a22bf7fd5b5ad769ad90e52cd", name: "DigiCert Wyvern2026h2", operator: "DigiCert" },
  { logId: "499c9b69de1d7cecfc36decd8764a6b85baf0a878019d15552fbe9eb29ddf8c3", name: "DigiCert Sphinx2026h1", operator: "DigiCert" },
  { logId: "944e4387faecc1ef81f3192426a8186501c7d35f3802013f72677d55372e19d8", name: "DigiCert Sphinx2026h2", operator: "DigiCert" },
  { logId: "252f94c22b29e96e9f411a72072b695c5b52ff97a90d2540bbfcdc51ec4dee0b", name: "Sectigo Mammoth2026h1", operator: "Sectigo" },
  { logId: "94b1c18ab0d057c47be0ac040e1f2cbc8dc375727bc951f20a526126863ba73c", name: "Sectigo Mammoth2026h2", operator: "Sectigo" },
  { logId: "566cd5a376be83dfe342b675c49c232498a769bac382cbab49a3877d9ab32d01", name: "Sectigo Sabre2026h1", operator: "Sectigo" },
  { logId: "1f56d1ab94704a41dd3feafdf4699355302c1431bfe61346089fffae795dcc2f", name: "Sectigo Sabre2026h2", operator: "Sectigo" },
  { logId: "74db9d58f7d47e9dfd787a162a991c18cf698da7c729918c9a18b0450dba44bc", name: "TrustAsia log2026a", operator: "TrustAsia" },
  { logId: "25b7efdea1130193ed93079770aa322a26620de35ac8aa7c75197de0b1a9e065", name: "TrustAsia log2026b", operator: "TrustAsia" },
];

import { createHash } from "node:crypto";

let LOG_MAP = new Map<string, KnownCtLog>(BUILTIN_LOGS.map((l) => [l.logId, l]));

/** Convert base64 log key to hex log_id (SHA-256 of the key bytes) */
function base64KeyToHexId(b64Key: string): string {
  const keyBytes = Buffer.from(b64Key, "base64");
  return createHash("sha256").update(keyBytes).digest("hex");
}

/** Load the full log list from Google's official endpoint. Called once at startup. */
async function loadGoogleLogList(): Promise<void> {
  try {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 10000);
    const res = await fetch("https://www.gstatic.com/ct/log_list/v3/log_list.json", {
      signal: c.signal,
      headers: { "User-Agent": "dn-sec/1.0" },
    });
    clearTimeout(t);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json() as {
      operators: { name: string; email: string[]; logs: { description: string; log_id: string; key: string; url: string }[]; tiled_logs?: { description: string; log_id: string; key: string }[] }[];
    };

    const newMap = new Map<string, KnownCtLog>();
    for (const l of BUILTIN_LOGS) newMap.set(l.logId, l);

    for (const op of data.operators ?? []) {
      for (const log of [...(op.logs ?? []), ...(op.tiled_logs ?? [])]) {
        // log_id is base64-encoded SHA-256 of the log's public key
        const hexId = Buffer.from(log.log_id, "base64").toString("hex");
        newMap.set(hexId, { logId: hexId, name: log.description, operator: op.name });
      }
    }
    LOG_MAP = newMap;
    console.log(`[ct-logs] Loaded ${newMap.size} CT logs from Google (was ${BUILTIN_LOGS.length} built-in)`);
  } catch (e: any) {
    console.warn(`[ct-logs] Failed to load Google log list: ${e?.message || e}. Using ${BUILTIN_LOGS.length} built-in logs.`);
  }
}

/** Resolves when the Google log list has been loaded (or failed gracefully). Await before serving. */
export const ctLogsReady: Promise<void> = loadGoogleLogList();

/** Find a known CT log by its hex-encoded log ID. Returns null if unknown. */
export function findLogByLogId(logIdHex: string): KnownCtLog | null {
  return LOG_MAP.get(logIdHex.toLowerCase()) ?? null;
}

/** Get the set of unique operators for a list of hex log IDs. Unknown IDs are ignored. */
export function getUniqueOperators(logIds: string[]): Set<string> {
  const ops = new Set<string>();
  for (const id of logIds) {
    const log = findLogByLogId(id);
    if (log) ops.add(log.operator);
  }
  return ops;
}
