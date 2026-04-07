const API = "/api/domain-check";

async function get(
  path: string,
  domain: string,
  noCache: boolean,
  timeoutMs: number,
  scanId?: string,
  extra?: string,
): Promise<any> {
  const nc = noCache ? "&noCache=1" : "";
  const sid = scanId ? `&scanId=${scanId}` : "";
  const ex = extra || "";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(
      `${API}/${path}?domain=${encodeURIComponent(domain)}${nc}${sid}${ex}`,
      { signal: controller.signal, credentials: "include" },
    );
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      throw new Error(data?.message || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err: any) {
    if (err.name === "AbortError") return null;
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export interface CheckGroup {
  key: string;
  promise: Promise<any>;
}

export function runAllChecks(
  domain: string,
  noCache: boolean,
  onResult: (key: string, data: any) => void,
  onError: (key: string, err: any) => void,
  scanId?: string,
  crtShFirst?: boolean,
): Promise<void> {
  const ctExtra = crtShFirst ? "&crtShFirst=1" : "";
  const groups: CheckGroup[] = [
    { key: "dns", promise: get("dns", domain, noCache, 20000, scanId) },
    { key: "web", promise: get("web", domain, noCache, 30000, scanId) },
    { key: "expiry", promise: get("expiry", domain, noCache, 18000, scanId) },
    { key: "ct", promise: get("ct", domain, noCache, 45000, scanId, ctExtra) },
    { key: "redirects", promise: get("redirects", domain, noCache, 18000, scanId) },
    { key: "seo", promise: get("seo", domain, noCache, 18000, scanId) },
    { key: "reputation", promise: get("reputation", domain, noCache, 12000, scanId) },
  ];

  const all = groups.map(g =>
    g.promise
      .then(data => {
        if (data) onResult(g.key, data);
        else onError(g.key, new Error("Request timed out"));
      })
      .catch(err => onError(g.key, err))
  );

  return Promise.allSettled(all).then(() => {});
}
