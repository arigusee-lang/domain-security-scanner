const API = "/api/domain-check";

async function get(path: string, domain: string, noCache: boolean, timeoutMs: number): Promise<any> {
  const nc = noCache ? "&noCache=1" : "";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${API}/${path}?domain=${encodeURIComponent(domain)}${nc}`, { signal: controller.signal });
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      throw new Error(data?.message || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err: any) {
    if (err.name === "AbortError") return null; // timeout — section just won't show
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export interface CheckGroup {
  key: string;
  promise: Promise<any>;
}

/** Fire all check groups in parallel, call onResult as each completes */
export function runAllChecks(
  domain: string,
  noCache: boolean,
  onResult: (key: string, data: any) => void,
  onError: (key: string, err: any) => void,
): Promise<void> {
  const groups: CheckGroup[] = [
    { key: "dns", promise: get("dns", domain, noCache, 12000) },
    { key: "web", promise: get("web", domain, noCache, 20000) },
    { key: "expiry", promise: get("expiry", domain, noCache, 18000) },
    { key: "ct", promise: get("ct", domain, noCache, 25000) },
    { key: "redirects", promise: get("redirects", domain, noCache, 18000) },
    { key: "seo", promise: get("seo", domain, noCache, 18000) },
    { key: "reputation", promise: get("reputation", domain, noCache, 12000) },
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
