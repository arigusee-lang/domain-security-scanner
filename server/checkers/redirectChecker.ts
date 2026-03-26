import type { CheckStatus } from "../types.js";

export interface RedirectCheckItem {
  check: string;
  status: CheckStatus;
  detail: string;
}

export interface RedirectResult {
  status: CheckStatus;
  httpsRedirect: boolean;
  wwwBehavior: string | null;
  items: RedirectCheckItem[];
  error?: string;
}

async function checkUrl(url: string, timeout: number): Promise<{ status: number; location: string | null } | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(url, {
      method: "HEAD",
      redirect: "manual",
      signal: controller.signal,
      headers: { "User-Agent": "security-txt-validator/1.0" },
    });
    clearTimeout(timer);
    return { status: res.status, location: res.headers.get("location") };
  } catch {
    return null;
  }
}

export async function checkRedirects(domain: string, timeout: number = 5000): Promise<RedirectResult> {
  const items: RedirectCheckItem[] = [];
  let httpsRedirect = false;
  let wwwBehavior: string | null = null;

  // Check HTTP → HTTPS redirect
  const httpResult = await checkUrl(`http://${domain}/`, timeout);
  if (httpResult) {
    if (httpResult.status >= 300 && httpResult.status < 400 && httpResult.location) {
      if (httpResult.location.startsWith("https://")) {
        httpsRedirect = true;
        items.push({ check: "HTTP → HTTPS redirect", status: "pass", detail: `Redirects to ${httpResult.location}` });
      } else {
        items.push({ check: "HTTP → HTTPS redirect", status: "warn", detail: `Redirects to ${httpResult.location} (not HTTPS)` });
      }
    } else if (httpResult.status === 200) {
      items.push({ check: "HTTP → HTTPS redirect", status: "fail", detail: "HTTP serves content without redirecting to HTTPS" });
    } else {
      items.push({ check: "HTTP → HTTPS redirect", status: "info", detail: `HTTP returned status ${httpResult.status}` });
    }
  } else {
    items.push({ check: "HTTP → HTTPS redirect", status: "info", detail: "Could not connect via HTTP" });
  }

  // Check www vs non-www consistency
  const hasWww = domain.startsWith("www.");
  const altDomain = hasWww ? domain.slice(4) : `www.${domain}`;
  const altResult = await checkUrl(`https://${altDomain}/`, timeout);
  if (altResult) {
    if (altResult.status >= 300 && altResult.status < 400 && altResult.location) {
      wwwBehavior = `${altDomain} → ${altResult.location}`;
      items.push({ check: "www consistency", status: "pass", detail: `${altDomain} redirects properly` });
    } else if (altResult.status === 200) {
      wwwBehavior = `Both ${domain} and ${altDomain} serve content`;
      items.push({ check: "www consistency", status: "warn", detail: `Both ${domain} and ${altDomain} serve content — consider redirecting one to the other` });
    } else {
      wwwBehavior = `${altDomain} returned ${altResult.status}`;
      items.push({ check: "www consistency", status: "info", detail: `${altDomain} returned status ${altResult.status}` });
    }
  } else {
    items.push({ check: "www consistency", status: "info", detail: `Could not connect to ${altDomain}` });
  }

  const overall: CheckStatus = items.some(i => i.status === "fail") ? "fail"
    : items.some(i => i.status === "warn") ? "warn" : "pass";

  return { status: overall, httpsRedirect, wwwBehavior, items };
}
