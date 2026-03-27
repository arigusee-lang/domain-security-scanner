import type { CheckStatus } from "../types.js";

export interface SeoCheckItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface SeoResult {
  status: CheckStatus;
  items: SeoCheckItem[];
  error?: string;
}

const GOOGLE_SEO = "https://developers.google.com/search/docs";

async function fetchText(url: string, timeout: number): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(url, { signal: controller.signal, headers: { "User-Agent": "security-txt-validator/1.0" } });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.text();
  } catch { return null; }
}

export async function checkSeo(domain: string, timeout: number = 5000): Promise<SeoResult> {
  const items: SeoCheckItem[] = [];

  const [homepage, robotsTxt, sitemapXml] = await Promise.all([
    fetchText(`https://${domain}/`, timeout),
    fetchText(`https://${domain}/robots.txt`, timeout),
    fetchText(`https://${domain}/sitemap.xml`, timeout),
  ]);

  if (homepage) {
    const titleMatch = homepage.match(/<title[^>]*>([^<]*)<\/title>/i);
    if (titleMatch && titleMatch[1].trim()) {
      const title = titleMatch[1].trim();
      if (title.length < 10) {
        items.push({ check: "Page title", status: "warn", detail: `Title too short (${title.length} chars): "${title}"`, ref: GOOGLE_SEO + "/appearance/title-link" });
      } else if (title.length > 70) {
        items.push({ check: "Page title", status: "warn", detail: `Title may be truncated in search results (${title.length} chars)`, ref: GOOGLE_SEO + "/appearance/title-link" });
      } else {
        items.push({ check: "Page title", status: "pass", detail: `"${title}" (${title.length} chars)`, ref: GOOGLE_SEO + "/appearance/title-link" });
      }
    } else {
      items.push({ check: "Page title", status: "fail", detail: "No <title> tag found", ref: GOOGLE_SEO + "/appearance/title-link" });
    }

    const descMatch = homepage.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i)
      || homepage.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i);
    if (descMatch && descMatch[1].trim()) {
      const desc = descMatch[1].trim();
      if (desc.length < 50) items.push({ check: "Meta description", status: "warn", detail: `Too short (${desc.length} chars)`, ref: GOOGLE_SEO + "/appearance/snippet" });
      else if (desc.length > 160) items.push({ check: "Meta description", status: "warn", detail: `May be truncated (${desc.length} chars)`, ref: GOOGLE_SEO + "/appearance/snippet" });
      else items.push({ check: "Meta description", status: "pass", detail: `Present (${desc.length} chars)`, ref: GOOGLE_SEO + "/appearance/snippet" });
    } else {
      items.push({ check: "Meta description", status: "warn", detail: "No meta description found", ref: GOOGLE_SEO + "/appearance/snippet" });
    }

    const canonicalMatch = homepage.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i);
    items.push(canonicalMatch
      ? { check: "Canonical URL", status: "pass", detail: canonicalMatch[1], ref: GOOGLE_SEO + "/crawling-indexing/consolidate-duplicate-urls" }
      : { check: "Canonical URL", status: "warn", detail: "No canonical link tag found", ref: GOOGLE_SEO + "/crawling-indexing/consolidate-duplicate-urls" }
    );

    const viewportMatch = homepage.match(/<meta[^>]+name=["']viewport["']/i);
    items.push(viewportMatch
      ? { check: "Viewport meta", status: "pass", detail: "Mobile viewport configured", ref: "https://developer.mozilla.org/en-US/docs/Web/HTML/Viewport_meta_tag" }
      : { check: "Viewport meta", status: "warn", detail: "No viewport meta tag — may not be mobile-friendly", ref: "https://developer.mozilla.org/en-US/docs/Web/HTML/Viewport_meta_tag" }
    );
  } else {
    items.push({ check: "Homepage", status: "info", detail: "Could not fetch homepage" });
  }

  items.push(robotsTxt
    ? { check: "robots.txt", status: "pass", detail: /sitemap:/i.test(robotsTxt) ? "Present with Sitemap directive" : "Present", ref: GOOGLE_SEO + "/crawling-indexing/robots/intro" }
    : { check: "robots.txt", status: "warn", detail: "No robots.txt found", ref: GOOGLE_SEO + "/crawling-indexing/robots/intro" }
  );

  if (sitemapXml && (sitemapXml.includes("<urlset") || sitemapXml.includes("<sitemapindex"))) {
    items.push({ check: "sitemap.xml", status: "pass", detail: "XML sitemap found", ref: GOOGLE_SEO + "/crawling-indexing/sitemaps/overview" });
  } else {
    items.push({ check: "sitemap.xml", status: "warn", detail: "No valid sitemap.xml found", ref: GOOGLE_SEO + "/crawling-indexing/sitemaps/overview" });
  }

  // Sort: fail first, then warn, then pass
  const order: Record<string, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
  items.sort((a, b) => (order[a.status] ?? 2) - (order[b.status] ?? 2));

  const overall: CheckStatus = items.some(i => i.status === "fail") ? "fail"
    : items.some(i => i.status === "warn") ? "warn" : "pass";

  return { status: overall, items };
}
