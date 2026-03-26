import type { CheckStatus } from "../types.js";

export interface SeoCheckItem {
  check: string;
  status: CheckStatus;
  detail: string;
}

export interface SeoResult {
  status: CheckStatus;
  items: SeoCheckItem[];
  error?: string;
}

async function fetchText(url: string, timeout: number): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "security-txt-validator/1.0" },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

export async function checkSeo(domain: string, timeout: number = 5000): Promise<SeoResult> {
  const items: SeoCheckItem[] = [];

  // Fetch homepage, robots.txt, sitemap.xml in parallel
  const [homepage, robotsTxt, sitemapXml] = await Promise.all([
    fetchText(`https://${domain}/`, timeout),
    fetchText(`https://${domain}/robots.txt`, timeout),
    fetchText(`https://${domain}/sitemap.xml`, timeout),
  ]);

  // Check homepage meta tags
  if (homepage) {
    // Title
    const titleMatch = homepage.match(/<title[^>]*>([^<]*)<\/title>/i);
    if (titleMatch && titleMatch[1].trim()) {
      const title = titleMatch[1].trim();
      if (title.length < 10) {
        items.push({ check: "Page title", status: "warn", detail: `Title too short (${title.length} chars): "${title}"` });
      } else if (title.length > 70) {
        items.push({ check: "Page title", status: "warn", detail: `Title may be truncated in search results (${title.length} chars)` });
      } else {
        items.push({ check: "Page title", status: "pass", detail: `"${title}" (${title.length} chars)` });
      }
    } else {
      items.push({ check: "Page title", status: "fail", detail: "No <title> tag found" });
    }

    // Meta description
    const descMatch = homepage.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i)
      || homepage.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i);
    if (descMatch && descMatch[1].trim()) {
      const desc = descMatch[1].trim();
      if (desc.length < 50) {
        items.push({ check: "Meta description", status: "warn", detail: `Too short (${desc.length} chars)` });
      } else if (desc.length > 160) {
        items.push({ check: "Meta description", status: "warn", detail: `May be truncated (${desc.length} chars)` });
      } else {
        items.push({ check: "Meta description", status: "pass", detail: `Present (${desc.length} chars)` });
      }
    } else {
      items.push({ check: "Meta description", status: "warn", detail: "No meta description found" });
    }

    // Canonical
    const canonicalMatch = homepage.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i);
    items.push(canonicalMatch
      ? { check: "Canonical URL", status: "pass", detail: canonicalMatch[1] }
      : { check: "Canonical URL", status: "warn", detail: "No canonical link tag found" }
    );

    // Viewport
    const viewportMatch = homepage.match(/<meta[^>]+name=["']viewport["']/i);
    items.push(viewportMatch
      ? { check: "Viewport meta", status: "pass", detail: "Mobile viewport configured" }
      : { check: "Viewport meta", status: "warn", detail: "No viewport meta tag — may not be mobile-friendly" }
    );
  } else {
    items.push({ check: "Homepage", status: "info", detail: "Could not fetch homepage" });
  }

  // robots.txt
  if (robotsTxt) {
    const hasSitemap = /sitemap:/i.test(robotsTxt);
    items.push({ check: "robots.txt", status: "pass", detail: hasSitemap ? "Present with Sitemap directive" : "Present" });
  } else {
    items.push({ check: "robots.txt", status: "warn", detail: "No robots.txt found" });
  }

  // sitemap.xml
  if (sitemapXml && sitemapXml.includes("<urlset") || sitemapXml?.includes("<sitemapindex")) {
    items.push({ check: "sitemap.xml", status: "pass", detail: "XML sitemap found" });
  } else {
    items.push({ check: "sitemap.xml", status: "warn", detail: "No valid sitemap.xml found" });
  }

  const overall: CheckStatus = items.some(i => i.status === "fail") ? "fail"
    : items.some(i => i.status === "warn") ? "warn" : "pass";

  return { status: overall, items };
}
