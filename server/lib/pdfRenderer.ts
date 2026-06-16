/**
 * Renders HTML to PDF using a long-lived Puppeteer browser instance.
 *
 * The browser is launched lazily on the first PDF request and reused for
 * subsequent requests so we don't pay the Chromium startup cost on every
 * export. Pages are created and closed per-request.
 */

import type { Browser } from "puppeteer";

let browserPromise: Promise<Browser> | null = null;

async function getBrowser(): Promise<Browser> {
  if (!browserPromise) {
    browserPromise = (async () => {
      const puppeteer = await import("puppeteer");
      return puppeteer.default.launch({
        headless: true,
        // --no-sandbox is required for many container/Cloud-Run environments
        // where the user namespace isn't available. Safe here because the only
        // input is the HTML we generated ourselves.
        args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
      });
    })();
    // If launch fails, allow a retry on the next call.
    browserPromise.catch(() => {
      browserPromise = null;
    });
  }
  return browserPromise;
}

export async function htmlToPdf(html: string): Promise<Buffer> {
  const browser = await getBrowser();
  const page = await browser.newPage();
  try {
    await page.setContent(html, { waitUntil: "networkidle0" });
    // Margins are controlled by the @page rule in the report stylesheet so the
    // CSS template owns the entire layout in one place.
    const pdf = await page.pdf({
      format: "A4",
      printBackground: true,
      preferCSSPageSize: true,
    });
    return Buffer.from(pdf);
  } finally {
    await page.close().catch(() => {});
  }
}

export async function shutdownPdfRenderer(): Promise<void> {
  if (browserPromise) {
    try {
      const b = await browserPromise;
      await b.close();
    } catch {
      // best-effort shutdown
    }
    browserPromise = null;
  }
}
