/**
 * GET /verify/:scanId — public report verification page.
 *
 * Renders a minimal self-contained HTML page so the recipient of an exported
 * report can confirm that the scan exists in our database and that the domain,
 * date, and score they're looking at match what we have on file.
 *
 * No auth required — knowing the scanId (a random UUID) is sufficient. The
 * only information disclosed is what the report itself already contains.
 */

import { Router, type Request, type Response } from "express";
import type Database from "better-sqlite3";

interface VerifyDeps {
  db: Database.Database;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function esc(s: unknown): string {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPE_MAP[c]);
}

function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return (
    d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" }) +
    " at " +
    d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );
}

const BASE_STYLES = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    background: #0a0a0f; color: #e8e8ed;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 2rem 1rem; line-height: 1.5;
  }
  .verify-card {
    background: #14141f;
    border: 1px solid #2a2a3a;
    border-radius: 12px;
    padding: 1.75rem 1.75rem 1.5rem;
    max-width: 460px;
    width: 100%;
  }
  .status-row { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 1.25rem; }
  .status-icon { width: 28px; height: 28px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .status-icon.ok { background: rgba(0, 212, 170, 0.15); color: #00d4aa; }
  .status-icon.bad { background: rgba(255, 77, 106, 0.15); color: #ff4d6a; }
  .status-icon svg { width: 16px; height: 16px; }
  .status-title { font-size: 1.05rem; font-weight: 700; }
  .status-title.ok { color: #00d4aa; }
  .status-title.bad { color: #ff4d6a; }
  .kv-grid { display: flex; flex-direction: column; gap: 0.55rem; }
  .kv-row { display: flex; gap: 0.9rem; font-size: 0.85rem; align-items: baseline; }
  .kv-label { color: #8888a0; min-width: 96px; font-size: 0.75rem; }
  .kv-value { color: #e8e8ed; word-break: break-word; }
  .kv-value.domain { font-family: 'SF Mono', monospace; color: #00d4aa; }
  .kv-value.score { font-family: 'SF Mono', monospace; font-weight: 600; }
  .kv-value.score.bad { color: #ff4d6a; }
  .kv-value.score.warn { color: #ffb84d; }
  .kv-value.score.good { color: #00d4aa; }
  .blurb {
    margin-top: 1.25rem;
    padding-top: 1rem;
    border-top: 1px solid #2a2a3a;
    font-size: 0.78rem;
    color: #8888a0;
    line-height: 1.55;
  }
  .scan-id { font-family: 'SF Mono', monospace; font-size: 0.7rem; color: #5a6072; word-break: break-all; }
  a { color: #4da6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
`;

function scoreClass(score: number | null): string {
  if (score === null) return "";
  if (score >= 90) return "good";
  if (score >= 70) return "warn";
  return "bad";
}

function renderFoundPage(scan: { id: string; domain: string; score: number | null; created_at: string; completed_at: string | null }): string {
  const scanDate = scan.completed_at || scan.created_at;
  const scoreVal = scan.score;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Verified scan — ${esc(scan.domain)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<style>${BASE_STYLES}</style>
</head>
<body>
  <div class="verify-card">
    <div class="status-row">
      <span class="status-icon ok" aria-hidden="true">
        <svg viewBox="0 0 16 16" fill="none"><path d="M3 8.5L6.5 12L13 5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </span>
      <span class="status-title ok">Verified scan</span>
    </div>

    <div class="kv-grid">
      <div class="kv-row"><span class="kv-label">Domain</span><span class="kv-value domain">${esc(scan.domain)}</span></div>
      <div class="kv-row"><span class="kv-label">Scanned</span><span class="kv-value">${esc(formatDateTime(scanDate))}</span></div>
      <div class="kv-row"><span class="kv-label">Score</span><span class="kv-value score ${scoreClass(scoreVal)}">${scoreVal !== null ? `${Math.ceil(scoreVal)}/100` : "—"}</span></div>
    </div>

    <p class="blurb">
      This scan exists in our database. The domain, date, and score above should match the report you received.
      If they don't, the report may have been altered.
    </p>
    <p class="scan-id">ID: ${esc(scan.id)}</p>
  </div>
</body>
</html>`;
}

function renderNotFoundPage(scanId: string, reason: "invalid" | "missing"): string {
  const detail = reason === "invalid"
    ? "The verification link doesn't look like a valid scan ID."
    : "We don't have a record of this scan. The link may be from a different deployment, the scan was deleted, or the report was forged.";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scan not found</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<style>${BASE_STYLES}</style>
</head>
<body>
  <div class="verify-card">
    <div class="status-row">
      <span class="status-icon bad" aria-hidden="true">
        <svg viewBox="0 0 16 16" fill="none"><path d="M4 4L12 12M12 4L4 12" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
      </span>
      <span class="status-title bad">Not found</span>
    </div>
    <p class="blurb">${esc(detail)}</p>
    ${reason === "missing" ? `<p class="scan-id">Looked up ID: ${esc(scanId)}</p>` : ""}
  </div>
</body>
</html>`;
}

export function createVerifyRoutes({ db }: VerifyDeps): Router {
  const router = Router();

  router.get("/:scanId", (req: Request, res: Response) => {
    const scanId = req.params.scanId;

    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Type", "text/html; charset=utf-8");

    if (!UUID_RE.test(scanId)) {
      res.status(400).send(renderNotFoundPage(scanId, "invalid"));
      return;
    }

    const row = db
      .prepare(
        "SELECT id, domain, score, created_at, completed_at FROM scans WHERE id = ?",
      )
      .get(scanId) as
      | { id: string; domain: string; score: number | null; created_at: string; completed_at: string | null }
      | undefined;

    if (!row) {
      res.status(404).send(renderNotFoundPage(scanId, "missing"));
      return;
    }

    res.send(renderFoundPage(row));
  });

  return router;
}
