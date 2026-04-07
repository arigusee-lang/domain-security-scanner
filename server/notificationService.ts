import type { DiffChange, NotificationLogRow } from "./types.js";
import type Database from "better-sqlite3";
import crypto from "node:crypto";

/**
 * Payload for sending a change notification email.
 */
export interface NotificationPayload {
  userId: string;
  to: string;
  domain: string;
  scanId: string | null;
  scheduledId: string | null;
  scanDate: string;
  currentGrade: string;
  previousGrade: string | null;
  scoreDelta: number;
  changes: DiffChange[];
  reportUrl: string;
}

const DAILY_EMAIL_LIMIT = 10;

/**
 * Count how many emails were sent today for a given user.
 */
function countTodayEmails(db: Database.Database, userId: string): number {
  const todayStart = new Date();
  todayStart.setUTCHours(0, 0, 0, 0);
  const row = db
    .prepare(
      `SELECT COUNT(*) as cnt FROM notification_log
       WHERE user_id = ? AND type = 'email' AND status = 'sent'
         AND created_at >= ?`
    )
    .get(userId, todayStart.toISOString()) as { cnt: number } | undefined;
  return row?.cnt ?? 0;
}

/**
 * Build the email subject line.
 */
function buildSubject(domain: string, changes: DiffChange[]): string {
  const issueCount = changes.filter(
    (c) => c.severity === "critical" || c.severity === "warn"
  ).length;
  if (issueCount > 0) {
    return `[Domain Security] ⚠️ ${issueCount} new issue${issueCount > 1 ? "s" : ""} detected on ${domain}`;
  }
  return `[Domain Security] Changes detected on ${domain}`;
}

/**
 * Build HTML email body.
 */
function buildHtmlBody(payload: NotificationPayload, unsubscribeUrl: string): string {
  const { domain, scanDate, currentGrade, previousGrade, scoreDelta, changes, reportUrl } =
    payload;

  const gradeInfo = previousGrade
    ? `Grade: <strong>${currentGrade}</strong> (was ${previousGrade}) — Score delta: ${scoreDelta > 0 ? "+" : ""}${scoreDelta}`
    : `Grade: <strong>${currentGrade}</strong>`;

  const newIssues = changes.filter(
    (c) => c.severity === "critical" || c.severity === "warn"
  );
  const resolved = changes.filter((c) => c.severity === "resolved");

  let issuesHtml = "";
  if (newIssues.length > 0) {
    const items = newIssues.map((c) => `<li>${escapeHtml(c.message)}</li>`).join("\n");
    issuesHtml = `<h3>⚠️ New Issues (${newIssues.length}):</h3>\n<ul>${items}</ul>`;
  }

  let resolvedHtml = "";
  if (resolved.length > 0) {
    const items = resolved.map((c) => `<li>${escapeHtml(c.message)}</li>`).join("\n");
    resolvedHtml = `<h3>✅ Resolved (${resolved.length}):</h3>\n<ul>${items}</ul>`;
  }

  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2>Domain Security Report — ${escapeHtml(domain)}</h2>
  <p>Scan date: ${escapeHtml(scanDate)}</p>
  <p>${gradeInfo}</p>
  ${issuesHtml}
  ${resolvedHtml}
  <p style="margin-top: 20px;">
    <a href="${escapeHtml(reportUrl)}" style="background: #2563eb; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 6px;">View Full Report</a>
  </p>
  <hr style="margin-top: 30px; border: none; border-top: 1px solid #e5e7eb;">
  <p style="font-size: 12px; color: #6b7280;">
    You received this because you have scheduled scans enabled.
    <a href="${escapeHtml(unsubscribeUrl)}">Unsubscribe / Manage notifications</a>
  </p>
</body>
</html>`;
}

/**
 * Build plain text email body.
 */
function buildTextBody(payload: NotificationPayload, unsubscribeUrl: string): string {
  const { domain, scanDate, currentGrade, previousGrade, scoreDelta, changes, reportUrl } =
    payload;

  const gradeInfo = previousGrade
    ? `Grade: ${currentGrade} (was ${previousGrade}) — Score delta: ${scoreDelta > 0 ? "+" : ""}${scoreDelta}`
    : `Grade: ${currentGrade}`;

  const newIssues = changes.filter(
    (c) => c.severity === "critical" || c.severity === "warn"
  );
  const resolved = changes.filter((c) => c.severity === "resolved");

  let text = `Domain Security Report — ${domain}\n`;
  text += `Scan date: ${scanDate}\n`;
  text += `${gradeInfo}\n\n`;

  if (newIssues.length > 0) {
    text += `⚠️ New Issues (${newIssues.length}):\n`;
    for (const c of newIssues) {
      text += `  • ${c.message}\n`;
    }
    text += "\n";
  }

  if (resolved.length > 0) {
    text += `✅ Resolved (${resolved.length}):\n`;
    for (const c of resolved) {
      text += `  • ${c.message}\n`;
    }
    text += "\n";
  }

  text += `View Full Report: ${reportUrl}\n\n`;
  text += `---\nUnsubscribe / Manage notifications: ${unsubscribeUrl}\n`;

  return text;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Insert a notification log entry.
 */
function insertNotificationLog(
  db: Database.Database,
  entry: Omit<NotificationLogRow, "created_at">
): void {
  db.prepare(
    `INSERT INTO notification_log (id, user_id, scan_id, scheduled_id, type, status, payload_json, error, sent_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    entry.id,
    entry.user_id,
    entry.scan_id,
    entry.scheduled_id,
    entry.type,
    entry.status,
    entry.payload_json,
    entry.error,
    entry.sent_at
  );
}

/**
 * Send a change notification email via Resend REST API.
 *
 * - Aggregates all changes for one domain into a single email
 * - Enforces 10 emails/day per user limit
 * - Logs each send to notification_log table
 * - Gracefully skips if RESEND_API_KEY is not configured
 */
export async function sendChangeNotification(
  payload: NotificationPayload,
  db: Database.Database
): Promise<void> {
  const logId = crypto.randomUUID();
  const apiKey = process.env.RESEND_API_KEY;
  const fromEmail = process.env.FROM_EMAIL || "notifications@domainsecuritychecker.com";
  const appUrl = process.env.APP_URL || "http://localhost:5173";

  // Check if API key is configured
  if (!apiKey) {
    console.warn("[notification] RESEND_API_KEY not set — skipping email send");
    insertNotificationLog(db, {
      id: logId,
      user_id: payload.userId,
      scan_id: payload.scanId,
      scheduled_id: payload.scheduledId,
      type: "email",
      status: "failed",
      payload_json: JSON.stringify({ to: payload.to, domain: payload.domain }),
      error: "RESEND_API_KEY not configured",
      sent_at: null,
    });
    return;
  }

  // Enforce daily limit
  const todayCount = countTodayEmails(db, payload.userId);
  if (todayCount >= DAILY_EMAIL_LIMIT) {
    console.warn(
      `[notification] Daily email limit (${DAILY_EMAIL_LIMIT}) reached for user ${payload.userId}`
    );
    insertNotificationLog(db, {
      id: logId,
      user_id: payload.userId,
      scan_id: payload.scanId,
      scheduled_id: payload.scheduledId,
      type: "email",
      status: "failed",
      payload_json: JSON.stringify({ to: payload.to, domain: payload.domain }),
      error: "Daily email limit exceeded",
      sent_at: null,
    });
    return;
  }

  // Log as pending
  insertNotificationLog(db, {
    id: logId,
    user_id: payload.userId,
    scan_id: payload.scanId,
    scheduled_id: payload.scheduledId,
    type: "email",
    status: "pending",
    payload_json: JSON.stringify({
      to: payload.to,
      domain: payload.domain,
      subject: buildSubject(payload.domain, payload.changes),
    }),
    error: null,
    sent_at: null,
  });

  const unsubscribeUrl = `${appUrl}/#/dashboard?tab=settings`;
  const subject = buildSubject(payload.domain, payload.changes);
  const html = buildHtmlBody(payload, unsubscribeUrl);
  const text = buildTextBody(payload, unsubscribeUrl);

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [payload.to],
        subject,
        html,
        text,
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Resend API error ${response.status}: ${errorBody}`);
    }

    // Update log to sent
    db.prepare(
      `UPDATE notification_log SET status = 'sent', sent_at = datetime('now') WHERE id = ?`
    ).run(logId);
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    console.error(`[notification] Failed to send email to ${payload.to}:`, errorMsg);

    // Update log to failed
    db.prepare(
      `UPDATE notification_log SET status = 'failed', error = ? WHERE id = ?`
    ).run(errorMsg, logId);
  }
}
