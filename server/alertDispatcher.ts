import type Database from "better-sqlite3";
import crypto from "node:crypto";
import type { AlertPayload, MonitorAlertRow, MonitorType, AlertSeverity } from "./monitoringTypes.js";
import { sendChangeNotification } from "./notificationService.js";
import { deliverWebhook } from "./webhookService.js";
import type { DiffChange, WebhookRow } from "./types.js";
import { createLogger } from "./lib/logger.js";

const log = createLogger("alert-dispatcher");

const AGGREGATION_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const SEVERITY_LEVEL: Record<string, number> = { info: 0, warn: 1, critical: 2, resolved: 1 };

/**
 * AlertDispatcher uses the `monitor_alerts` table (notified=0 rows) as the
 * source of truth for pending alerts. Memory only holds aggregation timers.
 * Restart-safe: `restorePending()` re-arms timers from DB on server start.
 */
export class AlertDispatcher {
  private aggregationTimers = new Map<string, NodeJS.Timeout>();

  constructor(private db: Database.Database) {}

  enqueue(alert: AlertPayload): void {
    if (alert.severity === "critical") {
      this.sendImmediate(alert).catch(err =>
        log.error({ err }, "immediate send failed")
      );
      return;
    }

    const key = `${alert.userId}:${alert.domain}`;
    if (!this.aggregationTimers.has(key)) {
      this.scheduleFlush(key, alert.userId, alert.domain, AGGREGATION_WINDOW_MS);
    }
    // Alert is already persisted in monitor_alerts (notified=0) — flush will load it.
  }

  /**
   * Restore aggregation timers after a restart. For each (user, domain)
   * group with pending non-critical alerts, schedule a flush; if the oldest
   * pending alert is already past the aggregation window, flush immediately.
   * Critical alerts that were never sent (e.g. server crashed mid-send) are
   * also re-dispatched.
   */
  async restorePending(): Promise<void> {
    // Non-critical: group by (user, domain), compute elapsed_ms from oldest pending alert
    const groups = this.db.prepare(`
      SELECT ma.user_id, md.domain,
        CAST((julianday('now') - julianday(MIN(ma.created_at))) * 86400000 AS INTEGER) AS elapsed_ms
      FROM monitor_alerts ma
      JOIN monitored_domains md ON md.id = ma.domain_id
      WHERE ma.notified = 0 AND ma.severity != 'critical'
      GROUP BY ma.user_id, md.domain
    `).all() as Array<{ user_id: string; domain: string; elapsed_ms: number }>;

    for (const g of groups) {
      const remaining = Math.max(0, AGGREGATION_WINDOW_MS - g.elapsed_ms);
      const key = `${g.user_id}:${g.domain}`;
      if (remaining === 0) {
        this.flush(g.user_id, g.domain).catch(err =>
          log.error({ err }, "restored flush failed")
        );
      } else {
        this.scheduleFlush(key, g.user_id, g.domain, remaining);
      }
    }

    // Critical alerts that never got notified — fire each one immediately.
    const criticalRows = this.db.prepare(`
      SELECT ma.*, md.domain FROM monitor_alerts ma
      JOIN monitored_domains md ON md.id = ma.domain_id
      WHERE ma.notified = 0 AND ma.severity = 'critical'
    `).all() as Array<MonitorAlertRow & { domain: string }>;

    for (const row of criticalRows) {
      const alert = this.rowToPayload(row);
      this.sendImmediate(alert).catch(err =>
        log.error({ err }, "restored immediate failed")
      );
    }

    if (groups.length > 0 || criticalRows.length > 0) {
      log.info(
        { aggregationTimers: groups.length, pendingCritical: criticalRows.length },
        "restored pending alerts"
      );
    }
  }

  /** Cancel all pending timers (e.g. for graceful shutdown or tests). */
  shutdown(): void {
    for (const timer of this.aggregationTimers.values()) {
      clearTimeout(timer);
    }
    this.aggregationTimers.clear();
  }

  private scheduleFlush(key: string, userId: string, domain: string, delayMs: number): void {
    const timer = setTimeout(() => {
      this.aggregationTimers.delete(key);
      this.flush(userId, domain).catch(err =>
        log.error({ err }, "flush failed")
      );
    }, delayMs);
    this.aggregationTimers.set(key, timer);
  }

  private async flush(userId: string, domain: string): Promise<void> {
    const rows = this.db.prepare(`
      SELECT ma.*, md.domain FROM monitor_alerts ma
      JOIN monitored_domains md ON md.id = ma.domain_id
      WHERE ma.user_id = ? AND md.domain = ? AND ma.notified = 0
      ORDER BY ma.created_at ASC
    `).all(userId, domain) as Array<MonitorAlertRow & { domain: string }>;

    if (rows.length === 0) return;
    const alerts = rows.map(r => this.rowToPayload(r));
    await this.deliverAlerts(userId, domain, alerts);
  }

  private async sendImmediate(alert: AlertPayload): Promise<void> {
    await this.deliverAlerts(alert.userId, alert.domain, [alert]);
  }

  private rowToPayload(row: MonitorAlertRow & { domain: string }): AlertPayload {
    return {
      alertId: row.id,
      userId: row.user_id,
      domainId: row.domain_id,
      domain: row.domain,
      monitorType: row.monitor_type as MonitorType,
      severity: row.severity as AlertSeverity,
      title: row.title,
      description: row.description,
      previousValue: row.previous_value ? safeParse(row.previous_value) : null,
      currentValue: row.current_value ? safeParse(row.current_value) : null,
    };
  }

  private async deliverAlerts(userId: string, domain: string, alerts: AlertPayload[]): Promise<void> {
    if (alerts.length === 0) return;

    // Check per-domain notification settings
    const domainSettings = this.db.prepare(
      "SELECT email_enabled, min_severity FROM monitored_domains WHERE id = ? AND user_id = ?"
    ).get(alerts[0].domainId, userId) as { email_enabled: number; min_severity: string } | undefined;

    const emailEnabled = domainSettings ? !!domainSettings.email_enabled : true;
    const minSeverity = domainSettings?.min_severity ?? "warn";
    const minLevel = SEVERITY_LEVEL[minSeverity] ?? 0;

    // Filter alerts by min severity
    const filteredAlerts = alerts.filter(a => (SEVERITY_LEVEL[a.severity] ?? 0) >= minLevel);

    // Send email if enabled and there are alerts to send
    if (emailEnabled && filteredAlerts.length > 0) {
      const user = this.db.prepare("SELECT email FROM users WHERE id = ?").get(userId) as { email: string } | undefined;
      if (user) {
        const changes: DiffChange[] = filteredAlerts.map(a => ({
          category: a.monitorType,
          type: "status_changed" as const,
          severity: a.severity as "critical" | "warn" | "resolved" | "info",
          previous: a.previousValue,
          current: a.currentValue,
          message: `${a.title}: ${a.description}`,
        }));

        const appUrl = process.env.APP_URL || "http://localhost:5173";
        try {
          await sendChangeNotification({
            userId,
            to: user.email,
            domain,
            scanId: null,
            scanDate: new Date().toISOString(),
            currentScore: 0,
            previousScore: null,
            scoreDelta: 0,
            changes,
            reportUrl: `${appUrl}/#/dashboard?tab=monitoring`,
          }, this.db);
        } catch (err) {
          log.error({ err, userId }, "email failed");
          this.db.prepare(
            `INSERT INTO notification_log (id, user_id, scan_id, type, status, error, created_at)
             VALUES (?, ?, NULL, 'email', 'failed', ?, datetime('now'))`
          ).run(crypto.randomUUID(), userId, String(err));
        }
      }
    }

    // Deliver webhooks
    const webhooks = this.db.prepare(
      "SELECT * FROM webhooks WHERE user_id = ? AND enabled = 1"
    ).all(userId) as WebhookRow[];

    for (const webhook of webhooks) {
      const events: string[] = safeParse(webhook.events_json) ?? [];
      if (events.includes("monitoring.alerts") || events.includes("*")) {
        try {
          await deliverWebhook(webhook, "monitoring.alerts", {
            event: "monitoring.alerts",
            timestamp: new Date().toISOString(),
            domain,
            alerts: alerts.map(a => ({
              id: a.alertId,
              monitorType: a.monitorType,
              severity: a.severity,
              title: a.title,
              description: a.description,
              previousValue: a.previousValue,
              currentValue: a.currentValue,
              createdAt: new Date().toISOString(),
            })),
          }, this.db);
        } catch (err) {
          log.error({ err, webhookId: webhook.id }, "webhook failed");
        }
      }
    }

    // Mark alerts as notified — single statement for the whole batch.
    const ids = alerts.map(a => a.alertId);
    const placeholders = ids.map(() => "?").join(",");
    this.db.prepare(`UPDATE monitor_alerts SET notified = 1 WHERE id IN (${placeholders})`).run(...ids);
  }
}

function safeParse(json: string): unknown {
  try { return JSON.parse(json); } catch { return null; }
}
