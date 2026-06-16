import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { Queue } from "bullmq";
import {
  type MonitorType, type UserPlan, type AlertSeverity,
  type AddDomainResult, type MonitoredDomainWithStatus,
  type DomainMonitorStatus, type AlertQueryOpts, type PaginatedAlerts,
  type HealthStatus, type MonitorRow, type MonitoredDomainRow,
  type MonitorAlertRow, type MonitorStateRow, type MonitoringSettingsRow,
  MONITOR_INTERVALS, ALL_MONITOR_TYPES,
  DOMAIN_LIMITS, JOB_PRIORITIES,
} from "./monitoringTypes.js";

export const QUEUE_NAME = "domain-monitoring";

export class DomainLimitError extends Error {
  currentLimit: number;
  currentCount: number;
  constructor(limit: number, count: number) {
    super(`Domain limit exceeded: ${count}/${limit}`);
    this.name = "DomainLimitError";
    this.currentLimit = limit;
    this.currentCount = count;
  }
}

export class MonitoringService {
  constructor(
    private db: Database.Database,
    private queue: Queue | null,
  ) {}

  async addDomain(userId: string, domain: string, opts?: { monitorTypes?: MonitorType[]; emailEnabled?: boolean; minSeverity?: string }): Promise<AddDomainResult> {
    const user = this.db.prepare("SELECT plan FROM users WHERE id = ?").get(userId) as { plan: string } | undefined;
    const plan = (user?.plan ?? "free") as UserPlan;

    const countRow = this.db.prepare(
      "SELECT COUNT(*) as cnt FROM monitored_domains WHERE user_id = ?"
    ).get(userId) as { cnt: number };

    if (countRow.cnt >= DOMAIN_LIMITS[plan]) {
      throw new DomainLimitError(DOMAIN_LIMITS[plan], countRow.cnt);
    }

    const domainId = crypto.randomUUID();
    const now = new Date().toISOString();
    const allowedTypes = ALL_MONITOR_TYPES;
    // Expand 'ssl' shorthand into ssl_expiry + ct_logs
    let requestedTypes = opts?.monitorTypes ?? [];
    if (requestedTypes.length > 0) {
      const expanded: string[] = [];
      for (const t of requestedTypes) {
        if (t === "ssl") { expanded.push("ssl_expiry", "ct_logs"); }
        else { expanded.push(t); }
      }
      requestedTypes = expanded;
    }
    const selectedTypes = requestedTypes.length > 0
      ? (requestedTypes as MonitorType[]).filter(t => allowedTypes.includes(t))
      : allowedTypes;
    const emailEnabled = opts?.emailEnabled ?? true;
    const minSeverity = opts?.minSeverity ?? "warn";

    this.db.prepare(
      "INSERT INTO monitored_domains (id, user_id, domain, enabled, email_enabled, min_severity, created_at) VALUES (?, ?, ?, 1, ?, ?, ?)"
    ).run(domainId, userId, domain, emailEnabled ? 1 : 0, minSeverity, now);

    const monitors: AddDomainResult["monitors"] = [];

    for (const type of selectedTypes) {
      const monitorId = crypto.randomUUID();
      const intervalMs = MONITOR_INTERVALS[type];
      this.db.prepare(
        `INSERT INTO monitors (id, domain_id, user_id, monitor_type, enabled, interval_ms, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`
      ).run(monitorId, domainId, userId, type, intervalMs, now);
      monitors.push({ id: monitorId, type, intervalMs });

      if (this.queue) {
        // Initial check: CAA/DNSSEC runs first (priority 0, no delay)
        // SSL and CT logs run after a short delay so CAA data is available
        const isCaaDnssec = type === "caa_dnssec";
        const needsCaa = type === "ssl_expiry" || type === "ct_logs";
        const initialDelay = isCaaDnssec ? 0 : needsCaa ? 5000 : 1000;
        const initialPriority = isCaaDnssec ? 0 : JOB_PRIORITIES[type];

        await this.queue.add("check", {
          monitorId, domainId, domain, monitorType: type, userId,
          isInitial: true,
        }, {
          jobId: `initial-${monitorId}`,
          priority: initialPriority,
          delay: initialDelay,
          attempts: 3,
          backoff: { type: "exponential", delay: 30_000 },
          removeOnComplete: { count: 10 },
          removeOnFail: { count: 10 },
        });
        // Repeatable job for subsequent checks
        await this.queue.add("check", {
          monitorId, domainId, domain, monitorType: type, userId,
        }, {
          repeat: { every: intervalMs },
          jobId: `monitor-${monitorId}`,
          priority: JOB_PRIORITIES[type],
          attempts: 3,
          backoff: { type: "exponential", delay: 30_000 },
          removeOnComplete: { count: 100 },
          removeOnFail: { count: 50 },
        });
      }
    }

    return { domainId, domain, monitors, createdAt: now };
  }

  async removeDomain(userId: string, domainId: string): Promise<void> {
    const monitors = this.db.prepare(
      "SELECT id FROM monitors WHERE domain_id = ? AND user_id = ?"
    ).all(domainId, userId) as Array<{ id: string }>;
    const monitorIds = new Set(monitors.map(m => m.id));

    if (this.queue && monitorIds.size > 0) {
      // Remove repeatable jobs
      const repeatableJobs = await this.queue.getRepeatableJobs();
      for (const job of repeatableJobs) {
        if (job.id && monitorIds.has(job.id.replace("monitor-", ""))) {
          try { await this.queue.removeRepeatableByKey(job.key); } catch { /* ignore */ }
        }
      }
      // Remove delayed/waiting jobs
      const delayed = await this.queue.getDelayed();
      for (const job of delayed) {
        const data = job.data as any;
        if (data?.monitorId && monitorIds.has(data.monitorId)) {
          try { await job.remove(); } catch { /* ignore */ }
        }
      }
      const waiting = await this.queue.getWaiting();
      for (const job of waiting) {
        const data = job.data as any;
        if (data?.monitorId && monitorIds.has(data.monitorId)) {
          try { await job.remove(); } catch { /* ignore */ }
        }
      }
    }

    this.db.prepare(
      "DELETE FROM monitored_domains WHERE id = ? AND user_id = ?"
    ).run(domainId, userId);
  }

  getDomains(userId: string): { domains: MonitoredDomainWithStatus[]; limits: { max: number; used: number } } {
    const user = this.db.prepare("SELECT plan FROM users WHERE id = ?").get(userId) as { plan: string } | undefined;
    const plan = (user?.plan ?? "free") as UserPlan;

    const rows = this.db.prepare(`
      SELECT md.id, md.domain, md.enabled,
        (SELECT COUNT(*) FROM monitors m WHERE m.domain_id = md.id) as monitors_count,
        (SELECT COUNT(*) FROM monitors m WHERE m.domain_id = md.id AND m.last_run_at IS NOT NULL) as completed_count,
        (SELECT COUNT(*) FROM monitor_alerts ma WHERE ma.domain_id = md.id AND ma.user_id = ? AND ma.created_at > datetime('now', '-24 hours')) as active_alerts_count,
        (SELECT MAX(m2.last_run_at) FROM monitors m2 WHERE m2.domain_id = md.id) as last_check_at
      FROM monitored_domains md
      WHERE md.user_id = ?
      ORDER BY md.created_at DESC
    `).all(userId, userId) as Array<any>;

    const domains: MonitoredDomainWithStatus[] = rows.map(r => {
      let overallStatus: "pass" | "warn" | "critical" | null = null;
      // Check current monitor states for active issues
      const worstSeverity = this.db.prepare(`
        SELECT MIN(CASE ms.result_hash WHEN '' THEN NULL ELSE
          CASE
            WHEN m.monitor_type IN ('ssl_expiry','domain_expiry','security_txt_expiry')
              AND json_extract(ms.result_json, '$.daysRemaining') IS NOT NULL
              AND json_extract(ms.result_json, '$.daysRemaining') <= 7 THEN 1
            WHEN m.monitor_type IN ('ssl_expiry','domain_expiry','security_txt_expiry')
              AND json_extract(ms.result_json, '$.daysRemaining') IS NOT NULL
              AND json_extract(ms.result_json, '$.daysRemaining') <= 30 THEN 2
            ELSE 3
          END
        END) as worst
        FROM monitors m
        LEFT JOIN monitor_state ms ON ms.monitor_id = m.id
        WHERE m.domain_id = ? AND m.enabled = 1
      `).get(r.id) as { worst: number | null } | undefined;

      // Also check recent alerts (last 7 days for context)
      const recentAlerts = (this.db.prepare(
        "SELECT COUNT(*) as cnt FROM monitor_alerts WHERE domain_id = ? AND user_id = ? AND severity IN ('critical','warn') AND created_at > datetime('now', '-7 days')"
      ).get(r.id, userId) as { cnt: number }).cnt;

      if (worstSeverity?.worst === 1 || recentAlerts > 0) {
        const critCount = (this.db.prepare(
          "SELECT COUNT(*) as cnt FROM monitor_alerts WHERE domain_id = ? AND user_id = ? AND severity = 'critical' AND created_at > datetime('now', '-7 days')"
        ).get(r.id, userId) as { cnt: number }).cnt;
        overallStatus = critCount > 0 || worstSeverity?.worst === 1 ? "critical" : "warn";
      } else if (r.completed_count >= r.monitors_count && r.last_check_at) {
        overallStatus = "pass";
      }
      // null = still checking
      return {
        id: r.id,
        domain: r.domain,
        enabled: !!r.enabled,
        monitorsCount: r.monitors_count,
        activeAlertsCount: r.active_alerts_count,
        lastCheckAt: r.last_check_at,
        overallStatus,
      };
    });

    return { domains, limits: { max: DOMAIN_LIMITS[plan], used: rows.length } };
  }

  getDomainStatus(userId: string, domainId: string): DomainMonitorStatus | null {
    const md = this.db.prepare(
      "SELECT id, domain FROM monitored_domains WHERE id = ? AND user_id = ?"
    ).get(domainId, userId) as MonitoredDomainRow | undefined;
    if (!md) return null;

    const monitors = this.db.prepare(
      "SELECT m.*, ms.result_json FROM monitors m LEFT JOIN monitor_state ms ON ms.monitor_id = m.id WHERE m.domain_id = ?"
    ).all(domainId) as Array<MonitorRow & { result_json: string | null }>;

    return {
      domain: md.domain,
      monitors: monitors.map(m => {
        let lastResult: unknown = null;
        let status: string | null = null;
        if (m.result_json) {
          try {
            const parsed = JSON.parse(m.result_json);
            lastResult = parsed;
            status = parsed.status ?? null;
          } catch { /* ignore */ }
        }
        return {
          id: m.id,
          type: m.monitor_type,
          enabled: !!m.enabled,
          lastRunAt: m.last_run_at,
          nextRunAt: m.next_run_at,
          lastResult,
          lastError: m.last_error,
          status,
        };
      }),
    };
  }

  getAlerts(userId: string, opts: AlertQueryOpts): PaginatedAlerts {
    const { page, limit, domain, severity } = opts;
    const offset = (page - 1) * limit;
    let where = "ma.user_id = ?";
    const params: unknown[] = [userId];

    if (domain) {
      where += " AND md.domain = ?";
      params.push(domain);
    }
    if (severity) {
      where += " AND ma.severity = ?";
      params.push(severity);
    }

    const total = (this.db.prepare(
      `SELECT COUNT(*) as cnt FROM monitor_alerts ma JOIN monitored_domains md ON md.id = ma.domain_id WHERE ${where}`
    ).get(...params) as { cnt: number }).cnt;

    const alerts = this.db.prepare(
      `SELECT ma.*, md.domain FROM monitor_alerts ma
       JOIN monitored_domains md ON md.id = ma.domain_id
       WHERE ${where}
       ORDER BY ma.created_at DESC LIMIT ? OFFSET ?`
    ).all(...params, limit, offset) as MonitorAlertRow[];

    return { alerts, pagination: { page, limit, total } };
  }

  async restoreJobs(): Promise<number> {
    if (!this.queue) return 0;

    const activeMonitors = this.db.prepare(`
      SELECT m.*, md.domain FROM monitors m
      JOIN monitored_domains md ON m.domain_id = md.id
      WHERE m.enabled = 1 AND md.enabled = 1
    `).all() as Array<MonitorRow & { domain: string }>;

    const existingJobs = await this.queue.getRepeatableJobs();
    const existingIds = new Set(existingJobs.map(j => j.id));

    let restored = 0;
    for (const monitor of activeMonitors) {
      const jobId = `monitor-${monitor.id}`;
      if (!existingIds.has(jobId)) {
        await this.queue.add("check", {
          monitorId: monitor.id,
          domainId: monitor.domain_id,
          domain: monitor.domain,
          monitorType: monitor.monitor_type,
          userId: monitor.user_id,
        }, {
          repeat: { every: monitor.interval_ms },
          jobId,
          priority: JOB_PRIORITIES[monitor.monitor_type],
          attempts: 3,
          backoff: { type: "exponential", delay: 30_000 },
          removeOnComplete: { count: 100 },
          removeOnFail: { count: 50 },
        });
        restored++;
      }
    }
    return restored;
  }

  async healthCheck(): Promise<HealthStatus> {
    if (!this.queue) {
      return { redis: "disconnected", monitoringEnabled: false, activeJobs: 0, waitingJobs: 0, failedJobs: 0 };
    }
    try {
      const [active, waiting, failed] = await Promise.all([
        this.queue.getActiveCount(),
        this.queue.getWaitingCount(),
        this.queue.getFailedCount(),
      ]);
      return { redis: "connected", monitoringEnabled: true, activeJobs: active, waitingJobs: waiting, failedJobs: failed };
    } catch {
      return { redis: "disconnected", monitoringEnabled: false, activeJobs: 0, waitingJobs: 0, failedJobs: 0 };
    }
  }

  getSettings(userId: string): { emailEnabled: boolean; minSeverity: string } {
    const row = this.db.prepare(
      "SELECT email_enabled, min_severity FROM monitoring_settings WHERE user_id = ?"
    ).get(userId) as MonitoringSettingsRow | undefined;
    return {
      emailEnabled: row ? !!row.email_enabled : true,
      minSeverity: row?.min_severity ?? "warn",
    };
  }

  updateSettings(userId: string, settings: { emailEnabled?: boolean; minSeverity?: string }): { emailEnabled: boolean; minSeverity: string } {
    const current = this.getSettings(userId);
    const emailEnabled = settings.emailEnabled ?? current.emailEnabled;
    const minSeverity = settings.minSeverity ?? current.minSeverity;

    this.db.prepare(`
      INSERT INTO monitoring_settings (user_id, email_enabled, min_severity, updated_at)
      VALUES (?, ?, ?, datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        email_enabled = excluded.email_enabled,
        min_severity = excluded.min_severity,
        updated_at = excluded.updated_at
    `).run(userId, emailEnabled ? 1 : 0, minSeverity);

    return { emailEnabled, minSeverity };
  }

  updateDomainSettings(userId: string, domainId: string, settings: { emailEnabled?: boolean; minSeverity?: string; enabledMonitors?: string[] }): { emailEnabled: boolean; minSeverity: string; monitors: Array<{ type: string; enabled: boolean }> } | null {
    const md = this.db.prepare(
      "SELECT id, email_enabled, min_severity FROM monitored_domains WHERE id = ? AND user_id = ?"
    ).get(domainId, userId) as { id: string; email_enabled: number; min_severity: string } | undefined;
    if (!md) return null;

    const emailEnabled = settings.emailEnabled ?? !!md.email_enabled;
    const minSeverity = settings.minSeverity ?? md.min_severity;

    this.db.prepare(
      "UPDATE monitored_domains SET email_enabled = ?, min_severity = ? WHERE id = ?"
    ).run(emailEnabled ? 1 : 0, minSeverity, domainId);

    // Update individual monitor enabled states
    if (settings.enabledMonitors) {
      const enabledSet = new Set(settings.enabledMonitors);
      const monitors = this.db.prepare(
        "SELECT id, monitor_type, enabled FROM monitors WHERE domain_id = ?"
      ).all(domainId) as Array<{ id: string; monitor_type: string; enabled: number }>;
      for (const m of monitors) {
        const shouldEnable = enabledSet.has(m.monitor_type) ? 1 : 0;
        if (m.enabled !== shouldEnable) {
          this.db.prepare("UPDATE monitors SET enabled = ? WHERE id = ?").run(shouldEnable, m.id);
        }
      }
    }

    const monitors = this.db.prepare(
      "SELECT monitor_type, enabled FROM monitors WHERE domain_id = ?"
    ).all(domainId) as Array<{ monitor_type: string; enabled: number }>;

    return {
      emailEnabled, minSeverity,
      monitors: monitors.map(m => ({ type: m.monitor_type, enabled: !!m.enabled })),
    };
  }
}
