import { Router } from "express";
import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { Lucia } from "lucia";
import { requireAuth } from "../middleware/authMiddleware.js";
import { requirePlan } from "../middleware/planGating.js";
import { computeNextRun } from "../scheduler.js";
import type { ScheduledScanRow, ScanConfig } from "../types.js";
import { DEFAULT_SCAN_CONFIG } from "../types.js";

interface ScheduledDeps {
  db: Database.Database;
  lucia: Lucia;
}

const MAX_SCHEDULES_PER_USER = 5;
const MAX_DOMAINS_PER_SCHEDULE = 100;

export function createScheduledRoutes({ db }: ScheduledDeps): Router {
  const router = Router();

  // POST /api/scheduled — create scheduled scan
  router.post("/", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const { domains, cron, config, name } = req.body as {
      domains: string[];
      cron: string;
      config?: ScanConfig;
      name?: string;
    };

    if (!domains || !Array.isArray(domains) || domains.length === 0) {
      res.status(400).json({ error: "invalid_request", message: "domains array is required" });
      return;
    }
    if (domains.length > MAX_DOMAINS_PER_SCHEDULE) {
      res.status(400).json({
        error: "limit_exceeded",
        message: `Maximum ${MAX_DOMAINS_PER_SCHEDULE} domains per scheduled scan`,
      });
      return;
    }
    if (!cron || typeof cron !== "string") {
      res.status(400).json({ error: "invalid_request", message: "cron expression is required" });
      return;
    }

    // Validate cron expression
    let nextRunAt: Date;
    try {
      nextRunAt = computeNextRun(cron, new Date());
    } catch {
      res.status(400).json({ error: "invalid_request", message: "Invalid cron expression" });
      return;
    }

    // Check schedule limit
    const count = (
      db.prepare("SELECT COUNT(*) as cnt FROM scheduled_scans WHERE user_id = ?").get(userId) as { cnt: number }
    ).cnt;
    if (count >= MAX_SCHEDULES_PER_USER) {
      res.status(400).json({
        error: "limit_exceeded",
        message: `Maximum ${MAX_SCHEDULES_PER_USER} scheduled scans per user`,
      });
      return;
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const scanConfig = config ?? DEFAULT_SCAN_CONFIG;

    db.prepare(
      `INSERT INTO scheduled_scans (id, user_id, name, domains_json, cron, config_json, enabled, next_run_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`
    ).run(id, userId, name ?? null, JSON.stringify(domains), cron, JSON.stringify(scanConfig), nextRunAt.toISOString(), now);

    const schedule = db.prepare("SELECT * FROM scheduled_scans WHERE id = ?").get(id) as ScheduledScanRow;
    res.status(201).json({
      ...schedule,
      domains_json: JSON.parse(schedule.domains_json),
      config_json: schedule.config_json ? JSON.parse(schedule.config_json) : null,
    });
  });

  // GET /api/scheduled — list user's schedules
  router.get("/", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const schedules = db
      .prepare("SELECT * FROM scheduled_scans WHERE user_id = ? ORDER BY created_at DESC")
      .all(userId) as ScheduledScanRow[];

    res.json(
      schedules.map((s) => ({
        ...s,
        domains_json: JSON.parse(s.domains_json),
        config_json: s.config_json ? JSON.parse(s.config_json) : null,
      }))
    );
  });

  // PUT /api/scheduled/:id — update schedule
  router.put("/:id", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const schedule = db
      .prepare("SELECT * FROM scheduled_scans WHERE id = ? AND user_id = ?")
      .get(req.params.id, userId) as ScheduledScanRow | undefined;

    if (!schedule) {
      res.status(404).json({ error: "not_found", message: "Schedule not found" });
      return;
    }

    const { domains, cron, config, name } = req.body as {
      domains?: string[];
      cron?: string;
      config?: ScanConfig;
      name?: string;
    };

    const newDomains = domains ?? JSON.parse(schedule.domains_json);
    const newCron = cron ?? schedule.cron;
    const newConfig = config ?? (schedule.config_json ? JSON.parse(schedule.config_json) : DEFAULT_SCAN_CONFIG);
    const newName = name !== undefined ? name : schedule.name;

    if (newDomains.length > MAX_DOMAINS_PER_SCHEDULE) {
      res.status(400).json({
        error: "limit_exceeded",
        message: `Maximum ${MAX_DOMAINS_PER_SCHEDULE} domains per scheduled scan`,
      });
      return;
    }

    let nextRunAt: Date;
    try {
      nextRunAt = computeNextRun(newCron, new Date());
    } catch {
      res.status(400).json({ error: "invalid_request", message: "Invalid cron expression" });
      return;
    }

    db.prepare(
      `UPDATE scheduled_scans SET name = ?, domains_json = ?, cron = ?, config_json = ?, next_run_at = ? WHERE id = ?`
    ).run(newName, JSON.stringify(newDomains), newCron, JSON.stringify(newConfig), nextRunAt.toISOString(), req.params.id);

    const updated = db.prepare("SELECT * FROM scheduled_scans WHERE id = ?").get(req.params.id) as ScheduledScanRow;
    res.json({
      ...updated,
      domains_json: JSON.parse(updated.domains_json),
      config_json: updated.config_json ? JSON.parse(updated.config_json) : null,
    });
  });

  // DELETE /api/scheduled/:id — delete schedule
  router.delete("/:id", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const result = db
      .prepare("DELETE FROM scheduled_scans WHERE id = ? AND user_id = ?")
      .run(req.params.id, userId);

    if (result.changes === 0) {
      res.status(404).json({ error: "not_found", message: "Schedule not found" });
      return;
    }
    res.status(204).send();
  });

  // PATCH /api/scheduled/:id/toggle — flip enabled state
  router.patch("/:id/toggle", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const schedule = db
      .prepare("SELECT * FROM scheduled_scans WHERE id = ? AND user_id = ?")
      .get(req.params.id, userId) as ScheduledScanRow | undefined;

    if (!schedule) {
      res.status(404).json({ error: "not_found", message: "Schedule not found" });
      return;
    }

    const newEnabled = schedule.enabled ? 0 : 1;
    let nextRunAt = schedule.next_run_at;

    // Recompute next_run_at when enabling
    if (newEnabled === 1) {
      try {
        nextRunAt = computeNextRun(schedule.cron, new Date()).toISOString();
      } catch {
        // Keep existing next_run_at
      }
    }

    db.prepare(
      "UPDATE scheduled_scans SET enabled = ?, next_run_at = ? WHERE id = ?"
    ).run(newEnabled, nextRunAt, req.params.id);

    const updated = db.prepare("SELECT * FROM scheduled_scans WHERE id = ?").get(req.params.id) as ScheduledScanRow;
    res.json({
      ...updated,
      domains_json: JSON.parse(updated.domains_json),
      config_json: updated.config_json ? JSON.parse(updated.config_json) : null,
    });
  });

  return router;
}
