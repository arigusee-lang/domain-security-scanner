import { Router } from "express";
import type Database from "better-sqlite3";
import type { Lucia } from "lucia";
import { requireAuth } from "../middleware/authMiddleware.js";
import { SCAN_HISTORY_LIMITS } from "../db.js";
import type { ScanRow } from "../types.js";

interface ScansDeps {
  db: Database.Database;
  lucia: Lucia;
}

export function createScansRoutes({ db }: ScansDeps): Router {
  const router = Router();

  // GET /api/scans — paginated list with filters
  router.get("/", requireAuth, (req, res) => {
    const userId = req.user!.id;
    const planCap = SCAN_HISTORY_LIMITS[req.user!.plan];
    const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
    const limit = 20;
    const offset = (page - 1) * limit;

    // Cap to the most recent `planCap` rows for this user, then apply filters
    // on top. This makes the cap robust to cleanup lag — anything past N is
    // never visible even if the daily cleanup job hasn't pruned it yet.
    const conditions: string[] = [
      `id IN (SELECT id FROM scans WHERE user_id = ? AND scan_type = 'single' ORDER BY created_at DESC LIMIT ?)`,
    ];
    const params: unknown[] = [userId, planCap];

    // Filter by domain
    if (req.query.domain) {
      conditions.push("domain LIKE ?");
      params.push(`%${req.query.domain}%`);
    }

    // Filter by status (score-based: pass=85+, warn=55–84, fail=<55)
    if (req.query.status) {
      const status = req.query.status as string;
      if (status === "pass") {
        conditions.push("score >= 85");
      } else if (status === "warn") {
        conditions.push("score >= 55 AND score < 85");
      } else if (status === "fail") {
        conditions.push("score < 55");
      }
    }

    // Filter by date range
    if (req.query.from) {
      conditions.push("created_at >= ?");
      params.push(req.query.from as string);
    }
    if (req.query.to) {
      conditions.push("created_at <= ?");
      params.push(req.query.to as string);
    }

    const where = conditions.join(" AND ");

    const total = (
      db.prepare(`SELECT COUNT(*) as cnt FROM scans WHERE ${where}`).get(...params) as { cnt: number }
    ).cnt;

    const scans = db
      .prepare(
        `SELECT id, domain, scan_type, status, score, created_at, completed_at
         FROM scans WHERE ${where}
         ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .all(...params, limit, offset);

    res.json({
      scans,
      page,
      totalPages: Math.ceil(total / limit),
      total,
      historyCap: planCap,
    });
  });

  // GET /api/scans/:id — full scan result
  router.get("/:id", requireAuth, (req, res) => {
    const scan = db
      .prepare(`
        SELECT s.*, b.name AS batch_name
        FROM scans s
        LEFT JOIN batch_scans b ON b.id = s.batch_id
        WHERE s.id = ?
      `)
      .get(req.params.id) as (ScanRow & { batch_name: string | null }) | undefined;

    if (!scan) {
      res.status(404).json({ error: "not_found", message: "Scan not found" });
      return;
    }
    if (scan.user_id !== req.user!.id) {
      res.status(403).json({ error: "forbidden", message: "Not your scan" });
      return;
    }

    res.json({
      ...scan,
      result_json: scan.result_json ? JSON.parse(scan.result_json) : null,
      config_json: scan.config_json ? JSON.parse(scan.config_json) : null,
      changes_json: scan.changes_json ? JSON.parse(scan.changes_json) : null,
    });
  });

  // DELETE /api/scans/:id — delete scan
  router.delete("/:id", requireAuth, (req, res) => {
    const scan = db
      .prepare("SELECT id, user_id FROM scans WHERE id = ?")
      .get(req.params.id) as { id: string; user_id: string | null } | undefined;

    if (!scan) {
      res.status(404).json({ error: "not_found", message: "Scan not found" });
      return;
    }
    if (scan.user_id !== req.user!.id) {
      res.status(403).json({ error: "forbidden", message: "Not your scan" });
      return;
    }

    db.prepare("DELETE FROM scans WHERE id = ?").run(req.params.id);
    res.status(204).send();
  });

  return router;
}
