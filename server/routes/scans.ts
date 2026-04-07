import { Router } from "express";
import type Database from "better-sqlite3";
import type { Lucia } from "lucia";
import { requireAuth } from "../middleware/authMiddleware.js";
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
    const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
    const limit = 20;
    const offset = (page - 1) * limit;

    const conditions: string[] = ["user_id = ?"];
    const params: unknown[] = [userId];

    // Filter by domain
    if (req.query.domain) {
      conditions.push("domain LIKE ?");
      params.push(`%${req.query.domain}%`);
    }

    // Filter by status (grade-based: pass/warn/fail)
    if (req.query.status) {
      const status = req.query.status as string;
      if (status === "pass") {
        conditions.push("grade IN ('A+', 'A')");
      } else if (status === "warn") {
        conditions.push("grade IN ('B', 'C')");
      } else if (status === "fail") {
        conditions.push("grade IN ('D', 'F')");
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
        `SELECT id, domain, scan_type, status, score, grade, created_at, completed_at
         FROM scans WHERE ${where}
         ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .all(...params, limit, offset);

    res.json({
      scans,
      page,
      totalPages: Math.ceil(total / limit),
      total,
    });
  });

  // GET /api/scans/:id — full scan result
  router.get("/:id", requireAuth, (req, res) => {
    const scan = db
      .prepare("SELECT * FROM scans WHERE id = ?")
      .get(req.params.id) as ScanRow | undefined;

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
