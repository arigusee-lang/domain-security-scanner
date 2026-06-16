import { Router } from "express";
import type Database from "better-sqlite3";
import { getSharedReport } from "../reportSharing.js";

interface ReportsDeps {
  db: Database.Database;
}

export function createReportsRoutes({ db }: ReportsDeps): Router {
  const router = Router();

  // GET /api/reports/:id — public shared report (no auth required)
  router.get("/:id", (req, res) => {
    const report = getSharedReport(req.params.id, db);

    if (!report) {
      res.status(404).json({ error: "not_found", message: "Report not found or expired" });
      return;
    }

    res.json({
      id: report.id,
      domain: report.domain,
      scan_type: report.scan_type,
      score: report.score,
      result_json: report.result_json ? JSON.parse(report.result_json) : null,
      changes_json: report.changes_json ? JSON.parse(report.changes_json) : null,
      created_at: report.created_at,
      completed_at: report.completed_at,
    });
  });

  return router;
}
