import { Router } from "express";
import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { Lucia } from "lucia";
import { requireAuth } from "../middleware/authMiddleware.js";
import { requirePlan } from "../middleware/planGating.js";
import { runBatchScan } from "../batchScanner.js";
import type { BatchScanRow, BatchScanDomainRow, ScanRow, ScanConfig } from "../types.js";
import { DEFAULT_SCAN_CONFIG } from "../types.js";

interface BatchDeps {
  db: Database.Database;
  lucia: Lucia;
}

const MAX_BATCH_DOMAINS = 500;

/**
 * Parse domains from CSV text. Extracts the first column from each line.
 */
function parseCSV(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.split(",")[0]?.trim())
    .filter((d): d is string => !!d && d.length > 0 && !d.toLowerCase().startsWith("domain"));
}

export function createBatchRoutes({ db }: BatchDeps): Router {
  const router = Router();

  // POST /api/batch — create batch scan
  router.post("/", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const { domains: rawDomains, csv, config, name } = req.body as {
      domains?: string[];
      csv?: string;
      config?: ScanConfig;
      name?: string;
    };

    let domains: string[];
    if (rawDomains && Array.isArray(rawDomains)) {
      domains = rawDomains.map((d) => d.trim()).filter((d) => d.length > 0);
    } else if (csv && typeof csv === "string") {
      domains = parseCSV(csv);
    } else {
      res.status(400).json({ error: "invalid_request", message: "Provide domains array or csv text" });
      return;
    }

    if (domains.length === 0) {
      res.status(400).json({ error: "invalid_request", message: "No valid domains provided" });
      return;
    }
    if (domains.length > MAX_BATCH_DOMAINS) {
      res.status(400).json({
        error: "limit_exceeded",
        message: `Maximum ${MAX_BATCH_DOMAINS} domains per batch scan`,
      });
      return;
    }

    const batchId = crypto.randomUUID();
    const now = new Date().toISOString();
    const scanConfig = config ?? DEFAULT_SCAN_CONFIG;

    // Create batch_scans row
    db.prepare(
      `INSERT INTO batch_scans (id, user_id, name, status, total_domains, completed_domains, config_json, created_at)
       VALUES (?, ?, ?, 'pending', ?, 0, ?, ?)`
    ).run(batchId, userId, name ?? null, domains.length, JSON.stringify(scanConfig), now);

    // Create batch_scan_domains rows
    const insertDomain = db.prepare(
      "INSERT INTO batch_scan_domains (id, batch_id, domain, status) VALUES (?, ?, ?, 'pending')"
    );
    for (const domain of domains) {
      insertDomain.run(crypto.randomUUID(), batchId, domain);
    }

    // Start batch scan in background (don't await)
    runBatchScan({ batchId, domains, userId, config: scanConfig }, db).catch((err) => {
      console.error(`[batch] Background batch scan ${batchId} failed:`, err);
      db.prepare("UPDATE batch_scans SET status = 'failed' WHERE id = ?").run(batchId);
    });

    const batch = db.prepare("SELECT * FROM batch_scans WHERE id = ?").get(batchId) as BatchScanRow;
    res.status(201).json({
      ...batch,
      config_json: batch.config_json ? JSON.parse(batch.config_json) : null,
    });
  });

  // GET /api/batch — list user's batches with pagination
  router.get("/", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
    const limit = 20;
    const offset = (page - 1) * limit;

    const total = (
      db.prepare("SELECT COUNT(*) as cnt FROM batch_scans WHERE user_id = ?").get(userId) as { cnt: number }
    ).cnt;

    const batches = db
      .prepare(
        `SELECT * FROM batch_scans WHERE user_id = ?
         ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .all(userId, limit, offset) as BatchScanRow[];

    res.json({
      batches: batches.map((b) => ({
        ...b,
        config_json: b.config_json ? JSON.parse(b.config_json) : null,
      })),
      page,
      totalPages: Math.ceil(total / limit),
      total,
    });
  });

  // GET /api/batch/:id — batch status, progress, completed domain results
  router.get("/:id", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const batch = db
      .prepare("SELECT * FROM batch_scans WHERE id = ? AND user_id = ?")
      .get(req.params.id, userId) as BatchScanRow | undefined;

    if (!batch) {
      res.status(404).json({ error: "not_found", message: "Batch not found" });
      return;
    }

    const domains = db
      .prepare("SELECT * FROM batch_scan_domains WHERE batch_id = ?")
      .all(req.params.id) as BatchScanDomainRow[];

    // Fetch completed scan results
    const completedDomains = domains
      .filter((d) => d.scan_id)
      .map((d) => {
        const scan = db
          .prepare("SELECT id, domain, score, grade, status, created_at FROM scans WHERE id = ?")
          .get(d.scan_id!) as Pick<ScanRow, "id" | "domain" | "score" | "grade" | "status" | "created_at"> | undefined;
        return { ...d, scan: scan ?? null };
      });

    const pendingDomains = domains.filter((d) => !d.scan_id);

    res.json({
      ...batch,
      config_json: batch.config_json ? JSON.parse(batch.config_json) : null,
      domains: [...completedDomains, ...pendingDomains],
    });
  });

  // GET /api/batch/:id/csv — CSV export
  router.get("/:id/csv", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const batch = db
      .prepare("SELECT * FROM batch_scans WHERE id = ? AND user_id = ?")
      .get(req.params.id, userId) as BatchScanRow | undefined;

    if (!batch) {
      res.status(404).json({ error: "not_found", message: "Batch not found" });
      return;
    }

    const domains = db
      .prepare("SELECT * FROM batch_scan_domains WHERE batch_id = ?")
      .all(req.params.id) as BatchScanDomainRow[];

    // CSV header
    let csv = "domain,status,score,grade\n";

    for (const d of domains) {
      if (d.scan_id) {
        const scan = db
          .prepare("SELECT domain, score, grade, status FROM scans WHERE id = ?")
          .get(d.scan_id) as Pick<ScanRow, "domain" | "score" | "grade" | "status"> | undefined;
        if (scan) {
          csv += `${escapeCsvField(scan.domain)},${d.status},${scan.score ?? ""},${scan.grade ?? ""}\n`;
          continue;
        }
      }
      csv += `${escapeCsvField(d.domain)},${d.status},,\n`;
    }

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="batch-${req.params.id}.csv"`);
    res.send(csv);
  });

  // DELETE /api/batch/:id — cascade delete batch + domains + linked scans
  router.delete("/:id", requireAuth, requirePlan("pro", "enterprise"), (req, res) => {
    const userId = req.user!.id;
    const batch = db
      .prepare("SELECT id FROM batch_scans WHERE id = ? AND user_id = ?")
      .get(req.params.id, userId) as { id: string } | undefined;

    if (!batch) {
      res.status(404).json({ error: "not_found", message: "Batch not found" });
      return;
    }

    // Delete linked scans first
    const domainRows = db
      .prepare("SELECT scan_id FROM batch_scan_domains WHERE batch_id = ? AND scan_id IS NOT NULL")
      .all(req.params.id) as Array<{ scan_id: string }>;

    for (const { scan_id } of domainRows) {
      db.prepare("DELETE FROM scans WHERE id = ?").run(scan_id);
    }

    // batch_scan_domains will cascade delete with batch_scans
    db.prepare("DELETE FROM batch_scans WHERE id = ?").run(req.params.id);
    res.status(204).send();
  });

  return router;
}

function escapeCsvField(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
