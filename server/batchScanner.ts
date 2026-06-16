import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { DomainCheckResponse, ScanConfig } from "./types.js";
import { calculateScore } from "./scoreCalculator.js";
import { runDomainCheck } from "./domainPipeline.js";
import { computeDiff } from "./diffEngine.js";
import { createLogger } from "./lib/logger.js";

const log = createLogger("batch");

export interface BatchScanOptions {
  batchId: string;
  domains: string[];
  userId: string;
  config: ScanConfig;
  /** Delay between domains in milliseconds (default ~15000) */
  delayMs?: number;
}

/**
 * Runs a batch scan sequentially over the given domains.
 *
 * For each domain:
 * 1. Updates batch_scan_domains status → running
 * 2. Runs the full checker pipeline (same as /api/domain-check)
 * 3. Calculates score
 * 4. Computes diff against the previous batch-scan of the same domain
 * 5. Saves result + diff to scans table
 * 6. Updates batch_scan_domains status → completed (or failed)
 * 7. Increments batch_scans.completed_domains
 * 8. Waits 12–20s before next domain
 *
 * When all domains are processed, sets batch status → completed.
 */
export async function runBatchScan(
  options: BatchScanOptions,
  db: Database.Database,
): Promise<void> {
  const { batchId, domains, userId, config } = options;
  const delayMs = options.delayMs ?? 15_000;

  // Mark batch as running
  db.prepare("UPDATE batch_scans SET status = 'running' WHERE id = ?").run(batchId);

  for (let i = 0; i < domains.length; i++) {
    const domain = domains[i];

    // Find the batch_scan_domains row for this domain
    const batchDomainRow = db
      .prepare("SELECT id FROM batch_scan_domains WHERE batch_id = ? AND domain = ? AND status = 'pending' LIMIT 1")
      .get(batchId, domain) as { id: string } | undefined;

    if (!batchDomainRow) continue;

    const batchDomainId = batchDomainRow.id;

    // 1. Mark domain as running
    db.prepare("UPDATE batch_scan_domains SET status = 'running' WHERE id = ?").run(batchDomainId);

    let scanId: string | null = null;

    try {
      // 2. Run the full checker pipeline
      const result = await runDomainCheck(domain, config);

      // 3. Calculate score
      const score = calculateScore(result);

      // 4. Compute diff against the previous batch-scan for this domain (batch ↔ batch only).
      // Single-scan history is intentionally excluded; monitoring uses a separate table.
      let diff = null;
      try {
        const previousBatchScan = db
          .prepare(
            `SELECT id, result_json, created_at FROM scans
             WHERE user_id = ? AND domain = ? AND scan_type = 'batch' AND status = 'completed' AND result_json IS NOT NULL
             ORDER BY created_at DESC LIMIT 1`,
          )
          .get(userId, domain) as { id: string; result_json: string; created_at: string } | undefined;

        if (previousBatchScan) {
          const previousResult = JSON.parse(previousBatchScan.result_json) as DomainCheckResponse;
          diff = computeDiff(result as unknown as DomainCheckResponse, previousResult);
          diff.previousScanId = previousBatchScan.id;
          diff.previousScanDate = previousBatchScan.created_at;
        }
      } catch (err) {
        log.error({ err, domain }, "diff computation failed");
      }

      // 5. Save to scans table
      scanId = crypto.randomUUID();
      const now = new Date().toISOString();

      db.prepare(
        `INSERT INTO scans (id, user_id, batch_id, domain, scan_type, status, score, config_json, result_json, changes_json, created_at, completed_at)
         VALUES (?, ?, ?, ?, 'batch', 'completed', ?, ?, ?, ?, ?, ?)`,
      ).run(
        scanId,
        userId,
        batchId,
        domain,
        score.total,
        JSON.stringify(config),
        JSON.stringify(result),
        diff ? JSON.stringify(diff) : null,
        now,
        now,
      );

      // 6. Update batch_scan_domains → completed with scan_id
      db.prepare(
        "UPDATE batch_scan_domains SET status = 'completed', scan_id = ? WHERE id = ?",
      ).run(scanId, batchDomainId);
    } catch (err) {
      // Mark domain as failed, continue scanning remaining
      db.prepare("UPDATE batch_scan_domains SET status = 'failed' WHERE id = ?").run(batchDomainId);
      log.error({ err, domain }, "domain failed");
    }

    // 7. Increment completed_domains
    db.prepare(
      "UPDATE batch_scans SET completed_domains = completed_domains + 1 WHERE id = ?",
    ).run(batchId);

    // 8. Delay between domains (skip after last domain)
    if (i < domains.length - 1 && delayMs > 0) {
      await delay(delayMs);
    }
  }

  // All domains processed — mark batch as completed
  db.prepare(
    "UPDATE batch_scans SET status = 'completed', completed_at = ? WHERE id = ?",
  ).run(new Date().toISOString(), batchId);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
