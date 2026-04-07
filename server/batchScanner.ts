import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { ScanConfig } from "./types.js";
import { calculateScore } from "./scoreCalculator.js";
import { runDomainCheck } from "./domainPipeline.js";

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
 * 4. Saves result to scans table
 * 5. Updates batch_scan_domains status → completed (or failed)
 * 6. Increments batch_scans.completed_domains
 * 7. Waits 12–20s before next domain
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

      // 4. Save to scans table
      scanId = crypto.randomUUID();
      const now = new Date().toISOString();

      db.prepare(
        `INSERT INTO scans (id, user_id, domain, scan_type, status, score, grade, config_json, result_json, created_at, completed_at)
         VALUES (?, ?, ?, 'batch', 'completed', ?, ?, ?, ?, ?, ?)`,
      ).run(
        scanId,
        userId,
        domain,
        score.total,
        score.grade,
        JSON.stringify(config),
        JSON.stringify(result),
        now,
        now,
      );

      // 5. Update batch_scan_domains → completed with scan_id
      db.prepare(
        "UPDATE batch_scan_domains SET status = 'completed', scan_id = ? WHERE id = ?",
      ).run(scanId, batchDomainId);
    } catch (err) {
      // Mark domain as failed, continue scanning remaining
      db.prepare("UPDATE batch_scan_domains SET status = 'failed' WHERE id = ?").run(batchDomainId);
      console.error(`[batch] Domain "${domain}" failed:`, err);
    }

    // 6. Increment completed_domains
    db.prepare(
      "UPDATE batch_scans SET completed_domains = completed_domains + 1 WHERE id = ?",
    ).run(batchId);

    // 7. Delay between domains (skip after last domain)
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
