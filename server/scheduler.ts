import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { ScheduledScanRow, ScanConfig } from "./types.js";
import { DEFAULT_SCAN_CONFIG } from "./types.js";
import { runBatchScan } from "./batchScanner.js";
import { computeDiff } from "./diffEngine.js";

/**
 * Parses a simple cron expression and computes the next run time after `from`.
 *
 * Supported patterns (standard 5-field cron: minute hour dayOfMonth month dayOfWeek):
 *   - Daily:   "0 9 * * *"     → every day at 09:00
 *   - Weekly:  "0 9 * * 1"     → every Monday at 09:00 (0=Sun, 1=Mon, ..., 6=Sat)
 *   - Monthly: "0 9 15 * *"    → 15th of every month at 09:00
 */
export function computeNextRun(cron: string, from: Date): Date {
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) {
    throw new Error(`Invalid cron expression: expected 5 fields, got ${parts.length}`);
  }

  const [minuteStr, hourStr, dayOfMonthStr, , dayOfWeekStr] = parts;
  const minute = parseInt(minuteStr, 10);
  const hour = parseInt(hourStr, 10);

  if (isNaN(minute) || minute < 0 || minute > 59) {
    throw new Error(`Invalid cron minute: ${minuteStr}`);
  }
  if (isNaN(hour) || hour < 0 || hour > 23) {
    throw new Error(`Invalid cron hour: ${hourStr}`);
  }

  const isMonthly = dayOfMonthStr !== "*";
  const isWeekly = dayOfWeekStr !== "*";

  if (isMonthly) {
    // Monthly: "0 9 15 * *"
    const dayOfMonth = parseInt(dayOfMonthStr, 10);
    if (isNaN(dayOfMonth) || dayOfMonth < 1 || dayOfMonth > 31) {
      throw new Error(`Invalid cron day of month: ${dayOfMonthStr}`);
    }
    return nextMonthly(from, hour, minute, dayOfMonth);
  }

  if (isWeekly) {
    // Weekly: "0 9 * * 1"
    const dayOfWeek = parseInt(dayOfWeekStr, 10);
    if (isNaN(dayOfWeek) || dayOfWeek < 0 || dayOfWeek > 6) {
      throw new Error(`Invalid cron day of week: ${dayOfWeekStr}`);
    }
    return nextWeekly(from, hour, minute, dayOfWeek);
  }

  // Daily: "0 9 * * *"
  return nextDaily(from, hour, minute);
}

function nextDaily(from: Date, hour: number, minute: number): Date {
  const candidate = new Date(from);
  candidate.setUTCHours(hour, minute, 0, 0);

  // If candidate is not strictly after `from`, advance to next day
  if (candidate.getTime() <= from.getTime()) {
    candidate.setUTCDate(candidate.getUTCDate() + 1);
  }
  return candidate;
}

function nextWeekly(from: Date, hour: number, minute: number, dayOfWeek: number): Date {
  const candidate = new Date(from);
  candidate.setUTCHours(hour, minute, 0, 0);

  // Calculate days until target day of week
  const currentDay = candidate.getUTCDay();
  let daysAhead = dayOfWeek - currentDay;

  if (daysAhead < 0) {
    daysAhead += 7;
  } else if (daysAhead === 0 && candidate.getTime() <= from.getTime()) {
    daysAhead = 7;
  }

  candidate.setUTCDate(candidate.getUTCDate() + daysAhead);
  return candidate;
}

function nextMonthly(from: Date, hour: number, minute: number, dayOfMonth: number): Date {
  const candidate = new Date(from);
  candidate.setUTCHours(hour, minute, 0, 0);

  // Clamp day to valid range for the current month
  const maxDay = daysInMonth(candidate.getUTCFullYear(), candidate.getUTCMonth());
  const targetDay = Math.min(dayOfMonth, maxDay);
  candidate.setUTCDate(targetDay);

  if (candidate.getTime() <= from.getTime()) {
    // Move to next month
    candidate.setUTCMonth(candidate.getUTCMonth() + 1);
    const nextMaxDay = daysInMonth(candidate.getUTCFullYear(), candidate.getUTCMonth());
    candidate.setUTCDate(Math.min(dayOfMonth, nextMaxDay));
  }

  return candidate;
}

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
}

/**
 * Selects all due scheduled scans and runs them as batch scans.
 *
 * Called by POST /api/cron/run-scheduled (Cloud Scheduler trigger).
 *
 * For each due schedule:
 * 1. Creates a batch scan
 * 2. Runs the batch
 * 3. Computes diff for each domain against previous scan
 * 4. TODO: Triggers notifications if changes detected
 * 5. Updates last_run_at and next_run_at
 */
export async function runDueScheduledScans(db: Database.Database): Promise<void> {
  const now = new Date().toISOString();

  const dueSchedules = db
    .prepare(
      "SELECT * FROM scheduled_scans WHERE enabled = 1 AND next_run_at <= ?",
    )
    .all(now) as ScheduledScanRow[];

  for (const schedule of dueSchedules) {
    const domains: string[] = JSON.parse(schedule.domains_json);
    const config: ScanConfig = schedule.config_json
      ? JSON.parse(schedule.config_json)
      : DEFAULT_SCAN_CONFIG;

    // Create a batch scan
    const batchId = crypto.randomUUID();
    db.prepare(
      `INSERT INTO batch_scans (id, user_id, name, status, total_domains, config_json, created_at)
       VALUES (?, ?, ?, 'pending', ?, ?, ?)`,
    ).run(
      batchId,
      schedule.user_id,
      schedule.name ? `Scheduled: ${schedule.name}` : "Scheduled scan",
      domains.length,
      JSON.stringify(config),
      new Date().toISOString(),
    );

    // Create batch_scan_domains rows
    for (const domain of domains) {
      db.prepare(
        "INSERT INTO batch_scan_domains (id, batch_id, domain, status) VALUES (?, ?, ?, 'pending')",
      ).run(crypto.randomUUID(), batchId, domain);
    }

    // Run the batch scan
    await runBatchScan({ batchId, domains, userId: schedule.user_id, config }, db);

    // Compute diff for each completed domain
    const completedDomains = db
      .prepare(
        "SELECT bsd.domain, bsd.scan_id FROM batch_scan_domains bsd WHERE bsd.batch_id = ? AND bsd.status = 'completed' AND bsd.scan_id IS NOT NULL",
      )
      .all(batchId) as Array<{ domain: string; scan_id: string }>;

    for (const { domain, scan_id } of completedDomains) {
      try {
        // Find the previous scan for this domain + user (before the current one)
        const previousScan = db
          .prepare(
            `SELECT id, result_json FROM scans
             WHERE user_id = ? AND domain = ? AND id != ? AND status = 'completed' AND result_json IS NOT NULL
             ORDER BY created_at DESC LIMIT 1`,
          )
          .get(schedule.user_id, domain, scan_id) as { id: string; result_json: string } | undefined;

        const currentScan = db
          .prepare("SELECT result_json FROM scans WHERE id = ?")
          .get(scan_id) as { result_json: string } | undefined;

        if (currentScan?.result_json) {
          const currentResult = JSON.parse(currentScan.result_json);
          const previousResult = previousScan?.result_json
            ? JSON.parse(previousScan.result_json)
            : null;

          const diff = computeDiff(currentResult, previousResult);
          if (previousScan) {
            diff.previousScanId = previousScan.id;
          }

          // Save diff to the scan's changes_json
          db.prepare("UPDATE scans SET changes_json = ? WHERE id = ?").run(
            JSON.stringify(diff),
            scan_id,
          );

          // TODO: Trigger notifications if diff.hasDiff (task 8 — notificationService)
        }
      } catch (err) {
        console.error(`[scheduler] Diff computation failed for domain "${domain}":`, err);
      }
    }

    // Update schedule: last_run_at and next_run_at
    const nextRun = computeNextRun(schedule.cron, new Date());
    db.prepare(
      "UPDATE scheduled_scans SET last_run_at = ?, next_run_at = ? WHERE id = ?",
    ).run(new Date().toISOString(), nextRun.toISOString(), schedule.id);
  }
}
