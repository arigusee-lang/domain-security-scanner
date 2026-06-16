import type Database from "better-sqlite3";
import type { Job, Queue } from "bullmq";
import { cleanupScanHistoryByPlan, cleanupBatchHistoryByPlan, checkDatabaseSize } from "./db.js";
import { createLogger } from "./lib/logger.js";

const log = createLogger("maintenance");

export const MAINTENANCE_QUEUE_NAME = "maintenance";
export const CLEANUP_JOB_NAME = "cleanup-history";

// Daily at 03:00 UTC — off-peak, well clear of typical scheduled-scan windows.
const CLEANUP_CRON = "0 3 * * *";

export interface CleanupResult {
  scansDeleted: number;
  batchesDeleted: number;
}

/**
 * Run all retention cleanups. Chunked + yielding internally so this is safe
 * to call from the request path or as a fire-and-forget post-listen task.
 */
export async function runMaintenanceCleanup(db: Database.Database): Promise<CleanupResult> {
  const scansDeleted = await cleanupScanHistoryByPlan(db);
  const batchesDeleted = await cleanupBatchHistoryByPlan(db);
  if (scansDeleted > 0 || batchesDeleted > 0) {
    log.info({ scansDeleted, batchesDeleted }, "cleanup completed");
  }
  checkDatabaseSize(db);
  return { scansDeleted, batchesDeleted };
}

export async function createMaintenanceWorker(
  connection: import("ioredis").default,
  db: Database.Database,
): Promise<import("bullmq").Worker> {
  const { Worker } = await import("bullmq");

  const worker = new Worker(
    MAINTENANCE_QUEUE_NAME,
    async (job: Job): Promise<CleanupResult | undefined> => {
      if (job.name === CLEANUP_JOB_NAME) {
        return runMaintenanceCleanup(db);
      }
      return undefined;
    },
    { connection, concurrency: 1 },
  );

  worker.on("completed", (job) => {
    const durationMs = job.processedOn && job.finishedOn ? job.finishedOn - job.processedOn : null;
    log.info({ jobId: job.id, queue: MAINTENANCE_QUEUE_NAME, jobName: job.name, durationMs }, "job completed");
  });

  worker.on("failed", (job, err) => {
    const durationMs = job?.processedOn && job?.finishedOn ? job.finishedOn - job.processedOn : null;
    log.error({ jobId: job?.id, queue: MAINTENANCE_QUEUE_NAME, jobName: job?.name, durationMs, attempt: job?.attemptsMade, err: err.message }, "job failed");
  });

  worker.on("stalled", (jobId) => {
    log.warn({ jobId, queue: MAINTENANCE_QUEUE_NAME }, "job stalled");
  });

  worker.on("error", (err) => {
    log.error({ queue: MAINTENANCE_QUEUE_NAME, err: err.message }, "worker error");
  });

  return worker;
}

/** Idempotent: schedules the cleanup repeatable job if not already scheduled. */
export async function scheduleCleanupJob(queue: Queue): Promise<void> {
  const existing = await queue.getRepeatableJobs();
  if (existing.some((j) => j.name === CLEANUP_JOB_NAME)) return;

  await queue.add(
    CLEANUP_JOB_NAME,
    {},
    {
      repeat: { pattern: CLEANUP_CRON },
      removeOnComplete: { count: 50 },
      removeOnFail: { count: 50 },
    },
  );
  log.info({ job: CLEANUP_JOB_NAME, cron: CLEANUP_CRON }, "scheduled cleanup job");
}

/**
 * Enqueue a one-off cleanup pass to run as soon as the worker is free.
 * Used at startup to drain any backlog without blocking the boot path.
 */
export async function enqueueImmediateCleanup(queue: Queue): Promise<void> {
  await queue.add(CLEANUP_JOB_NAME, {}, {
    removeOnComplete: { count: 50 },
    removeOnFail: { count: 50 },
  });
}
