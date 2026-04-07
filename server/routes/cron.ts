import { Router } from "express";
import type Database from "better-sqlite3";
import { runDueScheduledScans } from "../scheduler.js";

interface CronDeps {
  db: Database.Database;
}

const isProduction = process.env.NODE_ENV === "production";

export function createCronRoutes({ db }: CronDeps): Router {
  const router = Router();

  // POST /api/cron/run-scheduled — Cloud Scheduler trigger
  router.post("/run-scheduled", async (req, res) => {
    // Verify the request is from Cloud Scheduler
    if (isProduction) {
      const cronSecret = process.env.CRON_SECRET;
      const authHeader = req.headers.authorization;

      if (!cronSecret) {
        console.error("[cron] CRON_SECRET not configured");
        res.status(500).json({ error: "internal", message: "Cron not configured" });
        return;
      }
      if (authHeader !== `Bearer ${cronSecret}`) {
        res.status(403).json({ error: "forbidden", message: "Not authorized" });
        return;
      }
    }

    try {
      await runDueScheduledScans(db);
      res.json({ ok: true });
    } catch (err) {
      console.error("[cron] runDueScheduledScans failed:", err);
      res.status(500).json({ error: "internal", message: "Scheduled scan run failed" });
    }
  });

  return router;
}
