import { Router } from "express";
import { requireAuth } from "../middleware/authMiddleware.js";
import { MonitoringService, DomainLimitError } from "../monitoringService.js";
import { createLogger } from "../lib/logger.js";

const log = createLogger("monitoring");

interface MonitoringDeps {
  monitoringService: MonitoringService;
}

export function createMonitoringRoutes({ monitoringService }: MonitoringDeps): Router {
  const router = Router();
  router.use(requireAuth);

  // POST /api/monitoring/domains — add domain
  router.post("/domains", async (req, res) => {
    try {
      const { domain } = req.body;
      if (!domain || typeof domain !== "string") {
        res.status(400).json({ error: "invalid_request", message: "domain is required" });
        return;
      }
      const normalized = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!normalized || normalized.length > 253) {
        res.status(400).json({ error: "invalid_request", message: "Invalid domain" });
        return;
      }
      const { monitorTypes, emailEnabled, minSeverity } = req.body;
      log.info({ domain: normalized, monitorTypes, emailEnabled, minSeverity }, "addDomain");
      const result = await monitoringService.addDomain(req.user!.id, normalized, {
        monitorTypes, emailEnabled, minSeverity,
      });
      res.status(201).json(result);
    } catch (err) {
      if (err instanceof DomainLimitError) {
        res.status(403).json({
          error: "domain_limit_exceeded",
          message: `Your plan allows monitoring up to ${err.currentLimit} domain(s). Upgrade to Premium for more domains.`,
          currentLimit: err.currentLimit,
          currentCount: err.currentCount,
        });
        return;
      }
      if ((err as any)?.code === "SQLITE_CONSTRAINT_UNIQUE") {
        res.status(409).json({ error: "duplicate", message: "Domain already monitored" });
        return;
      }
      log.error({ err }, "addDomain error");
      res.status(500).json({ error: "internal", message: "Failed to add domain" });
    }
  });

  // DELETE /api/monitoring/domains/:domainId — remove domain
  router.delete("/domains/:domainId", async (req, res) => {
    try {
      await monitoringService.removeDomain(req.user!.id, req.params.domainId);
      res.status(204).end();
    } catch (err) {
      log.error({ err }, "removeDomain error");
      res.status(500).json({ error: "internal", message: "Failed to remove domain" });
    }
  });

  // GET /api/monitoring/domains — list domains
  router.get("/domains", (req, res) => {
    try {
      const result = monitoringService.getDomains(req.user!.id);
      res.json(result);
    } catch (err) {
      log.error({ err }, "getDomains error");
      res.status(500).json({ error: "internal" });
    }
  });

  // GET /api/monitoring/domains/:domainId/status — domain detail
  router.get("/domains/:domainId/status", (req, res) => {
    try {
      const result = monitoringService.getDomainStatus(req.user!.id, req.params.domainId);
      if (!result) {
        res.status(404).json({ error: "not_found", message: "Domain not found" });
        return;
      }
      res.json(result);
    } catch (err) {
      log.error({ err }, "getDomainStatus error");
      res.status(500).json({ error: "internal" });
    }
  });

  // PATCH /api/monitoring/domains/:domainId/settings — update per-domain notification settings
  router.patch("/domains/:domainId/settings", (req, res) => {
    try {
      const { emailEnabled, minSeverity, enabledMonitors } = req.body;
      if (minSeverity && !["info", "warn", "critical"].includes(minSeverity)) {
        res.status(400).json({ error: "invalid_request", message: "minSeverity must be info, warn, or critical" });
        return;
      }
      const md = monitoringService.updateDomainSettings(req.user!.id, req.params.domainId, { emailEnabled, minSeverity, enabledMonitors });
      if (!md) { res.status(404).json({ error: "not_found" }); return; }
      res.json(md);
    } catch (err) {
      log.error({ err }, "updateDomainSettings error");
      res.status(500).json({ error: "internal" });
    }
  });

  // GET /api/monitoring/alerts — alerts history
  router.get("/alerts", (req, res) => {
    try {
      const page = Math.max(1, parseInt(req.query.page as string) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 20));
      const domain = (req.query.domain as string) || undefined;
      const severity = (req.query.severity as string) || undefined;
      const result = monitoringService.getAlerts(req.user!.id, { page, limit, domain, severity });
      res.json(result);
    } catch (err) {
      log.error({ err }, "getAlerts error");
      res.status(500).json({ error: "internal" });
    }
  });

  // GET /api/monitoring/health — health check
  router.get("/health", async (_req, res) => {
    try {
      const health = await monitoringService.healthCheck();
      res.json(health);
    } catch (err) {
      res.json({ redis: "disconnected", monitoringEnabled: false, activeJobs: 0, waitingJobs: 0, failedJobs: 0 });
    }
  });

  // GET /api/monitoring/settings
  router.get("/settings", (req, res) => {
    try {
      const settings = monitoringService.getSettings(req.user!.id);
      res.json(settings);
    } catch (err) {
      log.error({ err }, "getSettings error");
      res.status(500).json({ error: "internal" });
    }
  });

  // PUT /api/monitoring/settings
  router.put("/settings", (req, res) => {
    try {
      const { emailEnabled, minSeverity } = req.body;
      if (minSeverity && !["info", "warn", "critical"].includes(minSeverity)) {
        res.status(400).json({ error: "invalid_request", message: "minSeverity must be info, warn, or critical" });
        return;
      }
      const result = monitoringService.updateSettings(req.user!.id, { emailEnabled, minSeverity });
      res.json(result);
    } catch (err) {
      log.error({ err }, "updateSettings error");
      res.status(500).json({ error: "internal" });
    }
  });

  return router;
}
