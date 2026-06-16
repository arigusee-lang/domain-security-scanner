import { Router } from "express";
import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { Lucia } from "lucia";
import { requireAuth } from "../middleware/authMiddleware.js";
import { requirePlan } from "../middleware/planGating.js";
import { generateSecret, deliverWebhook } from "../webhookService.js";
import type { WebhookRow, WebhookDeliveryRow } from "../types.js";
import { createLogger } from "../lib/logger.js";

const log = createLogger("webhooks");

interface WebhooksDeps {
  db: Database.Database;
  lucia: Lucia;
}

const WEBHOOK_LIMITS: Record<string, number> = {
  premium: 3,
  premium_plus: 5,
};

export function createWebhooksRoutes({ db }: WebhooksDeps): Router {
  const router = Router();

  // POST /api/webhooks — create webhook
  router.post("/", requireAuth, requirePlan("premium", "premium_plus"), (req, res) => {
    const userId = req.user!.id;
    const plan = req.user!.plan;
    const { url, name, events } = req.body as {
      url: string;
      name?: string;
      events: string[];
    };

    if (!url || typeof url !== "string") {
      res.status(400).json({ error: "invalid_request", message: "url is required" });
      return;
    }
    if (!events || !Array.isArray(events) || events.length === 0) {
      res.status(400).json({ error: "invalid_request", message: "events array is required" });
      return;
    }

    // Check webhook limit
    const limit = WEBHOOK_LIMITS[plan] ?? 3;
    const count = (
      db.prepare("SELECT COUNT(*) as cnt FROM webhooks WHERE user_id = ?").get(userId) as { cnt: number }
    ).cnt;
    if (count >= limit) {
      res.status(400).json({
        error: "limit_exceeded",
        message: `Maximum ${limit} webhooks for ${plan} plan`,
      });
      return;
    }

    const id = crypto.randomUUID();
    const secret = generateSecret();
    const now = new Date().toISOString();

    db.prepare(
      `INSERT INTO webhooks (id, user_id, url, name, secret, events_json, enabled, failing, fail_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, 0, 0, ?)`
    ).run(id, userId, url, name ?? null, secret, JSON.stringify(events), now);

    const webhook = db.prepare("SELECT * FROM webhooks WHERE id = ?").get(id) as WebhookRow;
    res.status(201).json({
      ...webhook,
      events_json: JSON.parse(webhook.events_json),
    });
  });

  // GET /api/webhooks — list user's webhooks (secret masked)
  router.get("/", requireAuth, requirePlan("premium", "premium_plus"), (req, res) => {
    const userId = req.user!.id;
    const webhooks = db
      .prepare("SELECT * FROM webhooks WHERE user_id = ? ORDER BY created_at DESC")
      .all(userId) as WebhookRow[];

    res.json(
      webhooks.map((w) => ({
        ...w,
        secret: undefined,
        events_json: JSON.parse(w.events_json),
      }))
    );
  });

  // PUT /api/webhooks/:id — update webhook
  router.put("/:id", requireAuth, requirePlan("premium", "premium_plus"), (req, res) => {
    const userId = req.user!.id;
    const webhook = db
      .prepare("SELECT * FROM webhooks WHERE id = ? AND user_id = ?")
      .get(req.params.id, userId) as WebhookRow | undefined;

    if (!webhook) {
      res.status(404).json({ error: "not_found", message: "Webhook not found" });
      return;
    }

    const { url, name, events } = req.body as {
      url?: string;
      name?: string;
      events?: string[];
    };

    const newUrl = url ?? webhook.url;
    const newName = name !== undefined ? name : webhook.name;
    const newEvents = events ?? JSON.parse(webhook.events_json);

    db.prepare(
      "UPDATE webhooks SET url = ?, name = ?, events_json = ? WHERE id = ?"
    ).run(newUrl, newName, JSON.stringify(newEvents), req.params.id);

    const updated = db.prepare("SELECT * FROM webhooks WHERE id = ?").get(req.params.id) as WebhookRow;
    res.json({
      ...updated,
      secret: undefined,
      events_json: JSON.parse(updated.events_json),
    });
  });

  // DELETE /api/webhooks/:id — delete webhook
  router.delete("/:id", requireAuth, requirePlan("premium", "premium_plus"), (req, res) => {
    const userId = req.user!.id;
    const result = db
      .prepare("DELETE FROM webhooks WHERE id = ? AND user_id = ?")
      .run(req.params.id, userId);

    if (result.changes === 0) {
      res.status(404).json({ error: "not_found", message: "Webhook not found" });
      return;
    }
    res.status(204).send();
  });

  // POST /api/webhooks/:id/test — send test payload
  router.post("/:id/test", requireAuth, requirePlan("premium", "premium_plus"), async (req, res) => {
    const userId = req.user!.id;
    const webhook = db
      .prepare("SELECT * FROM webhooks WHERE id = ? AND user_id = ?")
      .get(req.params.id, userId) as WebhookRow | undefined;

    if (!webhook) {
      res.status(404).json({ error: "not_found", message: "Webhook not found" });
      return;
    }

    const testPayload = {
      event: "test",
      timestamp: new Date().toISOString(),
      domain: "example.com",
      scan: {
        id: "test-scan-id",
        score: 85,
        scoreDelta: 0,
        url: "https://example.com",
      },
      changes: null,
    };

    try {
      await deliverWebhook(webhook, "test", testPayload, db);
      res.json({ ok: true, message: "Test payload sent" });
    } catch (err) {
      log.error({ err }, "test delivery failed");
      res.status(500).json({ error: "delivery_failed", message: "Failed to deliver test payload" });
    }
  });

  // GET /api/webhooks/:id/deliveries — last 20 deliveries
  router.get("/:id/deliveries", requireAuth, requirePlan("premium", "premium_plus"), (req, res) => {
    const userId = req.user!.id;
    const webhook = db
      .prepare("SELECT id FROM webhooks WHERE id = ? AND user_id = ?")
      .get(req.params.id, userId) as { id: string } | undefined;

    if (!webhook) {
      res.status(404).json({ error: "not_found", message: "Webhook not found" });
      return;
    }

    const deliveries = db
      .prepare(
        `SELECT * FROM webhook_deliveries WHERE webhook_id = ?
         ORDER BY created_at DESC LIMIT 20`
      )
      .all(req.params.id) as WebhookDeliveryRow[];

    res.json(
      deliveries.map((d) => ({
        ...d,
        payload_json: JSON.parse(d.payload_json),
      }))
    );
  });

  return router;
}
