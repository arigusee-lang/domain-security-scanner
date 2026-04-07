import crypto from "node:crypto";
import type { WebhookRow } from "./types.js";
import type Database from "better-sqlite3";

/**
 * Compute HMAC-SHA256 signature for a webhook payload.
 */
export function signPayload(payload: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

/**
 * Generate a webhook secret with `whsec_` prefix.
 */
export function generateSecret(): string {
  return `whsec_${crypto.randomBytes(24).toString("hex")}`;
}

/** Retry delays in milliseconds: 10s, 30s, 90s */
const RETRY_DELAYS = [10_000, 30_000, 90_000];

/** Timeout per delivery attempt in milliseconds */
const DELIVERY_TIMEOUT_MS = 10_000;

/** Consecutive failures to mark webhook as failing */
const FAILING_THRESHOLD = 3;

/** Consecutive failures to auto-disable webhook */
const DISABLE_THRESHOLD = 10;

/**
 * Deliver a webhook event to the configured URL.
 *
 * - Signs the payload with HMAC-SHA256 and includes X-Signature-256 header
 * - Retries up to 3 times with exponential backoff (10s, 30s, 90s)
 * - 10s timeout per attempt via AbortController
 * - Tracks fail_count: marks as failing at 3, disables at 10
 * - Resets fail_count on success
 * - Logs each delivery to webhook_deliveries table
 */
export async function deliverWebhook(
  webhook: WebhookRow,
  event: string,
  payload: object,
  db: Database.Database
): Promise<void> {
  const deliveryId = crypto.randomUUID();
  const payloadStr = JSON.stringify(payload);
  const signature = signPayload(payloadStr, webhook.secret);

  // Insert pending delivery record
  db.prepare(
    `INSERT INTO webhook_deliveries (id, webhook_id, event, payload_json, status, attempts, created_at)
     VALUES (?, ?, ?, ?, 'pending', 0, datetime('now'))`
  ).run(deliveryId, webhook.id, event, payloadStr);

  let lastError: string | null = null;
  let responseCode: number | null = null;
  let delivered = false;

  for (let attempt = 0; attempt < RETRY_DELAYS.length; attempt++) {
    // Wait for retry delay (skip on first attempt)
    if (attempt > 0) {
      await sleep(RETRY_DELAYS[attempt - 1]);
    }

    // Update attempt count
    db.prepare(
      `UPDATE webhook_deliveries SET attempts = ? WHERE id = ?`
    ).run(attempt + 1, deliveryId);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

      const response = await fetch(webhook.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Signature-256": signature,
        },
        body: payloadStr,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      responseCode = response.status;

      if (response.ok) {
        delivered = true;
        break;
      }

      lastError = `HTTP ${response.status}`;
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        lastError = "Request timed out";
      } else {
        lastError = err instanceof Error ? err.message : String(err);
      }
    }
  }

  if (delivered) {
    // Mark delivery as delivered
    db.prepare(
      `UPDATE webhook_deliveries
       SET status = 'delivered', response_code = ?, delivered_at = datetime('now')
       WHERE id = ?`
    ).run(responseCode, deliveryId);

    // Reset fail counters on success
    db.prepare(
      `UPDATE webhooks SET fail_count = 0, failing = 0 WHERE id = ?`
    ).run(webhook.id);
  } else {
    // Mark delivery as failed
    db.prepare(
      `UPDATE webhook_deliveries
       SET status = 'failed', response_code = ?, error = ?
       WHERE id = ?`
    ).run(responseCode, lastError, deliveryId);

    // Increment fail_count and check thresholds
    const newFailCount = webhook.fail_count + 1;

    if (newFailCount >= DISABLE_THRESHOLD) {
      db.prepare(
        `UPDATE webhooks SET fail_count = ?, failing = 1, enabled = 0 WHERE id = ?`
      ).run(newFailCount, webhook.id);
    } else if (newFailCount >= FAILING_THRESHOLD) {
      db.prepare(
        `UPDATE webhooks SET fail_count = ?, failing = 1 WHERE id = ?`
      ).run(newFailCount, webhook.id);
    } else {
      db.prepare(
        `UPDATE webhooks SET fail_count = ? WHERE id = ?`
      ).run(newFailCount, webhook.id);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
