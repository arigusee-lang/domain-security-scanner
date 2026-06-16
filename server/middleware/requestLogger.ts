import type { Request, Response, NextFunction } from "express";
import { performance } from "node:perf_hooks";
import { createLogger } from "../lib/logger.js";

const log = createLogger("http");

// Bull-board polls its own API every few seconds — keep the scan/admin paths
// in the log but drop the firehose of bull-board's internal calls.
function shouldSkip(url: string): boolean {
  if (url.startsWith("/admin/queues/api/")) return true;
  if (url === "/admin/queues" || url.startsWith("/admin/queues/static/")) return true;
  return false;
}

/** First non-loopback X-Forwarded-For entry, falling back to req.ip. */
function clientIp(req: Request): string | undefined {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length > 0) return fwd.split(",")[0].trim();
  return req.ip;
}

export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  if (shouldSkip(req.url)) {
    next();
    return;
  }
  const start = performance.now();
  res.on("finish", () => {
    const durationMs = Math.round(performance.now() - start);
    const status = res.statusCode;
    const fields = {
      method: req.method,
      path: req.originalUrl || req.url,
      status,
      durationMs,
      ip: clientIp(req),
      userId: req.user?.id,
    };
    if (status >= 500) {
      log.error(fields, "request");
    } else if (status >= 400) {
      log.warn(fields, "request");
    } else {
      log.info(fields, "request");
    }
  });
  next();
}
