import { config as loadEnv } from "dotenv";
import path from "node:path";

// Load env file: .env.local for dev, .env.production for prod
const envFile = process.env.NODE_ENV === "production" ? ".env.production" : ".env.local";
loadEnv({ path: path.resolve(process.cwd(), envFile) });
// Fallback: also try .env
loadEnv();

import express from "express";
import cors from "cors";
import compression from "compression";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "node:url";
import { rateLimiter } from "./middleware/rateLimit.js";
import { validateRequest } from "./middleware/validateRequest.js";
import fetchRoute from "./routes/fetch.js";
import { createDomainCheckRoutes } from "./routes/domainCheck.js";
import { initDatabase, cleanupOldScans, checkDatabaseSize } from "./db.js";
import { createAuth } from "./auth.js";
import { createAuthMiddleware } from "./middleware/authMiddleware.js";
import { createAuthRoutes } from "./routes/auth.js";
import { createScansRoutes } from "./routes/scans.js";
import { createBatchRoutes } from "./routes/batch.js";
import { createScheduledRoutes } from "./routes/scheduled.js";
import { createCronRoutes } from "./routes/cron.js";
import { createWebhooksRoutes } from "./routes/webhooks.js";
import { createReportsRoutes } from "./routes/reports.js";
import { ctLogsReady } from "./checkers/knownCtLogs.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env.NODE_ENV === "production";

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;

// ── Initialize SQLite database ──
const db = initDatabase();

// ── Set up Lucia Auth ──
const { lucia, google, github } = createAuth(db);

// ── Gzip/brotli compression for all responses ──
app.use(compression());

// ── CORS — needed in dev for cross-origin cookie support ──
if (!isProduction) {
  app.use(
    cors({
      origin: process.env.CORS_ORIGIN || "http://localhost:5173",
      credentials: true,
    })
  );
}

// ── Parse cookies (needed for OAuth state cookies and session cookies) ──
app.use(cookieParser());

// ── Parse JSON bodies for POST/PUT/PATCH ──
app.use(express.json());

// ── Security headers ──
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// ── Auth middleware (non-blocking — attaches user if present) ──
app.use(createAuthMiddleware(lucia));

// ── Rate limiting on API routes ──
app.use("/api", rateLimiter);

// ── Auth routes (OAuth, logout, me) ──
app.use("/api/auth", createAuthRoutes({ lucia, google, github, db }));

// ── Existing routes ──
app.use("/api/fetch", validateRequest, fetchRoute);
app.use("/api/domain-check", validateRequest, createDomainCheckRoutes({ db }));

// ── New API routes ──
app.use("/api/scans", createScansRoutes({ db, lucia }));
app.use("/api/batch", createBatchRoutes({ db, lucia }));
app.use("/api/scheduled", createScheduledRoutes({ db, lucia }));
app.use("/api/cron", createCronRoutes({ db }));
app.use("/api/webhooks", createWebhooksRoutes({ db, lucia }));
app.use("/api/reports", createReportsRoutes({ db }));

// ── In production, serve the built frontend ──
if (isProduction) {
  const distPath = path.resolve(__dirname, "..", "dist");
  app.use(express.static(distPath, { maxAge: "1y", immutable: true }));
  // index.html should not be cached aggressively
  app.get("*", (_req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    res.sendFile(path.join(distPath, "index.html"));
  });
}

// ── Startup tasks ──
try {
  const deleted = cleanupOldScans(db);
  if (deleted > 0) {
    console.log(`[startup] Cleaned up ${deleted} old scan records`);
  }
} catch (err) {
  console.error("[startup] Failed to cleanup old scans:", err);
}

checkDatabaseSize(db);

// Wait for CT log registry before accepting requests
await ctLogsReady;

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT} (${isProduction ? "production" : "development"})`);
});

export default app;
