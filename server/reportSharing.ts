import crypto from "node:crypto";
import type Database from "better-sqlite3";
import type { ScanRow } from "./types.js";

/**
 * Generate a shareable public link for a scan report.
 * Updates the scans row with share_id, shared=1, and share_expires.
 * Returns the generated share_id (UUID).
 */
export function createShareLink(
  scanId: string,
  userId: string,
  expiresIn: "7d" | "30d" | "never",
  db: Database.Database
): string {
  const scan = db
    .prepare("SELECT id, user_id FROM scans WHERE id = ? AND user_id = ?")
    .get(scanId, userId) as { id: string; user_id: string } | undefined;

  if (!scan) {
    throw new Error("Scan not found or not owned by user");
  }

  const shareId = crypto.randomUUID();

  let shareExpires: string | null = null;
  if (expiresIn === "7d") {
    shareExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  } else if (expiresIn === "30d") {
    shareExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  }
  // "never" → shareExpires stays null

  db.prepare(
    "UPDATE scans SET shared = 1, share_id = ?, share_expires = ? WHERE id = ?"
  ).run(shareId, shareExpires, scanId);

  return shareId;
}

/**
 * Retrieve a shared report by its share_id (reportId).
 * Returns the ScanRow if the link is valid (shared=1, not expired), or null otherwise.
 */
export function getSharedReport(
  reportId: string,
  db: Database.Database
): ScanRow | null {
  const scan = db
    .prepare("SELECT * FROM scans WHERE share_id = ? AND shared = 1")
    .get(reportId) as ScanRow | undefined;

  if (!scan) {
    return null;
  }

  // Check expiry: share_expires is NULL (never) or must be in the future
  if (scan.share_expires !== null && new Date(scan.share_expires) <= new Date()) {
    return null;
  }

  return scan;
}

/**
 * Revoke a shared link for a scan. Clears share fields and sets shared=0.
 * Only the scan owner can revoke.
 */
export function revokeShareLink(
  scanId: string,
  userId: string,
  db: Database.Database
): void {
  const result = db
    .prepare(
      "UPDATE scans SET shared = 0, share_id = NULL, share_expires = NULL WHERE id = ? AND user_id = ?"
    )
    .run(scanId, userId);

  if (result.changes === 0) {
    throw new Error("Scan not found or not owned by user");
  }
}
