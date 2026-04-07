import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import { createShareLink, getSharedReport, revokeShareLink } from "../reportSharing.js";
import { initDatabase } from "../db.js";

describe("reportSharing", () => {
  let db: Database.Database;

  beforeEach(() => {
    db = initDatabase(":memory:");
    // Insert a test user
    db.prepare(
      "INSERT INTO users (id, email, provider, provider_id) VALUES (?, ?, ?, ?)"
    ).run("user-1", "test@example.com", "github", "gh-123");
    // Insert a completed scan owned by user-1
    db.prepare(
      `INSERT INTO scans (id, user_id, domain, scan_type, status, score, grade, result_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).run("scan-1", "user-1", "example.com", "single", "completed", 85, "A", '{"test":true}');
  });

  afterEach(() => {
    db.close();
  });

  describe("createShareLink", () => {
    it("generates a UUID share_id and sets shared=1", () => {
      const shareId = createShareLink("scan-1", "user-1", "7d", db);
      expect(shareId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
      const scan = db.prepare("SELECT shared, share_id, share_expires FROM scans WHERE id = ?").get("scan-1") as any;
      expect(scan.shared).toBe(1);
      expect(scan.share_id).toBe(shareId);
      expect(scan.share_expires).not.toBeNull();
    });

    it("sets share_expires ~7 days in the future for '7d'", () => {
      createShareLink("scan-1", "user-1", "7d", db);
      const scan = db.prepare("SELECT share_expires FROM scans WHERE id = ?").get("scan-1") as any;
      const expires = new Date(scan.share_expires).getTime();
      const expected = Date.now() + 7 * 24 * 60 * 60 * 1000;
      expect(Math.abs(expires - expected)).toBeLessThan(5000);
    });

    it("sets share_expires ~30 days in the future for '30d'", () => {
      createShareLink("scan-1", "user-1", "30d", db);
      const scan = db.prepare("SELECT share_expires FROM scans WHERE id = ?").get("scan-1") as any;
      const expires = new Date(scan.share_expires).getTime();
      const expected = Date.now() + 30 * 24 * 60 * 60 * 1000;
      expect(Math.abs(expires - expected)).toBeLessThan(5000);
    });

    it("sets share_expires to NULL for 'never'", () => {
      createShareLink("scan-1", "user-1", "never", db);
      const scan = db.prepare("SELECT share_expires FROM scans WHERE id = ?").get("scan-1") as any;
      expect(scan.share_expires).toBeNull();
    });

    it("throws if scan not found", () => {
      expect(() => createShareLink("nonexistent", "user-1", "7d", db)).toThrow(
        "Scan not found or not owned by user"
      );
    });

    it("throws if user does not own the scan", () => {
      db.prepare(
        "INSERT INTO users (id, email, provider, provider_id) VALUES (?, ?, ?, ?)"
      ).run("user-2", "other@example.com", "google", "g-456");
      expect(() => createShareLink("scan-1", "user-2", "7d", db)).toThrow(
        "Scan not found or not owned by user"
      );
    });
  });

  describe("getSharedReport", () => {
    it("returns the scan for a valid share link", () => {
      const shareId = createShareLink("scan-1", "user-1", "7d", db);
      const result = getSharedReport(shareId, db);
      expect(result).not.toBeNull();
      expect(result!.id).toBe("scan-1");
      expect(result!.domain).toBe("example.com");
    });

    it("returns the scan for a 'never' expiry link", () => {
      const shareId = createShareLink("scan-1", "user-1", "never", db);
      const result = getSharedReport(shareId, db);
      expect(result).not.toBeNull();
      expect(result!.id).toBe("scan-1");
    });

    it("returns null for an expired link", () => {
      const shareId = createShareLink("scan-1", "user-1", "7d", db);
      // Manually set share_expires to the past
      db.prepare("UPDATE scans SET share_expires = ? WHERE id = ?").run(
        new Date(Date.now() - 1000).toISOString(),
        "scan-1"
      );
      const result = getSharedReport(shareId, db);
      expect(result).toBeNull();
    });

    it("returns null for a revoked link", () => {
      const shareId = createShareLink("scan-1", "user-1", "7d", db);
      revokeShareLink("scan-1", "user-1", db);
      const result = getSharedReport(shareId, db);
      expect(result).toBeNull();
    });

    it("returns null for a nonexistent share_id", () => {
      const result = getSharedReport("nonexistent-id", db);
      expect(result).toBeNull();
    });
  });

  describe("revokeShareLink", () => {
    it("clears share fields and sets shared=0", () => {
      createShareLink("scan-1", "user-1", "7d", db);
      revokeShareLink("scan-1", "user-1", db);
      const scan = db.prepare("SELECT shared, share_id, share_expires FROM scans WHERE id = ?").get("scan-1") as any;
      expect(scan.shared).toBe(0);
      expect(scan.share_id).toBeNull();
      expect(scan.share_expires).toBeNull();
    });

    it("throws if scan not found or not owned", () => {
      expect(() => revokeShareLink("nonexistent", "user-1", db)).toThrow(
        "Scan not found or not owned by user"
      );
    });

    it("throws if user does not own the scan", () => {
      db.prepare(
        "INSERT INTO users (id, email, provider, provider_id) VALUES (?, ?, ?, ?)"
      ).run("user-2", "other@example.com", "google", "g-456");
      expect(() => revokeShareLink("scan-1", "user-2", db)).toThrow(
        "Scan not found or not owned by user"
      );
    });
  });
});
