import { Lucia, TimeSpan } from "lucia";
import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import * as arctic from "arctic";
import type Database from "better-sqlite3";

export function createAuth(db: Database.Database) {
  const adapter = new BetterSqlite3Adapter(db, {
    user: "users",
    session: "sessions",
  });

  const lucia = new Lucia(adapter, {
    sessionExpiresIn: new TimeSpan(30, "d"),
    sessionCookie: {
      attributes: {
        secure: process.env.NODE_ENV === "production",
      },
    },
    getUserAttributes: (attributes) => ({
      email: attributes.email,
      name: attributes.name,
      avatarUrl: attributes.avatar_url,
      provider: attributes.provider,
      plan: attributes.plan,
      role: attributes.role,
    }),
  });

  const google = process.env.GOOGLE_CLIENT_ID
    ? new arctic.Google(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET!,
        process.env.GOOGLE_REDIRECT_URI!
      )
    : null;

  const github = process.env.GITHUB_CLIENT_ID
    ? new arctic.GitHub(
        process.env.GITHUB_CLIENT_ID,
        process.env.GITHUB_CLIENT_SECRET!,
        process.env.GITHUB_REDIRECT_URI ?? null
      )
    : null;

  return { lucia, google, github };
}

/** Sync admin role for emails listed in ADMIN_EMAILS env var. Idempotent. */
export function syncAdminEmails(db: import("better-sqlite3").Database): void {
  const adminEmails = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);

  if (adminEmails.length === 0) return;

  const placeholders = adminEmails.map(() => "?").join(", ");
  db.prepare(
    `UPDATE users SET role = 'admin' WHERE LOWER(email) IN (${placeholders})`
  ).run(...adminEmails);
}

declare module "lucia" {
  interface Register {
    Lucia: ReturnType<typeof createAuth>["lucia"];
    DatabaseUserAttributes: DatabaseUserAttributes;
  }
}

interface DatabaseUserAttributes {
  email: string;
  name: string | null;
  avatar_url: string | null;
  provider: "google" | "github";
  plan: "free" | "premium" | "premium_plus";
  role: "user" | "admin";
  last_login_at: string | null;
}
