import type { Request, Response, NextFunction } from "express";
import type { Lucia, Session, User } from "lucia";

// Extend Express Request to include user and session
declare global {
  namespace Express {
    interface Request {
      user: User | null;
      session: Session | null;
    }
  }
}

/**
 * Creates auth middleware that extracts session from cookie,
 * attaches user to req, and extends session on activity.
 * Non-blocking: if no session, sets req.user = null and continues.
 */
export function createAuthMiddleware(lucia: Lucia) {
  return async function authMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const sessionId = lucia.readSessionCookie(req.headers.cookie ?? "");
    if (!sessionId) {
      req.user = null;
      req.session = null;
      return next();
    }

    try {
      const { session, user } = await lucia.validateSession(sessionId);

      if (session?.fresh) {
        res.appendHeader(
          "Set-Cookie",
          lucia.createSessionCookie(session.id).serialize()
        );
      }
      if (!session) {
        res.appendHeader(
          "Set-Cookie",
          lucia.createBlankSessionCookie().serialize()
        );
      }

      req.user = user;
      req.session = session;
    } catch {
      req.user = null;
      req.session = null;
    }

    next();
  };
}

/**
 * Strict auth guard — returns 401 if not authenticated.
 * Must be used after authMiddleware.
 */
export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.user) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

/**
 * Admin guard — returns 401 if not authenticated, 403 if not admin.
 * Must be used after authMiddleware.
 */
export function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.user) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  if ((req.user as any).role !== "admin") {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  next();
}
