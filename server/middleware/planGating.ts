import type { Request, Response, NextFunction } from "express";

/**
 * Middleware factory that restricts access to users with specific plans.
 * Returns 401 if not authenticated, 403 if user's plan is not in the allowed list.
 */
export function requirePlan(...plans: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    if (!plans.includes(req.user.plan)) {
      res.status(403).json({
        error: "plan_required",
        message: `This feature requires a ${plans.join(" or ")} plan`,
      });
      return;
    }
    next();
  };
}
