import rateLimit from "express-rate-limit";

const isProduction = process.env.NODE_ENV === "production";

/**
 * Rate limiter: 40 requests per minute per client IP in production,
 * 200 in development for testing.
 */
export const rateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: isProduction ? 40 : 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: "rate_limited",
    message: "Too many requests. Please try again later.",
  },
});
