import type {
  CheckStatus,
  DomainCheckResponse,
  ScoreBreakdown,
  ScoreResponse,
} from "./types.js";

/**
 * Category weights for security scoring (total = 100).
 * SEO and CT Logs are informational — excluded from scoring.
 */
export const WEIGHTS: Record<string, number> = {
  ssl: 15,
  headers: 15,
  spf: 8,
  dmarc: 8,
  dkim: 6,
  dnssec: 6,
  caa: 4,
  redirects: 6,
  blacklist: 8,
  safeBrowsing: 6,
  urlhaus: 4,
  danglingDns: 5,
  domainExpiry: 3,
  securityTxt: 3,
  mx: 2,
  ns: 1,
};

/** Grade thresholds — ordered from highest to lowest. */
export const GRADE_THRESHOLDS: [number, string][] = [
  [95, "A+"],
  [85, "A"],
  [70, "B"],
  [55, "C"],
  [35, "D"],
  [0, "F"],
];

/** Maps a CheckStatus to a numeric score: pass=1, warn=0.5, fail=0. info treated as pass (neutral). */
export function statusToPoints(status: CheckStatus): number {
  if (status === "pass") return 1;
  if (status === "warn") return 0.5;
  if (status === "fail") return 0;
  // "info" — category is informational / not applicable, treat as full points
  return 1;
}

/** Maps a numeric score (0–100) to a letter grade. */
export function computeGrade(total: number): string {
  const clamped = Math.round(Math.max(0, Math.min(100, total)));
  for (const [threshold, grade] of GRADE_THRESHOLDS) {
    if (clamped >= threshold) return grade;
  }
  return "F";
}

/**
 * Calculates the security score from a full DomainCheckResponse.
 *
 * For simple categories (single status), score = statusToPoints(status) × weight.
 * For multi-sub-check categories (headers, spf, dmarc, redirects):
 *   score = (sum of sub-check points / number of sub-checks) × weight.
 *
 * SEO and CT Logs are excluded from scoring.
 */
export function calculateScore(
  checkResults: Partial<DomainCheckResponse>,
): ScoreResponse {
  const breakdown: ScoreBreakdown = {};
  let total = 0;

  for (const [category, weight] of Object.entries(WEIGHTS)) {
    const result = (checkResults as Record<string, any>)[category];

    if (!result) {
      // Category not present in results — skip it entirely
      continue;
    }

    let earned: number;

    if (category === "headers" && result.items && Array.isArray(result.items)) {
      // Multi-sub-check: headers has items[] each with a status
      const items = result.items as { status: CheckStatus }[];
      if (items.length === 0) {
        earned = weight;
      } else {
        const sum = items.reduce((acc: number, item) => acc + statusToPoints(item.status), 0);
        earned = (sum / items.length) * weight;
      }
    } else if (category === "spf" && result.validations && Array.isArray(result.validations)) {
      // Multi-sub-check: spf has validations[] each with a status
      const validations = result.validations as { status: CheckStatus }[];
      if (validations.length === 0) {
        earned = statusToPoints(result.status) * weight;
      } else {
        const sum = validations.reduce((acc: number, v) => acc + statusToPoints(v.status), 0);
        earned = (sum / validations.length) * weight;
      }
    } else if (category === "dmarc" && result.validations && Array.isArray(result.validations)) {
      // Multi-sub-check: dmarc has validations[] each with a status
      const validations = result.validations as { status: CheckStatus }[];
      if (validations.length === 0) {
        earned = statusToPoints(result.status) * weight;
      } else {
        const sum = validations.reduce((acc: number, v) => acc + statusToPoints(v.status), 0);
        earned = (sum / validations.length) * weight;
      }
    } else if (category === "redirects" && result.items && Array.isArray(result.items)) {
      // Multi-sub-check: redirects has items[] each with a status
      const items = result.items as { status: CheckStatus }[];
      if (items.length === 0) {
        earned = statusToPoints(result.status) * weight;
      } else {
        const sum = items.reduce((acc: number, item) => acc + statusToPoints(item.status), 0);
        earned = (sum / items.length) * weight;
      }
    } else {
      // Simple category — single top-level status
      earned = statusToPoints(result.status) * weight;
    }

    breakdown[category] = { earned: Math.round(earned * 100) / 100, max: weight };
    total += earned;
  }

  const roundedTotal = Math.round(total * 100) / 100;
  const grade = computeGrade(roundedTotal);

  return { total: roundedTotal, grade, breakdown };
}
