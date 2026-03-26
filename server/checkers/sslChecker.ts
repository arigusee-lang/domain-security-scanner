import type { TlsCertInfo, SslResult } from "../types.js";

export function analyzeSsl(tlsCert: TlsCertInfo | null): SslResult {
  if (!tlsCert) {
    return { status: "fail", issuer: null, subject: null, validFrom: null, validTo: null, daysRemaining: null, sans: [], error: "Could not retrieve TLS certificate" };
  }

  const { issuer, subject, validFrom, validTo, daysRemaining, sans } = tlsCert;

  let status: "pass" | "warn" | "fail";
  if (daysRemaining < 0) {
    status = "fail";
  } else if (daysRemaining <= 30) {
    status = "warn";
  } else {
    status = "pass";
  }

  return { status, issuer, subject, validFrom, validTo, daysRemaining, sans };
}
