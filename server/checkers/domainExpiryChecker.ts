import type { DomainExpiryResult } from "../types.js";

export async function checkDomainExpiry(domain: string, timeout: number = 8000): Promise<DomainExpiryResult> {
  // Extract the registrable domain (last two parts) for RDAP lookup
  const parts = domain.split(".");
  const rdapDomain = parts.length > 2 ? parts.slice(-2).join(".") : domain;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(`https://rdap.org/domain/${rdapDomain}`, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json" },
    });
    clearTimeout(timer);

    if (!response.ok) {
      return { status: "info", expirationDate: null, daysRemaining: null, error: `RDAP returned HTTP ${response.status}` };
    }

    const data = await response.json() as any;
    const expirationEvent = data.events?.find((e: any) => e.eventAction === "expiration");

    if (!expirationEvent?.eventDate) {
      return { status: "info", expirationDate: null, daysRemaining: null, error: "No expiration date in RDAP response" };
    }

    const expirationDate = new Date(expirationEvent.eventDate).toISOString();
    const daysRemaining = Math.floor((new Date(expirationEvent.eventDate).getTime() - Date.now()) / 86400000);

    let status: "pass" | "warn" | "fail";
    if (daysRemaining < 0) {
      status = "fail";
    } else if (daysRemaining <= 60) {
      status = "warn";
    } else {
      status = "pass";
    }

    return { status, expirationDate, daysRemaining };
  } catch (err: any) {
    return { status: "info", expirationDate: null, daysRemaining: null, error: "RDAP lookup failed" };
  }
}
