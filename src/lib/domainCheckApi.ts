import type { DomainCheckResult } from "./types";

const API_URL = "/api/domain-check";
const TIMEOUT_MS = 15_000;

export async function fetchDomainCheck(domain: string): Promise<DomainCheckResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(`${API_URL}?domain=${encodeURIComponent(domain)}`, {
      signal: controller.signal,
    });

    if (!response.ok) {
      const data = await response.json().catch(() => null);
      throw new Error(data?.message || `Server returned HTTP ${response.status}`);
    }

    return await response.json();
  } catch (err: any) {
    if (err.name === "AbortError") {
      throw new Error("Request timed out. Please try again.");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
