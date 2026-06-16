import dns from "node:dns/promises";
import type { DkimResult, DkimSelectorResult } from "../types.js";
import { createLogger } from "../lib/logger.js";
import { safeResolve } from "../lib/dnsResolve.js";

const log = createLogger("dkim");

const SELECTORS: { selector: string; service: string }[] = [
  { selector: "google", service: "Google Workspace" },
  { selector: "default", service: "Generic" },
  { selector: "selector1", service: "Microsoft 365" },
  { selector: "selector2", service: "Microsoft 365" },
  { selector: "k1", service: "Mailchimp" },
  { selector: "k2", service: "Mailchimp" },
  { selector: "s1", service: "Generic" },
  { selector: "mail", service: "Generic" },
  { selector: "mailjet", service: "Mailjet" },
  { selector: "mandrill", service: "Mailchimp Transactional" },
  { selector: "dkim", service: "Generic" },
  { selector: "mta0", service: "Generic" },
  { selector: "gm1", service: "Generic" },
  { selector: "zendesk", service: "Zendesk" },
];

export async function checkDkim(domain: string, timeout: number = 5000): Promise<DkimResult> {
  const results = await Promise.allSettled(
    SELECTORS.map(async ({ selector, service }): Promise<DkimSelectorResult> => {
      try {
        const records = await safeResolve(() => dns.resolveTxt(`${selector}._domainkey.${domain}`), timeout);
        const record = records.map(r => r.join("")).join("");
        return { selector, service, found: true, record };
      } catch (err: any) {
        if (err?.message === "timeout") {
          log.warn({ domain, selector }, "DNS lookup timed out");
        }
        return { selector, service, found: false };
      }
    })
  );

  const selectors: DkimSelectorResult[] = results.map(r =>
    r.status === "fulfilled" ? r.value : { selector: "unknown", service: "Unknown", found: false }
  );

  const foundCount = selectors.filter(s => s.found).length;

  return {
    status: foundCount > 0 ? "pass" : "info",
    foundCount,
    totalChecked: SELECTORS.length,
    selectors,
  };
}
