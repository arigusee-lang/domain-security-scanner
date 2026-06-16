# Scoring Revision Plan

Goal: redo per-check severity assignment so the score reflects real impact,
and the SummaryBar counts match what the user sees on the page.

## Severity Levels

Each check gets one of four levels. They do **not** map 1:1 to status —
e.g. a `fail` on a low-impact check can still be level 1, and a `warn` on
a critical one can be level 3.

| Level | Meaning | Score weight |
|---|---|---|
| **0** | Informational only — surfaced as a note, not a warning | 0 (no score impact) |
| **1** | Minor — nice to have, narrow impact | low |
| **2** | Medium — meaningful security or operational risk | medium |
| **3** | Critical — real attack surface or user-facing security gap | high |

## Status × Severity → score points

For each check the score contribution is:

```
points_earned = statusToPoints(status) × level_weight
```

where `statusToPoints` is `pass=1`, `warn=0.5`, `fail=0`, `info=1` (neutral).
Level 0 checks always contribute 0.

---

## Security Headers (total weight: 15)

| Header | Level | Weight | Rationale |
|---|---|---|---|
| **Strict-Transport-Security** (HSTS) | 3 | 5 | Without HSTS the first hit to `http://` is interceptable (Wi-Fi MITM) before the 301 redirect lands. Baseline for any business site. |
| **Content-Security-Policy** (CSP) | 3 | 5 | Most powerful security header. Any XSS bug is instantly exploitable without it. |
| **X-Frame-Options** | 2 | 2 | Clickjacking protection. Deprecated in favor of `CSP: frame-ancestors` — when CSP has `frame-ancestors` set, the old header is redundant. *Cross-check pending: drop to level 1 when CSP covers it.* |
| **X-Content-Type-Options** | 1 | 1 | MIME-sniffing edge cases. Modern browsers default to strict behavior for critical types. |
| **Referrer-Policy** | 1 | 1 | Privacy (URL/query string leakage to third parties), not direct security. |
| **Permissions-Policy** | 0 | 1 | Niche — restricts native browser features. Real impact small for typical sites. Show as info, not warn. |
| **X-XSS-Protection** | 0 | 0 | Deprecated and harmful in old browsers — checker correctly warns when *present*. No score impact either way. |

### Open items
- [ ] CSP `frame-ancestors` cross-check → drop X-Frame-Options to level 1 when present
- [ ] Stronger CSP analysis (`unsafe-inline` / `unsafe-eval` should not be `pass`)
- [ ] Switch Permissions-Policy missing → `info` instead of `warn`

---

## DNS & Domain (total weight: 18)

Card aggregates 5 sub-checks. Card status = worst of internal statuses.

| Check | Level | Weight | Rationale |
|---|---|---|---|
| **DNSSEC** | 1 | 3 | HTTPS already covers the main MITM threats. DNSSEC adds protection for DNS responses themselves (matters for MX/email routing and legacy systems without ubiquitous HTTPS), but adoption is <10% even among top sites — Google, Facebook, Twitter do not use it. Nice-to-have, not a blocker. |
| **CAA** | 2 | 5 | Controls which CAs may issue certs for the domain. Biggest value is as a **cross-check with CT logs** — a cert from a CA not in the CAA list is a strong misissuance signal. With `iodef:mailto:...`, CAs can email alerts on issuance attempts. Real security control. |
| **NS** | 0 | 0 | Foundation: no NS → domain unresolvable → every other check fails anyway. **Validity check, not security**. Show as info in UI, no score impact. |
| **danglingDns** | 3 (NS) / 2 (MX) | 6 | Exploitable vulnerability. Dangling NS = attacker can register the abandoned nameserver domain and control your DNS. Dangling MX = email hijack. Checker already splits via status: NS→fail (0 points), MX→warn (0.5 × 6). Single weight. |
| **domainExpiry** | 2 | 4 | Operational risk: expired domain → attacker registers it → brand/email/identity loss. Not security per se (HTTPS doesn't help), but the impact looks like one. |
| **Total** |  | **18** | (was 19) |

### Open items
- [ ] **Revise expiry thresholds**: `<90d → info` (early nudge), `<30d → warn`, `<7d → fail`. Currently `<=60d → warn`, `<0d → fail`.
- [ ] CAA `iodef` parsing — surface as info if present (positive signal that owner monitors misissuance)
- [ ] DNSSEC chain-of-trust validation, not just DS presence (currently we only check DS records exist)

---

## Reputation (total weight: 17)

Card aggregates 3 sub-checks (Safe Browsing, URLhaus, DNSBL). Card status = worst.

| Check | Level | Weight | Rationale |
|---|---|---|---|
| **Google Safe Browsing** | 3 | 8 | **Direct user-facing impact**. Listing triggers the red "Deceptive site ahead" interstitial in Chrome/Firefox/Safari — ~70%+ of browser traffic effectively blocked. This is a live production-outage signal, not metadata. A `fail` here should noticeably drop the score. |
| **URLhaus** | 2 | 4 | abuse.ch's malware-hosting database. Doesn't block users directly, but a listing usually means the site is compromised (CMS/plugin) and now serves malware. Serious investigation trigger, not "site is down". |
| **Blacklist (DNSBL)** | 2 | 5 | Domain-based DNSBL (Spamhaus DBL, SURBL) → mail dropped by many receivers. IP-based is noisy for shared CDN edge IPs — UI already hides those, but the scoring path doesn't yet (see open items). |
| **Total** |  | **17** | (was 18) |

### Open items
- [ ] **Don't penalize IP-DNSBL when behind a CDN**. `checkBlacklist` currently sets `warn` if *any* provider is listed, including IP-DNSBL on a shared edge IP. When `infrastructure.cdnProvider != null`, only domain-based DNSBL hits should count toward the status.
- [ ] **No-mail downgrade for blacklist** (analog to SPF/DMARC): if the domain has no MX (or Null MX per RFC 7505), domain-based DNSBL is also irrelevant — surface as info, don't penalize.

---

## Pending categories

To be discussed/assigned next:

- [ ] Email Security (SPF, DMARC, DKIM, MX)
- [ ] Email Security (SPF, DMARC, DKIM, MX)
- [ ] security.txt
- [ ] SSL/TLS (chain validity, expiry, CT compliance, edges consistency, managedBy)
- [ ] Certificate Transparency (CT logs)
- [ ] Redirects
- [ ] SEO (informational — likely level 0)

## Implementation order

1. Land severity table for all categories (this doc finished)
2. Update `server/scoreCalculator.ts` weights to match
3. Update `server/checkers/headersAnalyzer.ts` to emit `info` instead of `warn`
   where the new severity says it shouldn't penalize
4. Update `src/components/DomainCheckerPage.svelte` SummaryBar to count
   **per card** (worst of internal checks), so counts match the visible UI
5. Mirror in `server/lib/reportRenderer.ts:renderSummaryBar`
