/**
 * Maps a leaf-certificate issuer to the CDN/cloud provider that manages
 * (and auto-rotates) the cert. When matched, the domain owner doesn't need
 * to track expiry themselves — the provider handles it.
 *
 * Matching is intentionally conservative: substring/keyword patterns against
 * the normalized issuer name. False positives here would silence a real
 * expiry alert, so we only flag when there's a clear signal.
 *
 * The `cdnProvider` hint (from blacklist CIDR detection) lets us safely match
 * short issuer aliases like "WE1" / "E1" that would be ambiguous on their own.
 */

interface IssuerRule {
  /** Display name shown to the user. */
  name: string;
  /** Lowercase substrings — any match flags the issuer as managed. */
  patterns: string[];
  /** When set, the rule only fires if blacklist's CDN detection agrees. */
  requiresCdn?: string;
}

const RULES: IssuerRule[] = [
  // Cloudflare Universal SSL: most edge certs are issued under "Cloudflare Inc
  // ECC CA-3" / "RSA CA-2", or under their newer short-CA aliases ("WE1",
  // "WE2", "E1", "E2"). The short aliases are ambiguous in isolation, so we
  // gate them on Cloudflare CDN detection.
  { name: "Cloudflare", patterns: ["cloudflare"] },
  { name: "Cloudflare", patterns: ["we1", "we2", "e1", "e2"], requiresCdn: "Cloudflare" },

  // AWS Certificate Manager (CloudFront, ALB): issued by Amazon CAs.
  { name: "AWS ACM", patterns: ["amazon"] },

  // Google managed certs (GCP HTTPS LB, App Engine, Cloud Run domain mapping):
  // issued by Google Trust Services (GTS).
  { name: "Google Cloud", patterns: ["google trust services", "gts ca", "gts root"] },

  // Fastly managed TLS — uses GlobalSign Atlas under the hood. Gate on Fastly
  // CDN detection because GlobalSign Atlas also issues for non-Fastly customers.
  { name: "Fastly", patterns: ["globalsign atlas"], requiresCdn: "Fastly" },

  // Azure Front Door / App Service managed certs.
  { name: "Azure", patterns: ["microsoft azure", "microsoft rsa tls"] },

  // Meta (Facebook / Instagram / WhatsApp) buys commercial certs from DigiCert
  // and rotates them on a tight ~7-day cycle across its fleet. The end user
  // doesn't manage these — Meta does. Gated on Meta CDN detection so generic
  // DigiCert certs on unrelated domains don't get misflagged.
  { name: "Meta", patterns: ["digicert"], requiresCdn: "Meta" },
];

/**
 * Detect whether a cert is auto-managed by a known CDN/cloud provider.
 * Returns the provider name when matched, or null otherwise.
 */
export function detectManagedCert(
  issuer: string | null | undefined,
  cdnProvider: string | null | undefined,
): string | null {
  if (!issuer) return null;
  const lower = issuer.toLowerCase();
  for (const rule of RULES) {
    if (rule.requiresCdn && rule.requiresCdn !== cdnProvider) continue;
    if (rule.patterns.some((p) => lower.includes(p))) {
      return rule.name;
    }
  }
  return null;
}
