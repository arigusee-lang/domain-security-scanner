import type { RemediationInfo } from "./types.js";

/**
 * Static remediation map keyed by "category:checkId".
 * Covers all 14 scored categories with actionable steps.
 */
export const REMEDIATIONS: Record<string, RemediationInfo> = {
  // ── SSL ──
  "ssl:expiring": {
    summary: "Renew your SSL/TLS certificate before it expires",
    steps: [
      "Check your certificate expiration date and plan renewal at least 2 weeks ahead.",
      "If using Let's Encrypt, verify auto-renewal is working: `certbot renew --dry-run`",
      "If using a commercial CA, log into your provider dashboard and initiate renewal.",
      "After renewal, restart your web server to load the new certificate.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://letsencrypt.org/docs/",
  },
  "ssl:expired": {
    summary: "Your SSL/TLS certificate has expired — renew immediately",
    steps: [
      "Renew the certificate immediately through your CA or Let's Encrypt.",
      "For Let's Encrypt: `sudo certbot certonly --nginx -d example.com`",
      "Restart your web server after installing the new certificate.",
      "Enable auto-renewal to prevent future expirations: `sudo certbot renew --deploy-hook 'systemctl reload nginx'`",
    ],
    effort: "low",
    impact: "high",
    ref: "https://letsencrypt.org/docs/",
  },
  "ssl:error": {
    summary: "Fix SSL/TLS certificate configuration errors",
    steps: [
      "Verify the certificate is installed correctly and matches your domain.",
      "Check that the full certificate chain (intermediate + root) is configured.",
      "Test your SSL configuration: `openssl s_client -connect example.com:443 -servername example.com`",
      "Use an online SSL checker to diagnose chain issues.",
    ],
    effort: "medium",
    impact: "high",
    ref: "https://www.ssllabs.com/ssltest/",
  },

  // ── Security Headers ──
  "headers:missing_hsts": {
    summary: "Add Strict-Transport-Security (HSTS) header",
    steps: [
      "Add the HSTS header to your web server configuration.",
      "Nginx: `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;`",
      "Apache: `Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"`",
      "Start with a short max-age (e.g., 300) and increase after verifying HTTPS works correctly.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
  },
  "headers:missing_csp": {
    summary: "Add Content-Security-Policy (CSP) header",
    steps: [
      "Start with a report-only policy to identify violations: `Content-Security-Policy-Report-Only: default-src 'self'`",
      "Refine the policy based on your application's needs (scripts, styles, images, fonts).",
      "Example: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:`",
      "Deploy the enforcing policy once you've resolved all violations.",
    ],
    effort: "medium",
    impact: "high",
    ref: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
  },
  "headers:missing_x_frame": {
    summary: "Add X-Frame-Options header to prevent clickjacking",
    steps: [
      "Add the header to your web server or application response.",
      "Recommended value: `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`",
      "Alternatively, use CSP frame-ancestors directive: `Content-Security-Policy: frame-ancestors 'none'`",
    ],
    effort: "low",
    impact: "medium",
    ref: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
  },
  "headers:missing_x_content_type": {
    summary: "Add X-Content-Type-Options header to prevent MIME sniffing",
    steps: [
      "Add the header: `X-Content-Type-Options: nosniff`",
      "Nginx: `add_header X-Content-Type-Options \"nosniff\" always;`",
      "Apache: `Header always set X-Content-Type-Options \"nosniff\"`",
    ],
    effort: "low",
    impact: "medium",
    ref: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
  },
  "headers:missing_referrer_policy": {
    summary: "Add Referrer-Policy header to control referrer information",
    steps: [
      "Add the header: `Referrer-Policy: strict-origin-when-cross-origin`",
      "This is the recommended default — sends origin on cross-origin requests, full URL on same-origin.",
      "For stricter control, use `no-referrer` or `same-origin`.",
    ],
    effort: "low",
    impact: "low",
    ref: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
  },
  "headers:missing_permissions_policy": {
    summary: "Add Permissions-Policy header to restrict browser features",
    steps: [
      "Add the header to restrict access to sensitive browser APIs.",
      "Example: `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`",
      "This disables camera, microphone, geolocation, and payment APIs for your site.",
      "Adjust based on which features your application actually needs.",
    ],
    effort: "low",
    impact: "low",
    ref: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
  },

  // ── SPF ──
  "spf:missing": {
    summary: "Publish an SPF record to prevent email spoofing",
    steps: [
      "Create a TXT record at your domain root with your SPF policy.",
      "Example: `example.com TXT \"v=spf1 include:_spf.google.com ~all\"`",
      "Replace the include with your email provider's SPF domain.",
      "Use `-all` (hard fail) for strict enforcement or `~all` (soft fail) during rollout.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://www.rfc-editor.org/rfc/rfc7208",
  },
  "spf:too_many_lookups": {
    summary: "Reduce SPF DNS lookups to stay within the 10-lookup limit",
    steps: [
      "Audit your SPF record for unnecessary `include:` mechanisms.",
      "Flatten nested includes by replacing them with direct `ip4:` / `ip6:` ranges.",
      "Use an SPF flattening tool to automate this process.",
      "Consider consolidating email services to reduce the number of includes.",
    ],
    effort: "medium",
    impact: "high",
    ref: "https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4",
  },
  "spf:softfail": {
    summary: "Strengthen SPF policy from ~all (softfail) to -all (hardfail)",
    steps: [
      "Change `~all` to `-all` in your SPF record to reject unauthorized senders.",
      "Before switching, verify all legitimate sending sources are included in your SPF record.",
      "Monitor SPF authentication results for 2–4 weeks after the change.",
    ],
    effort: "low",
    impact: "medium",
    ref: "https://www.rfc-editor.org/rfc/rfc7208#section-5.1",
  },
  "spf:policy_none": {
    summary: "Add an enforcement mechanism to your SPF record",
    steps: [
      "Your SPF record uses `?all` (neutral) or `+all` (pass all), which provides no protection.",
      "Update to `~all` (softfail) as a first step, then move to `-all` (hardfail).",
      "Example: `example.com TXT \"v=spf1 include:_spf.google.com -all\"`",
    ],
    effort: "low",
    impact: "high",
    ref: "https://www.rfc-editor.org/rfc/rfc7208#section-5.1",
  },

  // ── DMARC ──
  "dmarc:missing": {
    summary: "Publish a DMARC record to enforce email authentication",
    steps: [
      "Create a TXT record at `_dmarc.example.com` with your DMARC policy.",
      "Start with monitoring: `_dmarc.example.com TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com\"`",
      "Review aggregate reports for 2–4 weeks to identify legitimate senders.",
      "Upgrade to `p=quarantine` then `p=reject` once you're confident in your SPF/DKIM setup.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://dmarc.org/overview/",
  },
  "dmarc:policy_none": {
    summary: "Upgrade DMARC policy from none to quarantine or reject",
    steps: [
      "Update your DMARC record to enforce authentication.",
      "Step 1: `_dmarc.example.com TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com\"`",
      "Step 2: After monitoring, upgrade to `p=reject` for full enforcement.",
      "Monitor DMARC aggregate reports throughout the transition.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://dmarc.org/overview/",
  },
  "dmarc:no_rua": {
    summary: "Add aggregate report recipients (rua) to your DMARC record",
    steps: [
      "Add the `rua` tag to receive DMARC aggregate reports.",
      "Example: `_dmarc.example.com TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com\"`",
      "Use a DMARC report analysis service (e.g., Postmark, dmarcian) for easier report parsing.",
    ],
    effort: "low",
    impact: "medium",
    ref: "https://dmarc.org/overview/",
  },

  // ── DKIM ──
  "dkim:not_found": {
    summary: "Configure DKIM signing for your email",
    steps: [
      "Generate a DKIM key pair through your email provider (Google Workspace, Microsoft 365, etc.).",
      "Publish the public key as a TXT record: `selector._domainkey.example.com TXT \"v=DKIM1; k=rsa; p=MIGf...\"` ",
      "Enable DKIM signing in your email provider's admin console.",
      "Test by sending an email and checking the DKIM-Signature header.",
    ],
    effort: "medium",
    impact: "medium",
    ref: "https://www.rfc-editor.org/rfc/rfc6376",
  },

  // ── DNSSEC ──
  "dnssec:not_enabled": {
    summary: "Enable DNSSEC to protect DNS integrity",
    steps: [
      "Contact your domain registrar to enable DNSSEC — most support one-click activation.",
      "If self-hosting DNS, generate DNSSEC keys and sign your zone.",
      "Publish DS records at your registrar pointing to your zone's KSK.",
      "Verify with: `dig +dnssec example.com` or use an online DNSSEC analyzer.",
    ],
    effort: "medium",
    impact: "medium",
    ref: "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en",
  },

  // ── CAA ──
  "caa:missing": {
    summary: "Add CAA records to control which CAs can issue certificates",
    steps: [
      "Add CAA DNS records specifying authorized Certificate Authorities.",
      "Example for Let's Encrypt: `example.com CAA 0 issue \"letsencrypt.org\"`",
      "To allow no wildcard certs: `example.com CAA 0 issuewild \";\"`",
      "Add an iodef record for violation reports: `example.com CAA 0 iodef \"mailto:security@example.com\"`",
    ],
    effort: "low",
    impact: "medium",
    ref: "https://www.rfc-editor.org/rfc/rfc8659",
  },

  // ── Blacklist ──
  "blacklist:listed": {
    summary: "Investigate and resolve blacklist listing",
    steps: [
      "Check why your IP was listed at the specific DNSBL provider's lookup page.",
      "Common causes: compromised server, open relay, spam complaints, malware.",
      "Scan your server for malware and check for unauthorized email sending.",
      "Request delisting from each provider after resolving the root cause.",
      "Monitor your IP reputation regularly to catch future listings early.",
    ],
    effort: "high",
    impact: "high",
    ref: "https://www.spamhaus.org/lookup/",
  },

  // ── Dangling DNS ──
  "danglingDns:dangling_found": {
    summary: "Fix dangling DNS records to prevent subdomain takeover",
    steps: [
      "Identify the DNS records (MX or NS) pointing to non-resolving hostnames.",
      "Either update the records to point to valid, active hostnames, or remove them.",
      "Dangling MX records can be exploited to intercept email.",
      "Dangling NS records are critical — they enable full subdomain takeover.",
      "Audit your DNS records regularly for stale entries.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
  },

  // ── Domain Expiry ──
  "domainExpiry:expiring": {
    summary: "Renew your domain before it expires",
    steps: [
      "Log into your domain registrar and renew the domain.",
      "Enable auto-renewal to prevent accidental expiration.",
      "Consider registering for multiple years to reduce renewal risk.",
      "Set calendar reminders for 60, 30, and 14 days before expiration.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://www.icann.org/resources/pages/expired-2013-05-03-en",
  },
  "domainExpiry:expired": {
    summary: "Your domain has expired — renew immediately",
    steps: [
      "Contact your registrar immediately to renew the domain.",
      "Most registrars offer a redemption grace period (30–45 days) after expiration.",
      "After the grace period, the domain may be released for public registration.",
      "Enable auto-renewal after recovering the domain to prevent recurrence.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://www.icann.org/resources/pages/expired-2013-05-03-en",
  },

  // ── Redirects ──
  "redirects:no_https": {
    summary: "Configure HTTP to HTTPS redirect",
    steps: [
      "Set up a server-level redirect from HTTP (port 80) to HTTPS (port 443).",
      "Nginx: `server { listen 80; server_name example.com; return 301 https://$host$request_uri; }`",
      "Apache: `RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`",
      "Also add HSTS header to prevent future insecure connections.",
    ],
    effort: "low",
    impact: "high",
    ref: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
  },
  "redirects:no_redirect": {
    summary: "Ensure HTTP requests are redirected to HTTPS",
    steps: [
      "Your HTTP endpoint serves content without redirecting to HTTPS.",
      "Configure your web server to issue a 301 redirect from HTTP to HTTPS.",
      "Test with: `curl -I http://example.com` — should return 301 with Location: https://...",
    ],
    effort: "low",
    impact: "high",
    ref: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
  },

  // ── Security.txt ──
  "securityTxt:not_found": {
    summary: "Create a security.txt file for vulnerability disclosure",
    steps: [
      "Create a file at `/.well-known/security.txt` on your web server.",
      "Required fields: `Contact:` (email or URL) and `Expires:` (ISO 8601 date).",
      "Example:\n  Contact: mailto:security@example.com\n  Expires: 2026-12-31T23:59:59Z\n  Preferred-Languages: en",
      "Optionally sign the file with PGP for authenticity.",
    ],
    effort: "low",
    impact: "low",
    ref: "https://www.rfc-editor.org/rfc/rfc9116",
  },
  "securityTxt:invalid": {
    summary: "Fix validation errors in your security.txt file",
    steps: [
      "Review your security.txt file for missing required fields (Contact, Expires).",
      "Ensure the Expires date is in ISO 8601 format and is in the future.",
      "Ensure Contact URIs use `mailto:` or `https://` schemes.",
      "Use an online validator to check for additional issues.",
    ],
    effort: "low",
    impact: "low",
    ref: "https://www.rfc-editor.org/rfc/rfc9116",
  },

  // ── Safe Browsing ──
  "safeBrowsing:flagged": {
    summary: "Resolve Google Safe Browsing warnings on your domain",
    steps: [
      "Check the Google Safe Browsing transparency report for details on the threat.",
      "Scan your website for malware, phishing pages, or unwanted software.",
      "Remove any malicious content and patch the vulnerability that allowed it.",
      "Submit a review request through Google Search Console after cleanup.",
      "Monitor your site regularly for reinfection.",
    ],
    effort: "high",
    impact: "high",
    ref: "https://transparencyreport.google.com/safe-browsing/search",
  },

  // ── URLhaus ──
  "urlhaus:listed": {
    summary: "Investigate and resolve URLhaus malware listing",
    steps: [
      "Check your domain on URLhaus (urlhaus.abuse.ch) for listed malicious URLs.",
      "Scan your server for compromised files, backdoors, or malware droppers.",
      "Remove all malicious content and patch the exploited vulnerability.",
      "Update your CMS, plugins, and server software to the latest versions.",
      "Request removal from URLhaus after cleanup is complete.",
    ],
    effort: "high",
    impact: "high",
    ref: "https://urlhaus.abuse.ch/",
  },
};

/**
 * Look up remediation info for a given category and check ID.
 * Returns null if no remediation is defined for the combination.
 */
export function getRemediation(
  category: string,
  checkId: string,
): RemediationInfo | null {
  return REMEDIATIONS[`${category}:${checkId}`] ?? null;
}
