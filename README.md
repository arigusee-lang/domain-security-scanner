# Domain Security Scanner

A web tool that scans a domain's security posture across DNS, email, TLS, web, and
reputation signals, scores it, and tracks changes over time.

Enter a domain and the scanner runs a battery of checks, streaming results as each
completes, then renders a scored report with remediation guidance.

## Checks

- **TLS/SSL** — certificate validity, expiry, issuer, chain
- **Security headers** — HSTS, CSP, X-Frame-Options, and friends
- **Email auth** — SPF, DMARC, DKIM
- **DNS** — DNSSEC, CAA, nameservers, MX, dangling-DNS detection
- **Certificate Transparency** — CT-log certificate discovery and findings
- **Reputation** — Google Safe Browsing, URLhaus, DNSBL blacklists
- **Domain expiry** — registration expiry via RDAP/WHOIS
- **Redirects** — HTTP→HTTPS and redirect-chain hygiene
- **security.txt** — RFC 9116 presence and validation
- **SEO** — basic indexability signals

## Features

- **Live streaming results** (SSE) — sections render as each check finishes
- **Accounts** — Google / GitHub OAuth (Lucia)
- **Scan history & diffing** — see what changed between scans
- **Batch scans** — check many domains at once
- **Scheduled monitoring** — recurring scans with alerting (BullMQ + Redis)
- **Webhooks** and **report export** (HTML / CSV)
- **Dark / light theme**

## Tech Stack

- **Frontend**: Svelte 4, TypeScript, Vite
- **Backend**: Express, Node.js (run via `tsx`), SSRF-protected fetch proxy
- **Storage**: SQLite (better-sqlite3)
- **Queue / cache**: Redis + BullMQ (degrades gracefully if absent)
- **Auth**: Lucia + Arctic (OAuth)
- **Tests**: Vitest

## Getting Started

```bash
# Install dependencies
npm install

# Copy env and fill in values
cp .env.example .env.local

# Development (two processes)
npm run dev      # Vite dev server on :5173
npm run server   # Express API on :3001

# Run tests
npm test

# Production (serves built frontend + API on one port)
npm run build
npm start
```

See [.env.example](.env.example) for all configuration. External-API keys
(Safe Browsing, URLhaus, CertSpotter, Resend) are optional — checks degrade
gracefully without them.

## Deployment

Deployed to a single GCE `e2-micro` VM with SQLite and Redis co-located on the
same host, behind Cloudflare (proxied DNS, Flexible TLS). See [deploy/](deploy/):

- [deploy/setup-vm.sh](deploy/setup-vm.sh) — one-time VM provisioning
- [deploy/dn-sec.service](deploy/dn-sec.service) — systemd unit

## License

MIT
