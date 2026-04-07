/** Response from the proxy fetch endpoint on success */
export interface ProxyFetchResponse {
  success: true;
  content: string;
  contentType: string;
  fetchedFrom: string;
  redirectChain: string[];
  wellKnownFound: boolean;
  fallbackUsed: boolean;
}

/** Error response from the proxy */
export interface ProxyFetchError {
  success: false;
  error:
    | "timeout"
    | "size_limit"
    | "dns_failure"
    | "http_error"
    | "ssrf_blocked"
    | "invalid_content_type"
    | "not_found"
    | "too_many_redirects"
    | "invalid_request"
    | "internal";
  message: string;
  httpStatus?: number;
}

export type ProxyResponse = ProxyFetchResponse | ProxyFetchError;

// ── Domain Security Checker types ──

/** Status outcome for a single check item */
export type CheckStatus = "pass" | "warn" | "fail" | "info";

/** TLS certificate details extracted from the HTTPS connection */
export interface TlsCertInfo {
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  sans: string[];
}

/** Extended response from safeFetchWithHeaders */
export interface SafeFetchWithHeadersResponse {
  success: true;
  content: string;
  contentType: string;
  fetchedFrom: string;
  redirectChain: string[];
  wellKnownFound: boolean;
  fallbackUsed: boolean;
  responseHeaders: Record<string, string>;
  tlsCert: TlsCertInfo | null;
}

// ── Headers ──

export interface HeaderCheckItem {
  name: string;
  present: boolean;
  value: string;
  status: CheckStatus;
  explanation: string;
  ref?: string;
}

export interface HeadersResult {
  status: CheckStatus;
  items: HeaderCheckItem[];
}

// ── SPF ──

export interface SpfMechanism {
  mechanism: string;
  description: string;
}

export interface SpfValidationItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface SpfResult {
  status: CheckStatus;
  record: string | null;
  validations: SpfValidationItem[];
  mechanisms: SpfMechanism[];
  dnsLookupCount: number;
  error?: string;
}

// ── DMARC ──

export interface DmarcTag {
  tag: string;
  value: string;
  description: string;
}

export interface DmarcValidationItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface DmarcResult {
  status: CheckStatus;
  record: string | null;
  validations: DmarcValidationItem[];
  tags: DmarcTag[];
  error?: string;
}

// ── DKIM ──

export interface DkimSelectorResult {
  selector: string;
  service: string;
  found: boolean;
  record?: string;
}

export interface DkimResult {
  status: CheckStatus;
  foundCount: number;
  totalChecked: number;
  selectors: DkimSelectorResult[];
}

// ── DNSSEC ──

export interface DnssecResult {
  status: CheckStatus;
  enabled: boolean;
  error?: string;
}

// ── CAA ──

export interface CaaRecord {
  flags: number;
  tag: string;
  value: string;
}

export interface CaaResult {
  status: CheckStatus;
  records: CaaRecord[];
  error?: string;
}

// ── MX ──

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface MxResult {
  status: CheckStatus;
  records: MxRecord[];
}

// ── NS ──

export interface NsResult {
  status: CheckStatus;
  nameservers: string[];
  error?: string;
}

// ── SSL ──

import type { ChainCertInfo, ChainIssue, CtPolicyResult } from "./checkers/sslChecker.types.js";

export interface SslResult {
  status: CheckStatus;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  sans: string[];
  error?: string;

  // Deep check fields (optional for backward compatibility)
  chain?: ChainCertInfo[];
  chainStatus?: CheckStatus;
  chainIssues?: ChainIssue[];
  ct?: CtPolicyResult;
}

// ── Domain Expiry ──

export interface DomainExpiryResult {
  status: CheckStatus;
  expirationDate: string | null;
  daysRemaining: number | null;
  error?: string;
}

// ── Blacklist ──

export interface DnsblProviderResult {
  provider: string;
  host: string;
  listed: boolean;
  type: "ip" | "domain";
}

export interface BlacklistResult {
  status: CheckStatus;
  ip: string | null;
  cdnProvider?: string;
  providers: DnsblProviderResult[];
  error?: string;
}

// ── Security.txt section in domain check ──

export interface SecurityTxtSection {
  status: CheckStatus;
  available: boolean;
  validationStatus: "valid" | "invalid" | "valid-with-warnings" | null;
  errorCount: number;
  warningCount: number;
  findings: Array<{
    severity: "error" | "warning" | "info";
    title: string;
    explanation: string;
  }>;
  fetchedFrom: string | null;
  error?: string;
}

// ── Top-level API response ──

export interface DomainCheckResponse {
  domain: string;
  timestamp: string;
  securityTxt: SecurityTxtSection;
  headers: HeadersResult;
  spf: SpfResult;
  dmarc: DmarcResult;
  dkim: DkimResult;
  dnssec: DnssecResult;
  caa: CaaResult;
  mx: MxResult;
  ns: NsResult;
  ssl: SslResult;
  domainExpiry: DomainExpiryResult;
  blacklist: BlacklistResult;
  ctLogs: CtLogsResult;
  redirects: RedirectResult;
  seo: SeoResult;
  safeBrowsing: SafeBrowsingResult;
  urlhaus: UrlhausResult;
  danglingDns: DanglingDnsResult;
}

// ── Certificate Transparency ──

export interface CtLogEntry {
  id?: string;
  issuerName: string;
  commonName: string;
  notBefore: string;
  notAfter: string;
}

export interface CtFinding {
  severity: "warn" | "fail" | "info";
  title: string;
  description: string;
  subdomain?: string;
}

export type CtDataSource = "crt.sh" | "certspotter" | "cache" | "none";

export interface CtLogsResult {
  status: CheckStatus;
  totalCerts: number;
  recentCerts: CtLogEntry[];
  flaggedCerts?: CtLogEntry[];
  findings: CtFinding[];
  source: CtDataSource;
  fromCache?: boolean;
  cachedAt?: string;
  error?: string;
}

export interface CtCheckOptions {
  authenticated?: boolean;
  sslIssuer?: string | null;
  caaRecords?: CaaRecord[];
  crtShFirst?: boolean;
  timeout?: number;
}

// ── Redirect / HTTPS ──

export interface RedirectCheckItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface RedirectResult {
  status: CheckStatus;
  httpsRedirect: boolean;
  wwwBehavior: string | null;
  items: RedirectCheckItem[];
  error?: string;
}

// ── SEO ──

export interface SeoCheckItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface SeoResult {
  status: CheckStatus;
  items: SeoCheckItem[];
  error?: string;
}

// ── Google Safe Browsing ──

export interface SafeBrowsingThreat {
  threatType: string;
  platformType: string;
}

export interface SafeBrowsingResult {
  status: CheckStatus;
  safe: boolean | null;
  threats: SafeBrowsingThreat[];
  error?: string;
}

// ── URLhaus ──

export interface UrlhausResult {
  status: CheckStatus;
  listed: boolean;
  urlCount: number;
  error?: string;
}

// ── Dangling DNS ──

export interface DanglingRecord {
  type: "MX" | "NS";
  hostname: string;
  resolves: boolean;
}

export interface DanglingDnsResult {
  status: CheckStatus;
  records: DanglingRecord[];
  danglingCount: number;
  error?: string;
}

// ── Phase 3: Accounts, Batch, Monitoring types ──

export interface UserRow {
  id: string;
  email: string;
  name: string | null;
  avatar_url: string | null;
  provider: "google" | "github";
  provider_id: string;
  plan: "registered" | "pro" | "enterprise";
  created_at: string;
}

export interface ScanRow {
  id: string;
  user_id: string | null;
  domain: string;
  scan_type: "single" | "batch";
  status: "pending" | "running" | "completed" | "failed";
  score: number | null;
  grade: string | null;
  config_json: string | null;
  result_json: string | null;
  changes_json: string | null;
  shared: number;
  share_id: string | null;
  share_expires: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface BatchScanRow {
  id: string;
  user_id: string;
  name: string | null;
  status: "pending" | "running" | "completed" | "failed";
  total_domains: number;
  completed_domains: number;
  config_json: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface BatchScanDomainRow {
  id: string;
  batch_id: string;
  domain: string;
  scan_id: string | null;
  status: "pending" | "running" | "completed" | "failed";
}

export interface ScheduledScanRow {
  id: string;
  user_id: string;
  name: string | null;
  domains_json: string;
  cron: string;
  config_json: string | null;
  enabled: number;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
}

export interface WebhookRow {
  id: string;
  user_id: string;
  url: string;
  name: string | null;
  secret: string;
  events_json: string;
  enabled: number;
  failing: number;
  fail_count: number;
  created_at: string;
}

export interface WebhookDeliveryRow {
  id: string;
  webhook_id: string;
  event: string;
  payload_json: string;
  status: "pending" | "delivered" | "failed";
  response_code: number | null;
  error: string | null;
  attempts: number;
  created_at: string;
  delivered_at: string | null;
}

export interface NotificationLogRow {
  id: string;
  user_id: string;
  scan_id: string | null;
  scheduled_id: string | null;
  type: "email" | "webhook";
  status: "pending" | "sent" | "failed";
  payload_json: string | null;
  error: string | null;
  created_at: string;
  sent_at: string | null;
}

// ── Score ──

export interface ScoreBreakdown {
  [category: string]: { earned: number; max: number };
}

export interface ScoreResponse {
  total: number;
  grade: string;
  breakdown: ScoreBreakdown;
}

// ── Remediation ──

export interface RemediationInfo {
  summary: string;
  steps: string[];
  effort: "low" | "medium" | "high";
  impact: "low" | "medium" | "high";
  ref: string;
}

// ── Scan Config ──

export interface ScanConfig {
  checks: {
    securityTxt: boolean;
    headers: boolean;
    spf: boolean;
    dmarc: boolean;
    dkim: boolean;
    dnssec: boolean;
    caa: boolean;
    mx: boolean;
    ns: boolean;
    ssl: boolean;
    domainExpiry: boolean;
    blacklist: boolean;
    ctLogs: boolean;
    redirects: boolean;
    seo: boolean;
    reputation: boolean;
    danglingDns: boolean;
  };
  noCache: boolean;
  crtShFirst?: boolean;
  authenticated?: boolean;
}

export const DEFAULT_SCAN_CONFIG: ScanConfig = {
  checks: {
    securityTxt: true, headers: true, spf: true, dmarc: true,
    dkim: true, dnssec: true, caa: true, mx: true, ns: true,
    ssl: true, domainExpiry: true, blacklist: true, ctLogs: true,
    redirects: true, seo: true, reputation: true, danglingDns: true,
  },
  noCache: false,
};

// ── Diff ──

export interface DiffChange {
  category: string;
  type: "status_changed" | "value_changed" | "appeared" | "disappeared";
  field?: string;
  severity: "critical" | "warn" | "resolved" | "info";
  previous: unknown;
  current: unknown;
  message: string;
}

export interface DiffResult {
  hasDiff: boolean;
  previousScanId: string | null;
  previousScanDate: string | null;
  scoreDelta: number;
  gradeChange: { from: string; to: string } | null;
  changes: DiffChange[];
  summary: {
    newIssues: number;
    resolvedIssues: number;
    valueChanges: number;
    totalChanges: number;
  };
}

// ── Extended API response ──

export interface DomainCheckResponseV3 extends DomainCheckResponse {
  score: ScoreResponse;
  diff?: DiffResult;
}

// ── API Error ──

export interface ApiError {
  error: string;
  message?: string;
}
