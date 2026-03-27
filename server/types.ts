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

export interface SslResult {
  status: CheckStatus;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  sans: string[];
  error?: string;
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
}

export interface BlacklistResult {
  status: CheckStatus;
  ip: string | null;
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
  issuerName: string;
  commonName: string;
  notBefore: string;
  notAfter: string;
}

export interface CtLogsResult {
  status: CheckStatus;
  totalCerts: number;
  recentCerts: CtLogEntry[];
  error?: string;
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
