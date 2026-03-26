/** A single parsed line from the input */
export type ParsedLine =
  | { kind: "field"; lineNumber: number; raw: string; name: string; value: string }
  | { kind: "comment"; lineNumber: number; raw: string; text: string }
  | { kind: "blank"; lineNumber: number }
  | { kind: "invalid"; lineNumber: number; raw: string };

/** Severity levels for validation findings */
export type Severity = "error" | "warning" | "info";

/** A single validation finding */
export interface Finding {
  severity: Severity;
  lineNumber?: number;
  title: string;
  explanation: string;
  suggestedFix: string;
  ruleId: string;
  /** Optional link to relevant RFC section */
  rfcRef?: string;
}

/** Overall validation result */
export interface ValidationResult {
  status: "valid" | "invalid" | "valid-with-warnings";
  errorCount: number;
  warningCount: number;
  infoCount: number;
  findings: Finding[];
  parsedFields: ParsedLine[];
}

/** Metadata from URL-mode fetch */
export interface FetchMetadata {
  contentType: string;
  fetchedFrom: string;
  redirectChain: string[];
  wellKnownFound: boolean;
  fallbackUsed: boolean;
  usedHttps: boolean;
}

/** Known RFC 9116 field names */
export type KnownFieldName =
  | "Contact"
  | "Expires"
  | "Encryption"
  | "Acknowledgments"
  | "Canonical"
  | "Policy"
  | "Hiring"
  | "Preferred-Languages"
  | "CSAF";

/** Validation rule function signature */
export type ValidationRule = (lines: ParsedLine[], fetchMeta?: FetchMetadata) => Finding[];

/** PGP ClearSign wrapper info */
export interface PgpInfo {
  /** Whether the input was wrapped in a PGP ClearSign block */
  isSigned: boolean;
  /** The hash algorithm declared in the header (e.g. "SHA256") */
  hashAlgorithm?: string;
  /** Whether the PGP structure appears well-formed (has both header and signature) */
  wellFormed: boolean;
}

/** Result of parsing raw security.txt content */
export interface ParseResult {
  lines: ParsedLine[];
  pgp: PgpInfo;
}

// ── Domain Security Checker types (frontend) ──

export type CheckStatus = "pass" | "warn" | "fail" | "info";

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

export interface DnssecResult {
  status: CheckStatus;
  enabled: boolean;
  error?: string;
}

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

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface MxResult {
  status: CheckStatus;
  records: MxRecord[];
}

export interface NsResult {
  status: CheckStatus;
  nameservers: string[];
  error?: string;
}

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

export interface DomainExpiryResult {
  status: CheckStatus;
  expirationDate: string | null;
  daysRemaining: number | null;
  error?: string;
}

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

export interface DomainCheckResult {
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
