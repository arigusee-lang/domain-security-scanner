// ── Monitoring Types & Constants ──

export type MonitorType =
  | "ssl_expiry"
  | "domain_expiry"
  | "ct_logs"
  | "security_txt_expiry"
  | "blacklist"
  | "caa_dnssec"
  | "headers";

export type AlertSeverity = "info" | "warn" | "critical" | "resolved";

export type UserPlan = "free" | "premium" | "premium_plus";

/** Repeat intervals in milliseconds */
export const MONITOR_INTERVALS: Record<MonitorType, number> = {
  ssl_expiry:          24 * 60 * 60 * 1000,
  domain_expiry:      168 * 60 * 60 * 1000,
  ct_logs:              4 * 60 * 60 * 1000,
  security_txt_expiry: 24 * 60 * 60 * 1000,
  blacklist:            6 * 60 * 60 * 1000,
  caa_dnssec:          24 * 60 * 60 * 1000,
  headers:             24 * 60 * 60 * 1000,
};

export const ALL_MONITOR_TYPES: MonitorType[] = [
  "ssl_expiry", "domain_expiry", "ct_logs",
  "security_txt_expiry", "blacklist", "caa_dnssec", "headers",
];

export const DOMAIN_LIMITS: Record<UserPlan, number> = {
  free: 1,
  premium: 10,
  premium_plus: 100,
};

export const JOB_PRIORITIES: Record<MonitorType, number> = {
  blacklist: 1,
  ct_logs: 1,
  ssl_expiry: 5,
  domain_expiry: 5,
  security_txt_expiry: 5,
  caa_dnssec: 5,
  headers: 5,
};

export const SSL_THRESHOLDS = [
  { days: 30, severity: "warn" as const },
  { days: 14, severity: "warn" as const },
  { days: 7,  severity: "critical" as const },
  { days: 1,  severity: "critical" as const },
];

export const DOMAIN_THRESHOLDS = [
  { days: 90, severity: "info" as const },
  { days: 30, severity: "warn" as const },
  { days: 7,  severity: "critical" as const },
];

export const SECURITY_TXT_THRESHOLDS = [
  { days: 30, severity: "warn" as const },
  { days: 7,  severity: "critical" as const },
];

// ── Row interfaces ──

export interface MonitoredDomainRow {
  id: string;
  user_id: string;
  domain: string;
  enabled: number;
  created_at: string;
}

export interface MonitorRow {
  id: string;
  domain_id: string;
  user_id: string;
  monitor_type: MonitorType;
  enabled: number;
  interval_ms: number;
  last_run_at: string | null;
  next_run_at: string | null;
  last_error: string | null;
  created_at: string;
}

export interface DomainCheckStateRow {
  id: string;
  domain: string;
  check_type: string;
  result_json: string;
  result_hash: string;
  expiry_date: string | null;
  checked_at: string;
}

export interface MonitorStateRow {
  id: string;
  monitor_id: string;
  result_json: string;
  result_hash: string;
  checked_at: string;
  thresholds_fired_json: string | null;
}

export interface MonitorAlertRow {
  id: string;
  monitor_id: string;
  domain_id: string;
  user_id: string;
  monitor_type: string;
  severity: AlertSeverity;
  title: string;
  description: string;
  previous_value: string | null;
  current_value: string | null;
  notified: number;
  created_at: string;
}

export interface MonitoringSettingsRow {
  user_id: string;
  email_enabled: number;
  min_severity: string;
  updated_at: string;
}

// ── API interfaces ──

export interface AddDomainResult {
  domainId: string;
  domain: string;
  monitors: Array<{ id: string; type: MonitorType; intervalMs: number }>;
  createdAt: string;
}

export interface MonitoredDomainWithStatus {
  id: string;
  domain: string;
  enabled: boolean;
  monitorsCount: number;
  activeAlertsCount: number;
  lastCheckAt: string | null;
  overallStatus: "pass" | "warn" | "critical" | null;
}

export interface DomainMonitorStatus {
  domain: string;
  monitors: Array<{
    id: string;
    type: MonitorType;
    enabled: boolean;
    lastRunAt: string | null;
    nextRunAt: string | null;
    lastResult: unknown;
    lastError: string | null;
    status: string | null;
  }>;
}

export interface AlertQueryOpts {
  page: number;
  limit: number;
  domain?: string;
  severity?: string;
}

export interface PaginatedAlerts {
  alerts: MonitorAlertRow[];
  pagination: { page: number; limit: number; total: number };
}

export interface HealthStatus {
  redis: "connected" | "disconnected";
  monitoringEnabled: boolean;
  activeJobs: number;
  waitingJobs: number;
  failedJobs: number;
}

export interface MonitorJobData {
  monitorId: string;
  domainId: string;
  domain: string;
  monitorType: MonitorType;
  userId: string;
}

export interface AlertPayload {
  alertId: string;
  userId: string;
  domainId: string;
  domain: string;
  monitorType: MonitorType;
  severity: AlertSeverity;
  title: string;
  description: string;
  previousValue: unknown;
  currentValue: unknown;
}

export interface DetectedChange {
  severity: AlertSeverity;
  title: string;
  description: string;
  previousValue: unknown;
  currentValue: unknown;
}
