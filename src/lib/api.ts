export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const opts: RequestInit = {
    method,
    credentials: 'include',
    headers: {} as Record<string, string>,
  };

  if (body !== undefined) {
    (opts.headers as Record<string, string>)['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }

  const res = await fetch(url, opts);

  if (!res.ok) {
    let code = 'unknown';
    let message = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      code = data.error ?? code;
      message = data.message ?? message;
    } catch {
      // ignore parse errors
    }
    throw new ApiError(res.status, code, message);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

export function get<T>(url: string): Promise<T> {
  return request<T>('GET', url);
}

export function post<T>(url: string, body?: unknown): Promise<T> {
  return request<T>('POST', url, body);
}

export function put<T>(url: string, body?: unknown): Promise<T> {
  return request<T>('PUT', url, body);
}

export function patch<T>(url: string, body?: unknown): Promise<T> {
  return request<T>('PATCH', url, body);
}

export function del<T>(url: string): Promise<T> {
  return request<T>('DELETE', url);
}

// ── Admin API helpers ──

export function getAdminUsers(params: { page?: number; limit?: number; search?: string; plan?: string } = {}) {
  const qs = new URLSearchParams();
  if (params.page) qs.set('page', String(params.page));
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.search) qs.set('search', params.search);
  if (params.plan) qs.set('plan', params.plan);
  return get<{ users: any[]; total: number; page: number; limit: number }>(`/api/admin/users?${qs}`);
}

export function getAdminStats() {
  return get<{ total: number; byPlan: { registered: number; pro: number; enterprise: number } }>('/api/admin/stats');
}

export function updateUserPlan(userId: string, plan: string) {
  return patch<any>(`/api/admin/users/${userId}/plan`, { plan });
}

export function getUserScans(userId: string, params: { page?: number; limit?: number } = {}) {
  const qs = new URLSearchParams();
  if (params.page) qs.set('page', String(params.page));
  if (params.limit) qs.set('limit', String(params.limit));
  return get<{ scans: any[]; total: number; page: number; limit: number }>(`/api/admin/users/${userId}/scans?${qs}`);
}

export function getAuditLog(params: { page?: number; limit?: number } = {}) {
  const qs = new URLSearchParams();
  if (params.page) qs.set('page', String(params.page));
  if (params.limit) qs.set('limit', String(params.limit));
  return get<{ entries: any[]; total: number; page: number; limit: number }>(`/api/admin/audit-log?${qs}`);
}

export function getUserNotifications(userId: string, params: { page?: number; limit?: number } = {}) {
  const qs = new URLSearchParams();
  if (params.page) qs.set('page', String(params.page));
  if (params.limit) qs.set('limit', String(params.limit));
  return get<{ notifications: any[]; total: number; page: number; limit: number }>(`/api/admin/users/${userId}/notifications?${qs}`);
}

// ── Monitoring API helpers ──

export function getMonitoringDomains() {
  return get<{ domains: any[]; limits: { max: number; used: number } }>('/api/monitoring/domains');
}

export function addMonitoringDomain(domain: string, opts?: { monitorTypes?: string[]; emailEnabled?: boolean; minSeverity?: string }) {
  return post<any>('/api/monitoring/domains', { domain, ...opts });
}

export function updateMonitoringDomainSettings(domainId: string, settings: { emailEnabled?: boolean; minSeverity?: string; enabledMonitors?: string[] }) {
  return patch<any>(`/api/monitoring/domains/${domainId}/settings`, settings);
}

export function removeMonitoringDomain(domainId: string) {
  return del<void>(`/api/monitoring/domains/${domainId}`);
}

export function getMonitoringAlerts(params: { page?: number; limit?: number; domain?: string; severity?: string } = {}) {
  const qs = new URLSearchParams();
  if (params.page) qs.set('page', String(params.page));
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.domain) qs.set('domain', params.domain);
  if (params.severity) qs.set('severity', params.severity);
  return get<{ alerts: any[]; pagination: { page: number; limit: number; total: number } }>(`/api/monitoring/alerts?${qs}`);
}

export function getMonitoringDomainStatus(domainId: string) {
  return get<any>(`/api/monitoring/domains/${domainId}/status`);
}

export function getMonitoringHealth() {
  return get<any>('/api/monitoring/health');
}

export function getMonitoringSettings() {
  return get<{ emailEnabled: boolean; minSeverity: string }>('/api/monitoring/settings');
}

export function updateMonitoringSettings(settings: { emailEnabled?: boolean; minSeverity?: string }) {
  return put<{ emailEnabled: boolean; minSeverity: string }>('/api/monitoring/settings', settings);
}

export function getAdminUserMonitoredDomains(userId: string) {
  return get<{ domains: any[] }>(`/api/admin/users/${userId}/monitored-domains`);
}
