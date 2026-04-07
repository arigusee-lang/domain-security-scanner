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
