export type Role = 'viewer' | 'analyst' | 'admin';

export interface User {
  id: string;
  username: string;
  role: Role;
  is_active: boolean;
}

export interface LoginResponse {
  access_token: string;
  token_type: 'bearer';
  role: Role;
}

export interface HealthResponse {
  configured: boolean;
  reachable: boolean;
  service?: string;
  api_version?: string;
}

export interface Source {
  source_id: string;
  name: string;
  source_type: string;
  status: string;
  metadata: Record<string, unknown>;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/$/, '');
let memoryToken: string | null = null;

function apiBaseUrl(value: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('?') || value.includes('#')) return '/api/v1';
  return value;
}

const SAFE_API_BASE_URL = apiBaseUrl(API_BASE_URL);
const ONION_VALUE = /https?:\/\/[^\s"']*\.onion[^\s"']*/gi;

export function getToken(): string | null {
  return memoryToken || sessionStorage.getItem('cti_access_token');
}

export function setToken(token: string): void {
  memoryToken = token;
  sessionStorage.setItem('cti_access_token', token);
}

export function clearToken(): void {
  memoryToken = null;
  sessionStorage.removeItem('cti_access_token');
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (options.body) headers.set('Content-Type', 'application/json');
  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const response = await fetch(`${SAFE_API_BASE_URL}${path}`, { ...options, headers });
  if (response.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('cti:unauthorized'));
  }
  if (!response.ok) {
    let body: { detail?: unknown; code?: string; message?: string } = {};
    try { body = await response.json(); } catch { /* keep safe fallback */ }
    const detail = typeof body.detail === 'object' && body.detail !== null ? body.detail as { code?: string; message?: string } : undefined;
    const code = detail?.code || body.code || 'request_failed';
    const message = detail?.message || body.message || (typeof body.detail === 'string' ? body.detail : 'Request failed');
    throw new ApiError(response.status, sanitizeError(message), sanitizeError(code));
  }
  return response.json() as Promise<T>;
}

function parseLogin(value: unknown): LoginResponse {
  if (!value || typeof value !== 'object') throw new ApiError(502, 'invalid_response', 'Invalid authentication response');
  const body = value as Partial<LoginResponse>;
  if (typeof body.access_token !== 'string' || body.token_type !== 'bearer' || !isRole(body.role)) throw new ApiError(502, 'invalid_response', 'Invalid authentication response');
  return { access_token: body.access_token, token_type: 'bearer', role: body.role };
}

function parseHealth(value: unknown): HealthResponse {
  if (!value || typeof value !== 'object') throw new ApiError(502, 'invalid_response', 'Invalid health response');
  const body = value as Partial<HealthResponse>;
  if (typeof body.configured !== 'boolean' || typeof body.reachable !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid health response');
  return { configured: body.configured, reachable: body.reachable, service: safeText(body.service), api_version: safeText(body.api_version) };
}

function parseSources(value: unknown): Source[] {
  if (!Array.isArray(value)) throw new ApiError(502, 'invalid_response', 'Invalid sources response');
  return value.map((item) => {
    if (!item || typeof item !== 'object') throw new ApiError(502, 'invalid_response', 'Invalid sources response');
    const source = item as Partial<Source>;
    if (typeof source.source_id !== 'string' || typeof source.name !== 'string' || typeof source.source_type !== 'string' || typeof source.status !== 'string' || !source.metadata || typeof source.metadata !== 'object' || Array.isArray(source.metadata)) throw new ApiError(502, 'invalid_response', 'Invalid sources response');
    return { source_id: source.source_id, name: source.name, source_type: source.source_type, status: source.status, metadata: redactSensitive(source.metadata) as Record<string, unknown> };
  });
}

function isRole(value: unknown): value is Role { return value === 'viewer' || value === 'analyst' || value === 'admin'; }

function safeText(value: unknown): string | undefined { return typeof value === 'string' ? value.slice(0, 200) : undefined; }

function sanitizeError(value: string): string {
  return value.replace(ONION_VALUE, '[redacted]').replace(/(token|password|secret|authorization)\s*[=:]\s*[^\s,;]+/gi, '$1=[redacted]').slice(0, 300);
}

function redactSensitive(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSensitive);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, /(token|password|secret|authorization|cookie|api[_-]?key)/i.test(key) ? '[redacted]' : redactSensitive(item)]));
  if (typeof value === 'string') return value.replace(ONION_VALUE, '[redacted]');
  return value;
}

function parseUser(value: unknown): User {
  if (!value || typeof value !== 'object') throw new ApiError(502, 'invalid_response', 'Invalid user response');
  const body = value as Partial<User>;
  if (typeof body.id !== 'string' || typeof body.username !== 'string' || !isRole(body.role) || typeof body.is_active !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid user response');
  return { id: body.id, username: body.username, role: body.role, is_active: body.is_active };
}

export const api = {
  login: async (username: string, password: string) => parseLogin(await request<unknown>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) })),
  me: async () => parseUser(await request<unknown>('/auth/me')),
  externalHealth: async () => parseHealth(await request<unknown>('/integrations/external-control/health')),
  externalSources: async () => parseSources(await request<unknown>('/integrations/external-control/sources')),
};
