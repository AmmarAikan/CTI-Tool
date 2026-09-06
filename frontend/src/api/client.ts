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

export interface DashboardSummary {
  events: number;
  indicators: number;
  observables: number;
  correlations: number;
  sessions: number;
  outliers: number;
  by_severity: Record<string, number>;
  by_pipeline: Record<string, number>;
}

export type JobState = 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancellation_requested' | 'cancelled';
export interface ExternalJob {
  job_id: string;
  command_id: string;
  state: JobState;
  created_at: string;
  updated_at: string;
  counts: Partial<Record<'accepted_records' | 'review_records' | 'rejected_records' | 'skipped_records' | 'error_count', number>>;
  error?: string;
}

export interface ManualPreview {
  preview_id: string;
  state: 'pending';
  created_at: string;
  expires_at: string;
  display_url: string;
  page_type: string;
  title: string;
  excerpt: string;
  disposition: 'accepted' | 'review' | 'rejected';
  classification_label?: string;
  classification_confidence?: number;
  privacy_status: 'reviewed' | 'review_required';
  review_reasons: Array<'privacy_review' | 'classification_review' | 'relevance_rejected'>;
  content_sha256: string;
  items_preview: ManualPreviewItem[];
  items_preview_total: number;
  items_preview_truncated: boolean;
  counts: Record<'items' | 'accepted' | 'review' | 'rejected' | 'skipped' | 'errors', number>;
}
export interface ManualPreviewItem {
  item_index: number;
  title: string;
  excerpt: string;
  page_type: 'article';
  disposition: 'accepted' | 'review' | 'rejected';
  classification_label?: string;
  classification_confidence?: number;
  privacy_status: 'reviewed' | 'review_required';
  review_reasons: Array<'privacy_review' | 'classification_review' | 'relevance_rejected'>;
  content_sha256: string;
  published?: string;
}
export interface ManualPreviewRejection { preview_id: string; state: 'rejected'; decided_at: string; }

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

const API_BASE_URL = '/api/v1';
let memoryToken: string | null = null;

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

  const response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });
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

function parseDashboardSummary(value: unknown): DashboardSummary {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ApiError(502, 'invalid_response', 'Invalid dashboard summary response');
  const body = value as Record<string, unknown>;
  const count = (key: string) => {
    const item = body[key];
    if (!Number.isSafeInteger(item) || (item as number) < 0) throw new ApiError(502, 'invalid_response', 'Invalid dashboard summary response');
    return item as number;
  };
  const countMap = (key: string) => {
    const item = body[key];
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new ApiError(502, 'invalid_response', 'Invalid dashboard summary response');
    const entries = Object.entries(item);
    if (entries.some(([name, amount]) => !name || !Number.isSafeInteger(amount) || (amount as number) < 0)) throw new ApiError(502, 'invalid_response', 'Invalid dashboard summary response');
    return Object.fromEntries(entries) as Record<string, number>;
  };
  return {
    events: count('events'), indicators: count('indicators'), observables: count('observables'),
    correlations: count('correlations'), sessions: count('sessions'), outliers: count('outliers'),
    by_severity: countMap('by_severity'), by_pipeline: countMap('by_pipeline'),
  };
}

const JOB_STATES: JobState[] = ['queued', 'running', 'completed', 'partial', 'failed', 'cancellation_requested', 'cancelled'];
const JOB_COUNT_KEYS = ['accepted_records', 'review_records', 'rejected_records', 'skipped_records', 'error_count'] as const;

function isPlainObject(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }

function parseExternalJob(value: unknown): ExternalJob {
  if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
  const body = value;
  if (body.schema_version !== '1.0' || typeof body.job_id !== 'string' || body.job_id.length < 10 || typeof body.command_id !== 'string' || body.command_id.length < 10 || typeof body.state !== 'string' || !JOB_STATES.includes(body.state as JobState) || typeof body.created_at !== 'string' || !body.created_at.endsWith('Z') || typeof body.updated_at !== 'string' || !body.updated_at.endsWith('Z') || !isPlainObject(body.progress) || (body.result !== null && !isPlainObject(body.result)) || (body.error !== null && !isPlainObject(body.error))) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
  const counts: ExternalJob['counts'] = {};
  if (body.result) for (const key of JOB_COUNT_KEYS) {
    const amount = body.result[key];
    if (amount !== undefined) {
      if (!Number.isSafeInteger(amount) || (amount as number) < 0) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
      counts[key] = amount as number;
    }
  }
  const message = body.error && typeof body.error.message === 'string' ? sanitizeError(body.error.message) : undefined;
  return { job_id: body.job_id, command_id: body.command_id, state: body.state as JobState, created_at: body.created_at, updated_at: body.updated_at, counts, error: message };
}

function parseManualPreview(value: unknown): ManualPreview {
  if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid manual preview response');
  const required = ['schema_version', 'preview_id', 'state', 'created_at', 'expires_at', 'display_url', 'page_type', 'title', 'excerpt',
    'disposition', 'classification_label', 'classification_confidence', 'privacy_status', 'review_reasons', 'content_sha256', 'counts',
    'items_preview', 'items_preview_total', 'items_preview_truncated'];
  if (Object.keys(value).some((key) => !required.includes(key)) || required.some((key) => !(key in value))
    || value.schema_version !== '1.0' || typeof value.preview_id !== 'string' || value.preview_id.length < 20 || value.state !== 'pending'
    || typeof value.created_at !== 'string' || !value.created_at.endsWith('Z') || typeof value.expires_at !== 'string' || !value.expires_at.endsWith('Z')
    || typeof value.display_url !== 'string' || value.display_url.length > 400 || typeof value.page_type !== 'string' || value.page_type.length > 80
    || typeof value.title !== 'string' || value.title.length > 300 || typeof value.excerpt !== 'string' || value.excerpt.length > 500
    || !['accepted', 'review', 'rejected'].includes(String(value.disposition))
    || (value.classification_label !== null && typeof value.classification_label !== 'string')
    || (value.classification_confidence !== null && (typeof value.classification_confidence !== 'number' || value.classification_confidence < 0 || value.classification_confidence > 1))
    || !['reviewed', 'review_required'].includes(String(value.privacy_status)) || !Array.isArray(value.review_reasons)
    || value.review_reasons.some((reason) => !['privacy_review', 'classification_review', 'relevance_rejected'].includes(String(reason)))
    || typeof value.content_sha256 !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value.content_sha256) || !isPlainObject(value.counts)
    || !Array.isArray(value.items_preview) || value.items_preview.length > 20
    || !Number.isSafeInteger(value.items_preview_total) || (value.items_preview_total as number) < value.items_preview.length
    || typeof value.items_preview_truncated !== 'boolean'
    || value.items_preview_truncated !== ((value.items_preview_total as number) > value.items_preview.length)
    || value.items_preview.some((item, index) => !validManualPreviewItem(item, index + 1))) {
    throw new ApiError(502, 'invalid_response', 'Invalid manual preview response');
  }
  const countKeys = ['items', 'accepted', 'review', 'rejected', 'skipped', 'errors'];
  const counts = value.counts as Record<string, unknown>;
  if (Object.keys(counts).length !== countKeys.length || countKeys.some((key) => !Number.isSafeInteger(counts[key]) || (counts[key] as number) < 0)) throw new ApiError(502, 'invalid_response', 'Invalid manual preview response');
  return value as unknown as ManualPreview;
}

function validManualPreviewItem(value: unknown, index: number): boolean {
  if (!isPlainObject(value)) return false;
  const required = ['item_index', 'title', 'excerpt', 'page_type', 'disposition', 'classification_label',
    'classification_confidence', 'privacy_status', 'review_reasons', 'content_sha256'];
  const allowed = [...required, 'published'];
  return !Object.keys(value).some((key) => !allowed.includes(key)) && required.every((key) => key in value)
    && value.item_index === index && typeof value.title === 'string' && value.title.length <= 200
    && typeof value.excerpt === 'string' && value.excerpt.length <= 300 && value.page_type === 'article'
    && ['accepted', 'review', 'rejected'].includes(String(value.disposition))
    && (value.classification_label === null || (typeof value.classification_label === 'string' && value.classification_label.length <= 80))
    && (value.classification_confidence === null || (typeof value.classification_confidence === 'number' && value.classification_confidence >= 0 && value.classification_confidence <= 1))
    && ['reviewed', 'review_required'].includes(String(value.privacy_status)) && Array.isArray(value.review_reasons)
    && value.review_reasons.length <= 3
    && value.review_reasons.every((reason) => ['privacy_review', 'classification_review', 'relevance_rejected'].includes(String(reason)))
    && typeof value.content_sha256 === 'string' && /^sha256:[0-9a-f]{64}$/.test(value.content_sha256)
    && (!('published' in value) || (typeof value.published === 'string' && value.published.length <= 40 && value.published.endsWith('Z')));
}

function parseManualPreviewRejection(value: unknown): ManualPreviewRejection {
  if (!isPlainObject(value) || Object.keys(value).length !== 4 || value.schema_version !== '1.0'
    || typeof value.preview_id !== 'string' || value.preview_id.length < 20 || value.state !== 'rejected'
    || typeof value.decided_at !== 'string' || !value.decided_at.endsWith('Z')) {
    throw new ApiError(502, 'invalid_response', 'Invalid manual preview decision response');
  }
  return { preview_id: value.preview_id, state: 'rejected', decided_at: value.decided_at };
}

function isRole(value: unknown): value is Role { return value === 'viewer' || value === 'analyst' || value === 'admin'; }

function safeText(value: unknown): string | undefined { return typeof value === 'string' ? value.slice(0, 200) : undefined; }

function sanitizeError(value: string): string {
  return value.replace(ONION_VALUE, '[redacted]').replace(/https?:\/\/[^\s"']+/gi, '[redacted]').replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[redacted]').replace(/(token|password|secret|authorization)\s*[=:]\s*[^\s,;]+/gi, '$1=[redacted]').slice(0, 300);
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
  dashboardSummary: async () => parseDashboardSummary(await request<unknown>('/dashboard/summary')),
  startExternalSourceJob: async (sourceId: string) => parseExternalJob(await request<unknown>(`/integrations/external-control/sources/${encodeURIComponent(sourceId)}/jobs`, { method: 'POST', body: JSON.stringify({ force: false }) })),
  startManualUrlJob: async (url: string) => parseExternalJob(await request<unknown>('/integrations/external-control/manual-sources', { method: 'POST', body: JSON.stringify({ url, force: false }) })),
  createManualPreview: async (url: string) => parseManualPreview(await request<unknown>('/integrations/external-control/manual-sources/previews', { method: 'POST', body: JSON.stringify({ url }) })),
  approveManualPreview: async (preview: ManualPreview) => parseExternalJob(await request<unknown>(`/integrations/external-control/manual-sources/previews/${encodeURIComponent(preview.preview_id)}/approve`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ expected_content_sha256: preview.content_sha256 }) })),
  rejectManualPreview: async (previewId: string, reason: 'not_relevant' | 'duplicate' | 'user_cancelled') => parseManualPreviewRejection(await request<unknown>(`/integrations/external-control/manual-sources/previews/${encodeURIComponent(previewId)}/reject`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ reason }) })),
  externalJob: async (jobId: string) => parseExternalJob(await request<unknown>(`/integrations/external-control/jobs/${encodeURIComponent(jobId)}`)),
};
