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
  contract_valid?: boolean;
  hmac_verification?: boolean;
}

export interface SystemHealth { status: 'ok' | 'degraded'; database: boolean; }
export type InternalIntegration = 'dionaea' | 'host-auth' | 'web-access';
export interface IntegrationConfiguration {
  external_control_api: { configured: boolean };
  dionaea_sensor_api: { configured: boolean };
  host_auth_sensor_api: { configured: boolean };
  web_access_sensor_api: { configured: boolean };
}
export interface InternalEvent { id: string; integration: InternalIntegration; source: string; event_type: string; category?: string; severity?: string; summary: string; first_seen?: string; last_seen?: string; created_at: string; }
export interface InternalEventPage { items: InternalEvent[]; total: number; limit: number; offset: number; }
export interface PullResult { run_id: string; pipeline: 'internal'; status: string; collected_count: number; processed_count: number; stored_count: number; failed_count: number; }
export interface CTIIndicator { id: string; event_id: string; type: string; value: string; confidence: number; source_pipeline: 'external' | 'internal'; severity?: string; first_seen?: string; last_seen?: string; }
export interface CTIEvent { id: string; title: string; summary: string; source_type: string; source_pipeline: 'external' | 'internal'; category?: string; severity?: string; risk_score: number; confidence: number; processing_status: string; first_seen?: string; last_seen?: string; created_at: string; indicator_count: number; entity_count: number; }
export interface CTIEntity { type: string; value: string; confidence: number; }
export interface CTIRelationship { subject: string; relation: string; object: string; confidence: number; }
export interface CTIEventDetail extends CTIEvent { indicators: CTIIndicator[]; entities: CTIEntity[]; relationships: CTIRelationship[]; }
export interface CTICorrelation { id: string; source_event_id: string; target_event_id: string; type: string; score: number; reason: string; }
export interface CTIOutlier { id: string; event_id?: string; started_at: string; ended_at: string; alert_count: number; is_outlier: boolean; anomaly_score: number; detector: string; }
export interface AnalysisRun { id: string; pipeline: string; status: string; collected: number; processed: number; stored: number; failed: number; error_category?: string; started_at: string; completed_at?: string; duration_seconds?: number; }
export interface MLStatus { execution_model: 'central_backend'; backend: string; primary_model: string; secondary_model: string; primary_loaded: boolean; secondary_loaded: boolean; quality_gates_passed: boolean; held_out_f1?: number; }
export interface MISPHealth { configured: boolean; reachable: boolean; failure_category?: string; }
export interface MISPPreview { event_id: string; title: string; configured: boolean; published: false; distribution: 0; attributes: Array<{ type: string; category: string; value: string; to_ids: boolean }>; }
export interface MISPDelivery { event_id: string; created: boolean; attributes_requested: number; attributes_added: number; attributes_verified: number; published: boolean; }
export interface Page<T> { items: T[]; total: number; limit: number; offset: number; }
export interface AdminUser { id: string; username: string; role: Role; is_active: boolean; created_at: string; }
export interface AdminAudit { id: string; actor?: string; action: string; target_type: string; target_id?: string; outcome: 'success'; created_at: string; }

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
  sources: Record<string, { status: string; counts: ExternalJob['counts'] }>;
  error?: string;
}

export interface ExportSummary { run_id: string; status: string; dataset_sha256?: string; accepted_records: number; review_records: number; completed_at?: string; }
export interface ReviewRecord { record_id: string; title?: string; source_type?: string; review_reason: string; review_reasons: string[]; classification_label?: string; privacy_status?: string; collected_at?: string; published?: string; }
export interface LatestReviews { run_id: string; records: ReviewRecord[]; }
export interface JobSummary { job_id: string; source_id?: string; state: JobState; created_at: string; updated_at: string; counts: ExternalJob['counts']; error_code?: string; error_message?: string; }
export interface JobHistory { persistence: 'process_memory'; jobs: JobSummary[]; }

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

const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const EXTERNAL_SYNC_TIMEOUT_MS = 40_000;
const INTERNAL_PULL_TIMEOUT_MS = 120_000;

async function request<T>(path: string, options: RequestInit = {}, timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (options.body) headers.set('Content-Type', 'application/json');
  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const controller = new AbortController();
  const externalSignal = options.signal;
  const abortFromCaller = () => controller.abort(externalSignal?.reason);
  if (externalSignal?.aborted) abortFromCaller(); else externalSignal?.addEventListener('abort', abortFromCaller, { once: true });
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try { response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers, signal: controller.signal }); }
  catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw new ApiError(408, 'timeout', 'Request timed out');
    throw error;
  } finally { window.clearTimeout(timer); externalSignal?.removeEventListener('abort', abortFromCaller); }
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
    throw new ApiError(response.status, sanitizeError(code), sanitizeError(message));
  }
  return response.json() as Promise<T>;
}

function parseLogin(value: unknown): LoginResponse {
  if (!isPlainObject(value) || Object.keys(value).some((key) => !['access_token', 'token_type', 'role'].includes(key))) throw new ApiError(502, 'invalid_response', 'Invalid authentication response');
  const body = value as Partial<LoginResponse>;
  if (typeof body.access_token !== 'string' || body.token_type !== 'bearer' || !isRole(body.role)) throw new ApiError(502, 'invalid_response', 'Invalid authentication response');
  return { access_token: body.access_token, token_type: 'bearer', role: body.role };
}

function parseHealth(value: unknown): HealthResponse {
  if (!isPlainObject(value) || Object.keys(value).some((key) => !['configured', 'reachable', 'service', 'api_version', 'contract_valid', 'hmac_verification', 'error_type'].includes(key))) throw new ApiError(502, 'invalid_response', 'Invalid health response');
  const body = value as Partial<HealthResponse>;
  if (typeof body.configured !== 'boolean' || typeof body.reachable !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid health response');
  if (body.contract_valid !== undefined && typeof body.contract_valid !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid health response');
  if (body.hmac_verification !== undefined && typeof body.hmac_verification !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid health response');
  return { configured: body.configured, reachable: body.reachable, service: safeText(body.service), api_version: safeText(body.api_version), contract_valid: body.contract_valid, hmac_verification: body.hmac_verification };
}

function parseSystemHealth(value: unknown): SystemHealth {
  if (!isPlainObject(value) || Object.keys(value).some((key) => !['status', 'database'].includes(key)) || !['ok', 'degraded'].includes(String(value.status)) || typeof value.database !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid system health response');
  return { status: value.status as SystemHealth['status'], database: value.database };
}

function parseIntegrationStatus(value: unknown): IntegrationConfiguration {
  const profiles: Record<string, string[]> = {
    external_feed: ['configured', 'tls_verification', 'hmac_verification'],
    external_control_api: ['configured', 'deployment_status', 'tls_verification', 'transport'],
    wazuh_indexer: ['configured', 'deployment_status', 'tls_verification', 'authentication'],
    dionaea_sensor_api: ['configured', 'tls_verification', 'hmac_verification'],
    host_auth_sensor_api: ['configured', 'tls_verification', 'hmac_verification'],
    web_access_sensor_api: ['configured', 'tls_verification', 'hmac_verification'],
    misp: ['configured', 'tls_verification'],
  };
  if (!isPlainObject(value) || Object.keys(value).length !== Object.keys(profiles).length || Object.keys(value).some((key) => !(key in profiles))) throw new ApiError(502, 'invalid_response', 'Invalid integration status response');
  const read = (key: string) => {
    const entry = value[key];
    if (!isPlainObject(entry) || Object.keys(entry).some((field) => !profiles[key].includes(field)) || typeof entry.configured !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid integration status response');
    return { configured: entry.configured };
  };
  return { external_control_api: read('external_control_api'), dionaea_sensor_api: read('dionaea_sensor_api'), host_auth_sensor_api: read('host_auth_sensor_api'), web_access_sensor_api: read('web_access_sensor_api') };
}

function parseInternalEvents(value: unknown, integration: InternalIntegration): InternalEventPage {
  if (!isPlainObject(value) || Object.keys(value).some((key) => !['items', 'total', 'limit', 'offset'].includes(key)) || !Array.isArray(value.items) || value.items.length > 100 || !Number.isSafeInteger(value.total) || (value.total as number) < 0 || !Number.isSafeInteger(value.limit) || (value.limit as number) < 1 || (value.limit as number) > 100 || !Number.isSafeInteger(value.offset) || (value.offset as number) < 0) throw new ApiError(502, 'invalid_response', 'Invalid internal events response');
  const allowed = ['id', 'integration', 'source', 'event_type', 'category', 'severity', 'summary', 'first_seen', 'last_seen', 'created_at'];
  const items = value.items.map((item): InternalEvent => {
    if (!isPlainObject(item) || Object.keys(item).some((key) => !allowed.includes(key)) || item.integration !== integration || typeof item.id !== 'string' || item.id.length > 64 || typeof item.source !== 'string' || item.source.length > 40 || typeof item.event_type !== 'string' || item.event_type.length > 50 || typeof item.summary !== 'string' || item.summary.length > 160 || !validIsoTimestamp(item.created_at)) throw new ApiError(502, 'invalid_response', 'Invalid internal events response');
    for (const key of ['category', 'severity'] as const) if (item[key] !== null && item[key] !== undefined && (typeof item[key] !== 'string' || item[key].length > 50)) throw new ApiError(502, 'invalid_response', 'Invalid internal events response');
    for (const key of ['first_seen', 'last_seen'] as const) if (item[key] !== null && item[key] !== undefined && !validIsoTimestamp(item[key])) throw new ApiError(502, 'invalid_response', 'Invalid internal events response');
    return { id: item.id, integration, source: item.source, event_type: item.event_type, category: item.category as string | undefined, severity: item.severity as string | undefined, summary: sanitizeError(item.summary), first_seen: item.first_seen as string | undefined, last_seen: item.last_seen as string | undefined, created_at: item.created_at };
  });
  return { items, total: value.total as number, limit: value.limit as number, offset: value.offset as number };
}

function parsePullResult(value: unknown): PullResult {
  const allowed = ['run_id', 'pipeline', 'status', 'collected_count', 'processed_count', 'stored_count', 'failed_count'];
  if (!isPlainObject(value) || Object.keys(value).some((key) => !allowed.includes(key)) || typeof value.run_id !== 'string' || value.pipeline !== 'internal' || typeof value.status !== 'string') throw new ApiError(502, 'invalid_response', 'Invalid pull response');
  for (const key of ['collected_count', 'processed_count', 'stored_count', 'failed_count']) if (!Number.isSafeInteger(value[key]) || (value[key] as number) < 0) throw new ApiError(502, 'invalid_response', 'Invalid pull response');
  return { run_id: value.run_id, pipeline: 'internal', status: sanitizeError(value.status), collected_count: value.collected_count as number, processed_count: value.processed_count as number, stored_count: value.stored_count as number, failed_count: value.failed_count as number };
}

const pageKeys = ['items', 'total', 'limit', 'offset'];
function parsePage<T>(value: unknown, parseItem: (item: unknown) => T): Page<T> {
  if (!isPlainObject(value) || Object.keys(value).some((key) => !pageKeys.includes(key)) || !Array.isArray(value.items) || value.items.length > 100 || !Number.isSafeInteger(value.total) || (value.total as number) < 0 || !Number.isSafeInteger(value.limit) || (value.limit as number) < 1 || (value.limit as number) > 100 || !Number.isSafeInteger(value.offset) || (value.offset as number) < 0) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response');
  return { items: value.items.map(parseItem), total: value.total as number, limit: value.limit as number, offset: value.offset as number };
}
function requiredText(value: unknown, max: number): string { if (typeof value !== 'string' || !value || value.length > max) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); return sanitizeError(value); }
function optionalSafeText(value: unknown, max: number): string | undefined { if (value === null || value === undefined) return undefined; return requiredText(value, max); }
function boundedNumber(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): number { if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); return value; }
function exactKeys(value: Record<string, unknown>, allowed: string[]) { if (Object.keys(value).some((key) => !allowed.includes(key))) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); }
function optionalTimestamp(value: unknown): string | undefined { if (value === null || value === undefined) return undefined; if (!validIsoTimestamp(value)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); return value; }

const eventKeys = ['id', 'title', 'summary', 'source_type', 'source_pipeline', 'category', 'severity', 'risk_score', 'confidence', 'processing_status', 'first_seen', 'last_seen', 'created_at', 'indicator_count', 'entity_count'];
function parseCTIEvent(value: unknown): CTIEvent {
  if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); exactKeys(value, eventKeys);
  const pipeline = value.source_pipeline; if (pipeline !== 'external' && pipeline !== 'internal') throw new ApiError(502, 'invalid_response', 'Invalid intelligence response');
  if (!validIsoTimestamp(value.created_at)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response');
  return { id: requiredText(value.id, 64), title: requiredText(value.title, 500), summary: requiredText(value.summary, 500), source_type: requiredText(value.source_type, 50), source_pipeline: pipeline, category: optionalSafeText(value.category, 50), severity: optionalSafeText(value.severity, 30), risk_score: boundedNumber(value.risk_score), confidence: boundedNumber(value.confidence, 0, 1), processing_status: requiredText(value.processing_status, 30), first_seen: optionalTimestamp(value.first_seen), last_seen: optionalTimestamp(value.last_seen), created_at: value.created_at, indicator_count: boundedNumber(value.indicator_count), entity_count: boundedNumber(value.entity_count) };
}
const indicatorKeys = ['id', 'event_id', 'type', 'value', 'confidence', 'source_pipeline', 'severity', 'first_seen', 'last_seen'];
function parseIndicator(value: unknown): CTIIndicator { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); exactKeys(value, indicatorKeys); if (value.source_pipeline !== 'external' && value.source_pipeline !== 'internal') throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); return { id: requiredText(value.id, 36), event_id: requiredText(value.event_id, 64), type: requiredText(value.type, 50), value: requiredText(value.value, 2048), confidence: boundedNumber(value.confidence, 0, 1), source_pipeline: value.source_pipeline, severity: optionalSafeText(value.severity, 30), first_seen: optionalTimestamp(value.first_seen), last_seen: optionalTimestamp(value.last_seen) }; }
function parseEventDetail(value: unknown): CTIEventDetail { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); exactKeys(value, [...eventKeys, 'indicators', 'entities', 'relationships']); const base = parseCTIEvent(Object.fromEntries(eventKeys.map((key) => [key, value[key]]))); if (!Array.isArray(value.indicators) || !Array.isArray(value.entities) || !Array.isArray(value.relationships)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); const entities = value.entities.map((item): CTIEntity => { if (!isPlainObject(item)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); exactKeys(item, ['type', 'value', 'confidence']); return { type: requiredText(item.type, 100), value: requiredText(item.value, 1000), confidence: boundedNumber(item.confidence, 0, 1) }; }); const relationships = value.relationships.map((item): CTIRelationship => { if (!isPlainObject(item)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); exactKeys(item, ['subject', 'relation', 'object', 'confidence']); return { subject: requiredText(item.subject, 1000), relation: requiredText(item.relation, 100), object: requiredText(item.object, 1000), confidence: boundedNumber(item.confidence, 0, 1) }; }); return { ...base, indicators: value.indicators.map(parseIndicator), entities, relationships }; }
function parseCorrelation(value: unknown): CTICorrelation { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); exactKeys(value, ['id', 'source_event_id', 'target_event_id', 'type', 'score', 'reason']); return { id: requiredText(value.id, 36), source_event_id: requiredText(value.source_event_id, 64), target_event_id: requiredText(value.target_event_id, 64), type: requiredText(value.type, 50), score: boundedNumber(value.score, 0, 1), reason: requiredText(value.reason, 100) }; }
function parseOutlier(value: unknown): CTIOutlier { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); exactKeys(value, ['id', 'event_id', 'started_at', 'ended_at', 'alert_count', 'is_outlier', 'anomaly_score', 'detector']); if (!validIsoTimestamp(value.started_at) || !validIsoTimestamp(value.ended_at) || typeof value.is_outlier !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); return { id: requiredText(value.id, 64), event_id: optionalSafeText(value.event_id, 64), started_at: value.started_at, ended_at: value.ended_at, alert_count: boundedNumber(value.alert_count), is_outlier: value.is_outlier, anomaly_score: boundedNumber(value.anomaly_score, -1000, 1000), detector: requiredText(value.detector, 100) }; }
const runKeys = ['id', 'pipeline', 'status', 'collected', 'processed', 'stored', 'failed', 'error_category', 'started_at', 'completed_at', 'duration_seconds'];
function parseRun(value: unknown): AnalysisRun { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); exactKeys(value, runKeys); if (!validIsoTimestamp(value.started_at)) throw new ApiError(502, 'invalid_response', 'Invalid intelligence response'); return { id: requiredText(value.id, 36), pipeline: requiredText(value.pipeline, 20), status: requiredText(value.status, 30), collected: boundedNumber(value.collected), processed: boundedNumber(value.processed), stored: boundedNumber(value.stored), failed: boundedNumber(value.failed), error_category: optionalSafeText(value.error_category, 80), started_at: value.started_at, completed_at: optionalTimestamp(value.completed_at), duration_seconds: value.duration_seconds === null ? undefined : boundedNumber(value.duration_seconds) }; }
function parseMLStatus(value: unknown): MLStatus { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid ML response'); exactKeys(value, ['execution_model', 'backend', 'primary_model', 'secondary_model', 'primary_loaded', 'secondary_loaded', 'quality_gates_passed', 'held_out_f1']); if (value.execution_model !== 'central_backend' || typeof value.primary_loaded !== 'boolean' || typeof value.secondary_loaded !== 'boolean' || typeof value.quality_gates_passed !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid ML response'); return { execution_model: 'central_backend', backend: requiredText(value.backend, 50), primary_model: requiredText(value.primary_model, 80), secondary_model: requiredText(value.secondary_model, 80), primary_loaded: value.primary_loaded, secondary_loaded: value.secondary_loaded, quality_gates_passed: value.quality_gates_passed, held_out_f1: value.held_out_f1 === null ? undefined : boundedNumber(value.held_out_f1, 0, 1) }; }
function parseMISPHealth(value: unknown): MISPHealth { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid MISP response'); exactKeys(value, ['configured', 'reachable', 'failure_category']); if (typeof value.configured !== 'boolean' || typeof value.reachable !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid MISP response'); return { configured: value.configured, reachable: value.reachable, failure_category: optionalSafeText(value.failure_category, 80) }; }
function parseMISPPreview(value: unknown): MISPPreview { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid MISP response'); exactKeys(value, ['event_id', 'title', 'configured', 'published', 'distribution', 'attributes']); if (typeof value.configured !== 'boolean' || value.published !== false || value.distribution !== 0 || !Array.isArray(value.attributes) || value.attributes.length > 1000) throw new ApiError(502, 'invalid_response', 'Invalid MISP response'); const attributes = value.attributes.map((item) => { if (!isPlainObject(item)) throw new ApiError(502, 'invalid_response', 'Invalid MISP response'); exactKeys(item, ['type', 'category', 'value', 'to_ids']); if (typeof item.to_ids !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid MISP response'); return { type: requiredText(item.type, 40), category: requiredText(item.category, 80), value: requiredText(item.value, 2048), to_ids: item.to_ids }; }); return { event_id: requiredText(value.event_id, 64), title: requiredText(value.title, 255), configured: value.configured, published: false, distribution: 0, attributes }; }
function parseMISPDelivery(value: unknown): MISPDelivery { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid MISP response'); exactKeys(value, ['event_id', 'created', 'attributes_requested', 'attributes_added', 'attributes_verified', 'published']); if (typeof value.created !== 'boolean' || typeof value.published !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid MISP response'); return { event_id: requiredText(value.event_id, 64), created: value.created, attributes_requested: boundedNumber(value.attributes_requested), attributes_added: boundedNumber(value.attributes_added), attributes_verified: boundedNumber(value.attributes_verified), published: value.published }; }
function parseSTIX(value: unknown): Record<string, unknown> { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid STIX bundle'); exactKeys(value, ['type', 'id', 'objects']); if (value.type !== 'bundle' || typeof value.id !== 'string' || !Array.isArray(value.objects) || value.objects.length > 5000 || value.objects.some((item) => !isPlainObject(item) || typeof item.type !== 'string' || Object.keys(item).some((key) => /(token|password|secret|authorization|cookie|api[_-]?key)/i.test(key)))) throw new ApiError(502, 'invalid_response', 'Invalid STIX bundle'); return value; }
function parseAdminUser(value: unknown): AdminUser { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid administration response'); exactKeys(value, ['id', 'username', 'role', 'is_active', 'created_at']); if (!isRole(value.role) || typeof value.is_active !== 'boolean' || !validIsoTimestamp(value.created_at)) throw new ApiError(502, 'invalid_response', 'Invalid administration response'); return { id: requiredText(value.id, 36), username: requiredText(value.username, 100), role: value.role, is_active: value.is_active, created_at: value.created_at }; }
function parseAdminAudit(value: unknown): AdminAudit { if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid administration response'); exactKeys(value, ['id', 'actor', 'action', 'target_type', 'target_id', 'outcome', 'created_at']); if (value.outcome !== 'success' || !validIsoTimestamp(value.created_at)) throw new ApiError(502, 'invalid_response', 'Invalid administration response'); return { id: requiredText(value.id, 36), actor: optionalSafeText(value.actor, 100), action: requiredText(value.action, 100), target_type: requiredText(value.target_type, 100), target_id: optionalSafeText(value.target_id, 100), outcome: 'success', created_at: value.created_at }; }

function parseSources(value: unknown): Source[] {
  if (!Array.isArray(value)) throw new ApiError(502, 'invalid_response', 'Invalid sources response');
  return value.map((item) => {
    if (!isPlainObject(item) || Object.keys(item).some((key) => !['source_id', 'name', 'source_type', 'status', 'metadata'].includes(key)) || Object.keys(item).length !== 5) throw new ApiError(502, 'invalid_response', 'Invalid sources response');
    const source = item as Partial<Source>;
    if (typeof source.source_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(source.source_id) || typeof source.name !== 'string' || !source.name || source.name.length > 200 || typeof source.source_type !== 'string' || !source.source_type || source.source_type.length > 80 || typeof source.status !== 'string' || !['enabled', 'disabled', 'pending_review'].includes(source.status) || !isPlainObject(source.metadata) || Object.keys(source.metadata).some((key) => !['category', 'method'].includes(key)) || Object.values(source.metadata).some((entry) => typeof entry !== 'string' || !entry || entry.length > 100)) throw new ApiError(502, 'invalid_response', 'Invalid sources response');
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
  const topKeys = ['schema_version', 'job_id', 'command_id', 'state', 'created_at', 'updated_at', 'progress', 'result', 'error'];
  if (Object.keys(body).length !== topKeys.length || Object.keys(body).some((key) => !topKeys.includes(key)) || body.schema_version !== '1.0' || typeof body.job_id !== 'string' || body.job_id.length < 10 || typeof body.command_id !== 'string' || body.command_id.length < 10 || typeof body.state !== 'string' || !JOB_STATES.includes(body.state as JobState) || !validTimestamp(body.created_at) || !validTimestamp(body.updated_at) || !validCounts(body.progress) || (body.result !== null && !isPlainObject(body.result)) || (body.error !== null && !isPlainObject(body.error))) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
  const counts: ExternalJob['counts'] = {};
  const sources: ExternalJob['sources'] = {};
  if (body.result) {
    const resultKeys = ['status', 'scope', 'run_id', 'source_id', 'source_count', 'registered_source_count', 'manual_source_count', 'records_created', 'records_updated', ...JOB_COUNT_KEYS, 'force', 'sources', 'manual_sources', 'export'];
    if (Object.keys(body.result).some((key) => !resultKeys.includes(key))) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
    for (const key of ['status', 'scope', 'run_id', 'source_id']) if (body.result[key] !== undefined && (typeof body.result[key] !== 'string' || !(body.result[key] as string) || (body.result[key] as string).length > 200)) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
    for (const key of ['source_count', 'registered_source_count', 'manual_source_count', 'records_created', 'records_updated']) if (body.result[key] !== undefined && (!Number.isSafeInteger(body.result[key]) || (body.result[key] as number) < 0)) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
    if (body.result.force !== undefined && typeof body.result.force !== 'boolean') throw new ApiError(502, 'invalid_response', 'Invalid external job response');
    for (const key of JOB_COUNT_KEYS) {
    const amount = body.result[key];
    if (amount !== undefined) {
      if (!Number.isSafeInteger(amount) || (amount as number) < 0) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
      counts[key] = amount as number;
    }
    }
    for (const group of ['sources', 'manual_sources']) if (body.result[group] !== undefined) parseJobSources(body.result[group], sources);
    if (body.result.export !== undefined) validateJobExport(body.result.export);
  }
  if (body.error && (Object.keys(body.error).some((key) => !['code', 'message', 'retryable', 'details'].includes(key)) || typeof body.error.code !== 'string' || typeof body.error.message !== 'string' || typeof body.error.retryable !== 'boolean' || !isPlainObject(body.error.details) || Object.keys(body.error.details).length > 0)) throw new ApiError(502, 'invalid_response', 'Invalid external job response');
  const message = body.error ? sanitizeError(body.error.message as string) : undefined;
  return { job_id: body.job_id, command_id: body.command_id, state: body.state as JobState, created_at: body.created_at as string, updated_at: body.updated_at as string, counts, sources, error: message };
}

function validCounts(value: unknown): value is Record<string, number> { return isPlainObject(value) && Object.keys(value).every((key) => JOB_COUNT_KEYS.includes(key as typeof JOB_COUNT_KEYS[number])) && Object.values(value).every((amount) => Number.isSafeInteger(amount) && (amount as number) >= 0); }
function parseJobSources(value: unknown, target: ExternalJob['sources']) { if (!isPlainObject(value) || Object.keys(value).length > 100) throw new ApiError(502, 'invalid_response', 'Invalid external job response'); for (const [id, item] of Object.entries(value)) { if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(id) || !isPlainObject(item) || typeof item.status !== 'string' || !item.status || item.status.length > 40 || Object.keys(item).some((key) => key !== 'status' && !JOB_COUNT_KEYS.includes(key as typeof JOB_COUNT_KEYS[number]))) throw new ApiError(502, 'invalid_response', 'Invalid external job response'); const sourceCounts: ExternalJob['counts'] = {}; for (const key of JOB_COUNT_KEYS) if (item[key] !== undefined) { if (!Number.isSafeInteger(item[key]) || (item[key] as number) < 0) throw new ApiError(502, 'invalid_response', 'Invalid external job response'); sourceCounts[key] = item[key] as number; } target[id] = { status: sanitizeError(item.status), counts: sourceCounts }; } }
function validateJobExport(value: unknown) { if (!isPlainObject(value) || Object.keys(value).some((key) => !['status', 'run_id', 'dataset_sha256', 'accepted_records', 'review_records', 'error', 'reason'].includes(key))) throw new ApiError(502, 'invalid_response', 'Invalid external job response'); for (const key of ['status', 'run_id', 'reason']) if (value[key] !== undefined && (typeof value[key] !== 'string' || !(value[key] as string) || (value[key] as string).length > 200)) throw new ApiError(502, 'invalid_response', 'Invalid external job response'); if (value.dataset_sha256 !== undefined && value.dataset_sha256 !== null && (typeof value.dataset_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.dataset_sha256))) throw new ApiError(502, 'invalid_response', 'Invalid external job response'); for (const key of ['accepted_records', 'review_records']) if (value[key] !== undefined && (!Number.isSafeInteger(value[key]) || (value[key] as number) < 0)) throw new ApiError(502, 'invalid_response', 'Invalid external job response'); if (value.error !== undefined && value.error !== null && (!isPlainObject(value.error) || Object.keys(value.error).some((key) => !['code', 'message', 'retryable', 'details'].includes(key)) || typeof value.error.code !== 'string' || typeof value.error.message !== 'string' || typeof value.error.retryable !== 'boolean' || !isPlainObject(value.error.details) || Object.keys(value.error.details).length > 0)) throw new ApiError(502, 'invalid_response', 'Invalid external job response'); }

function validTimestamp(value: unknown): value is string { return typeof value === 'string' && value.length <= 40 && value.endsWith('Z') && !Number.isNaN(Date.parse(value)); }
function validIsoTimestamp(value: unknown): value is string { return typeof value === 'string' && value.length <= 40 && !Number.isNaN(Date.parse(value)); }
function normalizePublishedDate(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value !== 'string' || value.length > 64) throw new ApiError(502, 'invalid_response', 'Invalid reviews response');
  const iso = /^(\d{4})-(\d{2})-(\d{2})T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;
  const rfc = /^(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s)?(\d{2})\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s(\d{4})\s(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\s(?:GMT|UT|[+-](?:[01]\d|2[0-3])[0-5]\d)$/;
  const isoMatch = value.match(iso); const rfcMatch = value.match(rfc);
  if (!isoMatch && !rfcMatch) throw new ApiError(502, 'invalid_response', 'Invalid reviews response');
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const year = Number(isoMatch?.[1] || rfcMatch?.[3]); const month = isoMatch ? Number(isoMatch[2]) : months.indexOf(rfcMatch![2]) + 1; const day = Number(isoMatch?.[3] || rfcMatch?.[1]);
  if (month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()) throw new ApiError(502, 'invalid_response', 'Invalid reviews response');
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) throw new ApiError(502, 'invalid_response', 'Invalid reviews response');
  return new Date(parsed).toISOString();
}
function optionalText(value: unknown, max = 200): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value !== 'string' || value.length > max) throw new ApiError(502, 'invalid_response', 'Invalid external response');
  return sanitizeError(value);
}

function parseExportSummary(value: unknown): ExportSummary {
  if (!isPlainObject(value) || Object.keys(value).some((key) => !['run_id', 'status', 'dataset_sha256', 'accepted_records', 'review_records', 'completed_at'].includes(key))
    || typeof value.run_id !== 'string' || value.run_id.length > 200 || typeof value.status !== 'string' || value.status.length > 40
    || (value.dataset_sha256 !== null && value.dataset_sha256 !== undefined && (typeof value.dataset_sha256 !== 'string' || !/^(?:sha256:)?[0-9a-f]{64}$/.test(value.dataset_sha256)))
    || !Number.isSafeInteger(value.accepted_records) || (value.accepted_records as number) < 0 || !Number.isSafeInteger(value.review_records) || (value.review_records as number) < 0
    || (value.completed_at !== null && value.completed_at !== undefined && !validTimestamp(value.completed_at))) throw new ApiError(502, 'invalid_response', 'Invalid export summary response');
  const digest = typeof value.dataset_sha256 === 'string' ? value.dataset_sha256.replace(/^sha256:/, '') : undefined;
  return { run_id: value.run_id, status: value.status, dataset_sha256: digest, accepted_records: value.accepted_records as number, review_records: value.review_records as number, completed_at: value.completed_at as string | undefined };
}

function parseReviews(value: unknown): LatestReviews {
  if (!isPlainObject(value) || Object.keys(value).length !== 2 || typeof value.run_id !== 'string' || value.run_id.length > 200 || !Array.isArray(value.records) || value.records.length > 500) throw new ApiError(502, 'invalid_response', 'Invalid reviews response');
  const allowed = ['record_id', 'title', 'source_type', 'review_reason', 'review_reasons', 'classification_label', 'privacy_status', 'collected_at', 'published'];
  const records = value.records.map((item): ReviewRecord => {
    if (!isPlainObject(item) || Object.keys(item).some((key) => !allowed.includes(key)) || typeof item.record_id !== 'string' || !item.record_id || item.record_id.length > 200
      || typeof item.review_reason !== 'string' || item.review_reason.length > 200 || !Array.isArray(item.review_reasons) || item.review_reasons.length > 20
      || item.review_reasons.some((reason) => typeof reason !== 'string' || reason.length > 200)
      || (item.collected_at !== null && item.collected_at !== undefined && !validTimestamp(item.collected_at))) throw new ApiError(502, 'invalid_response', 'Invalid reviews response');
    return { record_id: item.record_id, title: optionalText(item.title, 300), source_type: optionalText(item.source_type, 100), review_reason: sanitizeError(item.review_reason), review_reasons: item.review_reasons.map((reason) => sanitizeError(reason as string)), classification_label: optionalText(item.classification_label, 100), privacy_status: optionalText(item.privacy_status, 100), collected_at: item.collected_at as string | undefined, published: normalizePublishedDate(item.published) };
  });
  return { run_id: value.run_id, records };
}

function parseJobHistory(value: unknown): JobHistory {
  if (!isPlainObject(value) || Object.keys(value).length !== 3 || value.schema_version !== '1.0' || value.persistence !== 'process_memory' || !Array.isArray(value.jobs) || value.jobs.length > 100) throw new ApiError(502, 'invalid_response', 'Invalid job history response');
  const allowed = ['schema_version', 'job_id', 'source_id', 'state', 'created_at', 'updated_at', 'counts', 'error_code', 'error_message'];
  const jobs = value.jobs.map((item): JobSummary => {
    if (!isPlainObject(item) || Object.keys(item).some((key) => !allowed.includes(key)) || item.schema_version !== '1.0' || typeof item.job_id !== 'string' || item.job_id.length < 10
      || typeof item.state !== 'string' || !JOB_STATES.includes(item.state as JobState) || !validTimestamp(item.created_at) || !validTimestamp(item.updated_at) || !isPlainObject(item.counts)
      || (item.source_id !== null && item.source_id !== undefined && (typeof item.source_id !== 'string' || item.source_id.length > 200))) throw new ApiError(502, 'invalid_response', 'Invalid job history response');
    const counts: ExternalJob['counts'] = {};
    if (Object.keys(item.counts).some((key) => !JOB_COUNT_KEYS.includes(key as typeof JOB_COUNT_KEYS[number]))) throw new ApiError(502, 'invalid_response', 'Invalid job history response');
    for (const key of JOB_COUNT_KEYS) if (item.counts[key] !== undefined) { if (!Number.isSafeInteger(item.counts[key]) || (item.counts[key] as number) < 0) throw new ApiError(502, 'invalid_response', 'Invalid job history response'); counts[key] = item.counts[key] as number; }
    return { job_id: item.job_id, source_id: item.source_id as string | undefined, state: item.state as JobState, created_at: item.created_at, updated_at: item.updated_at, counts, error_code: optionalText(item.error_code, 100), error_message: optionalText(item.error_message, 300) };
  });
  return { persistence: 'process_memory', jobs };
}

function parseManualPreview(value: unknown): ManualPreview {
  if (!isPlainObject(value)) throw new ApiError(502, 'invalid_response', 'Invalid manual preview response');
  const nullable = ['classification_label', 'classification_confidence'];
  const required = ['schema_version', 'preview_id', 'state', 'created_at', 'expires_at', 'display_url', 'page_type', 'title', 'excerpt',
    'disposition', 'privacy_status', 'review_reasons', 'content_sha256', 'counts',
    'items_preview', 'items_preview_total', 'items_preview_truncated'];
  if (Object.keys(value).some((key) => !required.includes(key) && !nullable.includes(key)) || required.some((key) => !(key in value))
    || value.schema_version !== '1.0' || typeof value.preview_id !== 'string' || value.preview_id.length < 20 || value.state !== 'pending'
    || typeof value.created_at !== 'string' || !value.created_at.endsWith('Z') || typeof value.expires_at !== 'string' || !value.expires_at.endsWith('Z')
    || typeof value.display_url !== 'string' || value.display_url.length > 400 || typeof value.page_type !== 'string' || value.page_type.length > 80
    || typeof value.title !== 'string' || value.title.length > 300 || typeof value.excerpt !== 'string' || value.excerpt.length > 500
    || !['accepted', 'review', 'rejected'].includes(String(value.disposition))
    || (value.classification_label !== null && value.classification_label !== undefined && typeof value.classification_label !== 'string')
    || (value.classification_confidence !== null && value.classification_confidence !== undefined && (typeof value.classification_confidence !== 'number' || value.classification_confidence < 0 || value.classification_confidence > 1))
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
  const required = ['item_index', 'title', 'excerpt', 'page_type', 'disposition', 'privacy_status', 'review_reasons', 'content_sha256'];
  const allowed = [...required, 'classification_label', 'classification_confidence', 'published'];
  return !Object.keys(value).some((key) => !allowed.includes(key)) && required.every((key) => key in value)
    && value.item_index === index && typeof value.title === 'string' && value.title.length <= 200
    && typeof value.excerpt === 'string' && value.excerpt.length <= 300 && value.page_type === 'article'
    && ['accepted', 'review', 'rejected'].includes(String(value.disposition))
    && (value.classification_label === null || value.classification_label === undefined || (typeof value.classification_label === 'string' && value.classification_label.length <= 80))
    && (value.classification_confidence === null || value.classification_confidence === undefined || (typeof value.classification_confidence === 'number' && value.classification_confidence >= 0 && value.classification_confidence <= 1))
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
  if (!isPlainObject(value) || Object.keys(value).some((key) => !['id', 'username', 'role', 'is_active'].includes(key))) throw new ApiError(502, 'invalid_response', 'Invalid user response');
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
  systemHealth: async () => parseSystemHealth(await request<unknown>('/health')),
  integrationStatus: async () => parseIntegrationStatus(await request<unknown>('/integrations/status')),
  internalHealth: async (integration: InternalIntegration) => parseHealth(await request<unknown>(`/integrations/${integration}/health`)),
  internalEvents: async (integration: InternalIntegration, limit = 25, offset = 0, severity = '') => parseInternalEvents(await request<unknown>(`/internal/sources/${integration}/events?limit=${limit}&offset=${offset}${severity ? `&severity=${encodeURIComponent(severity)}` : ''}`), integration),
  pullInternal: async (integration: InternalIntegration) => parsePullResult(await request<unknown>(`/integrations/${integration}/pull`, { method: 'POST' }, INTERNAL_PULL_TIMEOUT_MS)),
  intelligenceEvents: async (limit = 25, offset = 0, filters: { severity?: string; source_pipeline?: string; processing_status?: string; search?: string } = {}) => { const params = new URLSearchParams({ limit: String(limit), offset: String(offset) }); Object.entries(filters).forEach(([key, value]) => { if (value) params.set(key, value); }); return parsePage(await request<unknown>(`/intelligence/events?${params}`), parseCTIEvent); },
  intelligenceEvent: async (id: string) => parseEventDetail(await request<unknown>(`/intelligence/events/${encodeURIComponent(id)}`)),
  intelligenceIndicators: async (limit = 25, offset = 0, type = '', search = '') => { const params = new URLSearchParams({ limit: String(limit), offset: String(offset) }); if (type) params.set('indicator_type', type); if (search) params.set('search', search); return parsePage(await request<unknown>(`/intelligence/indicators?${params}`), parseIndicator); },
  intelligenceCorrelations: async (limit = 25, offset = 0) => parsePage(await request<unknown>(`/intelligence/correlations?limit=${limit}&offset=${offset}`), parseCorrelation),
  intelligenceOutliers: async (limit = 25, offset = 0, only = false) => parsePage(await request<unknown>(`/intelligence/outliers?limit=${limit}&offset=${offset}&only_outliers=${only}`), parseOutlier),
  analysisRuns: async (limit = 25, offset = 0) => parsePage(await request<unknown>(`/intelligence/runs?limit=${limit}&offset=${offset}`), parseRun),
  analysisRun: async (id: string) => parseRun(await request<unknown>(`/intelligence/runs/${encodeURIComponent(id)}`)),
  mlStatus: async () => parseMLStatus(await request<unknown>('/intelligence/ml/status')),
  mispHealth: async () => parseMISPHealth(await request<unknown>('/intelligence/misp/health')),
  mispPreview: async (eventId: string) => parseMISPPreview(await request<unknown>(`/intelligence/events/${encodeURIComponent(eventId)}/misp-preview`)),
  mispSend: async (eventId: string) => parseMISPDelivery(await request<unknown>(`/intelligence/events/${encodeURIComponent(eventId)}/misp`, { method: 'POST' })),
  stixBundle: async (eventId: string) => parseSTIX(await request<unknown>(`/events/${encodeURIComponent(eventId)}/stix`)),
  adminUsers: async (limit = 25, offset = 0, search = '', role = '', active = '') => { const params = new URLSearchParams({ limit: String(limit), offset: String(offset) }); if (search) params.set('search', search); if (role) params.set('role', role); if (active) params.set('is_active', active); return parsePage(await request<unknown>(`/admin/users?${params}`), parseAdminUser); },
  adminCreateUser: async (username: string, password: string, role: Role) => parseAdminUser(await request<unknown>('/admin/users', { method: 'POST', body: JSON.stringify({ username, password, role }) })),
  adminChangeRole: async (id: string, role: Role) => parseAdminUser(await request<unknown>(`/admin/users/${encodeURIComponent(id)}/role`, { method: 'PATCH', body: JSON.stringify({ role }) })),
  adminChangeActive: async (id: string, isActive: boolean) => parseAdminUser(await request<unknown>(`/admin/users/${encodeURIComponent(id)}/active`, { method: 'PATCH', body: JSON.stringify({ is_active: isActive }) })),
  adminResetPassword: async (id: string, password: string) => parseAdminUser(await request<unknown>(`/admin/users/${encodeURIComponent(id)}/password`, { method: 'POST', body: JSON.stringify({ password }) })),
  adminAudit: async (limit = 25, offset = 0, action = '', actor = '') => { const params = new URLSearchParams({ limit: String(limit), offset: String(offset) }); if (action) params.set('action', action); if (actor) params.set('actor', actor); return parsePage(await request<unknown>(`/admin/audit?${params}`), parseAdminAudit); },
  startExternalSourceJob: async (sourceId: string) => parseExternalJob(await request<unknown>(`/integrations/external-control/sources/${encodeURIComponent(sourceId)}/jobs`, { method: 'POST', body: JSON.stringify({ force: false }) })),
  startAllExternalSources: async () => parseExternalJob(await request<unknown>('/integrations/external-control/jobs', { method: 'POST', body: JSON.stringify({ source_ids: [], scope: 'all_enabled', force: false }) })),
  startManualUrlJob: async (url: string) => parseExternalJob(await request<unknown>('/integrations/external-control/manual-sources', { method: 'POST', body: JSON.stringify({ url, force: false }) })),
  recheckManualSource: async (url: string) => parseExternalJob(await request<unknown>('/integrations/external-control/manual-sources/recheck', { method: 'POST', body: JSON.stringify({ url, force: true }) })),
  createManualPreview: async (url: string, signal?: AbortSignal) => parseManualPreview(await request<unknown>('/integrations/external-control/manual-sources/previews', { method: 'POST', body: JSON.stringify({ url }), signal }, EXTERNAL_SYNC_TIMEOUT_MS)),
  approveManualPreview: async (preview: ManualPreview) => parseExternalJob(await request<unknown>(`/integrations/external-control/manual-sources/previews/${encodeURIComponent(preview.preview_id)}/approve`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ expected_content_sha256: preview.content_sha256 }) })),
  rejectManualPreview: async (previewId: string, reason: 'not_relevant' | 'duplicate' | 'user_cancelled') => parseManualPreviewRejection(await request<unknown>(`/integrations/external-control/manual-sources/previews/${encodeURIComponent(previewId)}/reject`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ reason }) })),
  externalJob: async (jobId: string) => parseExternalJob(await request<unknown>(`/integrations/external-control/jobs/${encodeURIComponent(jobId)}`)),
  latestExternalExport: async () => parseExportSummary(await request<unknown>('/integrations/external-control/exports/latest')),
  latestExternalReviews: async () => parseReviews(await request<unknown>('/integrations/external-control/reviews/latest')),
  externalJobs: async () => parseJobHistory(await request<unknown>('/integrations/external-control/jobs?limit=50')),
  cancelExternalJob: async (jobId: string) => parseExternalJob(await request<unknown>(`/integrations/external-control/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' })),
};
