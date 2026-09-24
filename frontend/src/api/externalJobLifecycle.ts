import type { ExternalJob, JobState } from './client';

export const JOB_POLL_INTERVAL_MS = 2_000;
export const JOB_INTERACTIVE_MONITOR_MS = 120_000;
export const JOB_POLL_TRANSIENT_RETRIES = 4;
export const TERMINAL_JOB_STATES: JobState[] = ['completed', 'partial', 'failed', 'cancelled'];
export const jobPollingRetryDelay = (attempt: number) => Math.min(2_000 * (2 ** attempt), 10_000);

const STORAGE_KEY = 'cti_external_active_jobs_v1';
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{9,199}$/;
const CONTEXT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const MAX_ENTRIES = 20;

export type StoredExternalJob = { context: string; jobId: string; sourceId: string; savedAt: number };

export function loadActiveExternalJobs(): StoredExternalJob[] {
  try {
    const value: unknown = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '[]');
    if (!Array.isArray(value)) return [];
    return value.slice(0, MAX_ENTRIES).filter((item): item is StoredExternalJob => {
      if (!item || typeof item !== 'object') return false;
      const candidate = item as Partial<StoredExternalJob>;
      return typeof candidate.context === 'string' && CONTEXT.test(candidate.context)
        && typeof candidate.jobId === 'string' && ID.test(candidate.jobId)
        && typeof candidate.sourceId === 'string' && CONTEXT.test(candidate.sourceId)
        && typeof candidate.savedAt === 'number' && Number.isSafeInteger(candidate.savedAt) && candidate.savedAt > 0;
    });
  } catch { return []; }
}

export function rememberActiveExternalJob(context: string, sourceId: string, jobId: string) {
  if (!CONTEXT.test(context) || !CONTEXT.test(sourceId) || !ID.test(jobId)) return;
  const next = [{ context, sourceId, jobId, savedAt: Date.now() }, ...loadActiveExternalJobs().filter((item) => item.context !== context)].slice(0, MAX_ENTRIES);
  try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch { /* monitoring remains available in-memory */ }
}

export function forgetActiveExternalJob(context: string, jobId?: string) {
  try {
    const next = loadActiveExternalJobs().filter((item) => item.context !== context || (jobId !== undefined && item.jobId !== jobId));
    if (next.length) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next)); else sessionStorage.removeItem(STORAGE_KEY);
  } catch { /* storage is optional */ }
}

export function acceptExternalJobUpdate(current: ExternalJob, incoming: ExternalJob): ExternalJob {
  if (incoming.job_id !== current.job_id) return current;
  if (TERMINAL_JOB_STATES.includes(current.state) && !TERMINAL_JOB_STATES.includes(incoming.state)) return current;
  const currentTime = Date.parse(current.updated_at), incomingTime = Date.parse(incoming.updated_at);
  return Number.isFinite(currentTime) && Number.isFinite(incomingTime) && incomingTime < currentTime ? current : incoming;
}
