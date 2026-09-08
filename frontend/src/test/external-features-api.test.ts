import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, clearToken } from '../api/client';

const response = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => { sessionStorage.clear(); clearToken(); vi.restoreAllMocks(); });
afterEach(() => vi.useRealTimers());

describe('external feature contracts', () => {
  it('uses exact same-origin paths and accepts safe responses', async () => {
    const bodies: Record<string, unknown> = {
      '/api/v1/integrations/external-control/exports/latest': { run_id: 'run-123', status: 'completed', dataset_sha256: 'a'.repeat(64), accepted_records: 2, review_records: 1, completed_at: '2026-09-07T00:00:00Z' },
      '/api/v1/integrations/external-control/reviews/latest': { run_id: 'run-123', records: [] },
      '/api/v1/integrations/external-control/jobs?limit=50': { schema_version: '1.0', persistence: 'process_memory', jobs: [] },
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => response(bodies[String(input)]));
    await api.latestExternalExport(); await api.latestExternalReviews(); await api.externalJobs();
    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual(Object.keys(bodies));
    expect(fetchMock.mock.calls.every(([input]) => String(input).startsWith('/api/v1/'))).toBe(true);
  });

  it('rejects malformed and sensitive fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run', records: [{ record_id: 'rec', review_reason: 'x', review_reasons: [], canonical_url: 'https://private.test' }] }));
    await expect(api.latestExternalReviews()).rejects.toMatchObject({ status: 502, code: 'invalid_response' });
    vi.restoreAllMocks();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ schema_version: '1.0', persistence: 'process_memory', jobs: [{ schema_version: '1.0', job_id: 'job-1234567890', source_id: null, state: 'failed', created_at: '2026-09-07T00:00:00Z', updated_at: '2026-09-07T00:00:01Z', counts: {}, error_code: null, error_message: null, token: 'secret' }] }));
    await expect(api.externalJobs()).rejects.toMatchObject({ status: 502, code: 'invalid_response' });
    vi.restoreAllMocks();
    const unsafeJob = { schema_version: '1.0', job_id: 'job-1234567890', command_id: 'cmd-1234567890', state: 'completed', created_at: '2026-09-07T00:00:00Z', updated_at: '2026-09-07T00:00:01Z', progress: {}, result: { accepted_records: 1, path: '/tmp/private' }, error: null };
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response(unsafeJob));
    await expect(api.externalJob('job-1234567890')).rejects.toMatchObject({ status: 502, code: 'invalid_response' });
    vi.restoreAllMocks();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response([{ source_id: 'safe', name: 'Safe', source_type: 'rss', status: 'enabled', metadata: {}, token: 'secret' }]));
    await expect(api.externalSources()).rejects.toMatchObject({ status: 502, code: 'invalid_response' });
  });

  it('gives manual preview a 40-second timeout without changing ordinary requests', async () => {
    vi.useFakeTimers();
    const hanging = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))));
    const ordinary = api.externalHealth(); const ordinaryCheck = expect(ordinary).rejects.toMatchObject({ status: 408 }); await vi.advanceTimersByTimeAsync(15_000); await ordinaryCheck;
    let settled = false; const preview = api.createManualPreview('https://example.test/report'); const previewResult = preview.then((value) => ({ value }), (error) => ({ error })).finally(() => { settled = true; }); await vi.advanceTimersByTimeAsync(15_000);
    expect(hanging).toHaveBeenCalledTimes(2); expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(25_000); expect((await previewResult as { error: { status: number } }).error).toMatchObject({ status: 408 });
  });
});
