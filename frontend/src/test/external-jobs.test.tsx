import { act, cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearToken } from '../api/client';
import { Jobs } from '../pages/Jobs';
import { renderWithProviders } from './fixtures';

const summary = { schema_version: '1.0', job_id: 'job-selected-1234', source_id: 'source-one', state: 'running', created_at: '2026-09-13T00:00:00Z', updated_at: '2026-09-13T00:00:01Z', counts: {}, error_code: null, error_message: null };
const status = (state = 'running', jobId = summary.job_id) => ({ schema_version: '1.0', job_id: jobId, command_id: 'cmd-selected-1234', state, created_at: summary.created_at, updated_at: '2026-09-13T00:00:02Z', progress: {}, result: state === 'completed' ? { accepted_records: 1 } : null, error: null });
const json = (body: unknown, code = 200) => Promise.resolve({ ok: code < 400, status: code, json: () => Promise.resolve(body) } as Response);

beforeEach(() => { sessionStorage.clear(); clearToken(); vi.restoreAllMocks(); sessionStorage.setItem('cti_access_token', 'token'); });
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe('external job history monitoring', () => {
  it('recovers a transient 503 on the same job and stops at terminal state', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true }); let polls = 0;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const path = String(input);
      if (path.endsWith('/auth/me')) return json({ id: 'u', username: 'analyst', role: 'analyst', is_active: true });
      if (path.includes('/jobs?limit=50')) return json({ schema_version: '1.0', persistence: 'process_memory', jobs: [summary] });
      if (path.endsWith(`/jobs/${summary.job_id}`)) return ++polls === 1 ? json({ detail: 'private upstream http://10.0.0.1 token=secret' }, 503) : json(status('completed'));
      return json({});
    });
    renderWithProviders(<Jobs />); const actor = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await actor.click(await screen.findByRole('button', { name: 'متابعة' }));
    expect(await screen.findByText(/جار إعادة الاتصال/)).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
    await screen.findByText(/الحالة: مكتملة/);
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith(`/jobs/${summary.job_id}`))).toHaveLength(2);
    expect(document.body).not.toHaveTextContent('10.0.0.1'); expect(document.body).not.toHaveTextContent('token=secret');
  });

  it('prevents duplicate cancellation and rejects late identity replacement', async () => {
    let resolveCancel!: (value: Response) => void; const pending = new Promise<Response>((resolve) => { resolveCancel = resolve; });
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith('/auth/me')) return json({ id: 'u', username: 'analyst', role: 'analyst', is_active: true });
      if (path.includes('/jobs?limit=50')) return json({ schema_version: '1.0', persistence: 'process_memory', jobs: [summary] });
      if (path.endsWith('/cancel') && init?.method === 'POST') return pending;
      if (path.endsWith(`/jobs/${summary.job_id}`)) return json(status());
      return json({});
    });
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Jobs />); const actor = userEvent.setup();
    const cancel = await screen.findByRole('button', { name: 'إلغاء' }); await actor.click(cancel); expect(cancel).toBeDisabled(); cancel.click();
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/cancel'))).toHaveLength(1);
    resolveCancel(await json(status('cancellation_requested', 'job-different-1234')));
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    expect(document.body).not.toHaveTextContent('job-different-1234');
  });
});
