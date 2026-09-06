import { act, cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, clearToken } from '../api/client';
import { JOB_POLL_INTERVAL_MS, JOB_POLL_MAX_MS, Sources } from '../pages/Sources';
import { renderWithProviders } from './fixtures';

const enabled = { source_id: 'source-one', name: 'المصدر الأول', source_type: 'rss', status: 'enabled', metadata: {} };
const disabled = { source_id: 'source-two', name: 'المصدر الثاني', source_type: 'cert', status: 'disabled', metadata: {} };
const otherEnabled = { source_id: 'source-three', name: 'المصدر الثالث', source_type: 'rss', status: 'enabled', metadata: {} };
const users = { viewer: { id: 'u1', username: 'viewer', role: 'viewer', is_active: true }, analyst: { id: 'u2', username: 'analyst', role: 'analyst', is_active: true }, admin: { id: 'u3', username: 'admin', role: 'admin', is_active: true } } as const;
const job = (state: string, result: Record<string, unknown> | null = null, error: Record<string, unknown> | null = null) => ({ schema_version: '1.0', job_id: 'job-1234567890', command_id: 'cmd-1234567890', state, created_at: '2026-09-06T00:00:00Z', updated_at: '2026-09-06T00:00:01Z', progress: {}, result, error });
const response = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);

function mockRole(role: keyof typeof users, handler?: (path: string, init?: RequestInit) => Promise<Response>) {
  sessionStorage.setItem('cti_access_token', 'token');
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const path = String(input);
    if (path.endsWith('/auth/me')) return response(users[role]);
    if (path.endsWith('/integrations/external-control/sources')) return response([enabled, disabled, otherEnabled]);
    return handler ? handler(path, init) : response(job('queued'));
  });
}

beforeEach(() => { sessionStorage.clear(); clearToken(); vi.restoreAllMocks(); });
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe('single external source job', () => {
  it('keeps viewers read-only and shows the action to analyst and admin', async () => {
    mockRole('viewer'); renderWithProviders(<Sources />); await screen.findByText(enabled.name); expect(screen.queryByRole('button', { name: `تشغيل ${enabled.name}` })).not.toBeInTheDocument(); cleanup();
    mockRole('analyst'); renderWithProviders(<Sources />); expect(await screen.findByRole('button', { name: `تشغيل ${enabled.name}` })).toBeEnabled(); cleanup();
    mockRole('admin'); renderWithProviders(<Sources />); expect(await screen.findByRole('button', { name: `تشغيل ${enabled.name}` })).toBeEnabled();
  });

  it('disables a disabled source and requires confirmation', async () => {
    const fetchMock = mockRole('analyst'); renderWithProviders(<Sources />);
    expect(await screen.findByRole('button', { name: `تشغيل ${disabled.name}` })).toBeDisabled();
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    await userEvent.setup().click(screen.getByRole('button', { name: `تشغيل ${enabled.name}` }));
    expect(window.confirm).toHaveBeenCalled(); expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/jobs'))).toBe(false);
  });

  it('starts only the selected source and prevents duplicate submissions', async () => {
    let resolveStart!: (value: Response) => void;
    const pending = new Promise<Response>((resolve) => { resolveStart = resolve; });
    const fetchMock = mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? pending : response(job('queued')));
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />); const button = await screen.findByRole('button', { name: `تشغيل ${enabled.name}` });
    await userEvent.setup().click(button); expect(button).toBeDisabled(); await userEvent.setup().click(button);
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/sources/source-one/jobs'))).toHaveLength(1);
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('source-two/jobs'))).toBe(false);
    resolveStart(await response(job('queued'))); await screen.findByText(/في الانتظار/);
  });

  it('keeps job state and result counts on the selected source row only', async () => {    let resolveStart!: (value: Response) => void; const pendingStart = new Promise<Response>((resolve) => { resolveStart = resolve; });    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? pendingStart : response(job('completed', { accepted_records: 7 }))); vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />);    const selectedButton = await screen.findByRole('button', { name: `تشغيل ${enabled.name}` }); const otherButton = screen.getByRole('button', { name: `تشغيل ${otherEnabled.name}` });    await userEvent.setup().click(selectedButton); expect(selectedButton).toBeDisabled(); expect(selectedButton).toHaveTextContent('جار الإرسال'); expect(otherButton).toBeEnabled(); expect(otherButton).toHaveTextContent('تشغيل');    resolveStart(await response(job('completed', { accepted_records: 7 }))); const selectedRow = screen.getByText(enabled.name).closest('tr')!; await waitFor(() => expect(selectedRow.nextElementSibling).not.toBeNull()); const detailRow = selectedRow.nextElementSibling as HTMLElement;    expect(within(detailRow).getByText(/مكتملة/)).toBeInTheDocument(); expect(within(detailRow).getByText('7')).toBeInTheDocument(); const otherRow = screen.getByText(otherEnabled.name).closest('tr')!; expect(within(otherRow).queryByText(/مكتملة|قيد التشغيل/)).not.toBeInTheDocument(); expect(within(otherRow).getByRole('button')).toBeEnabled();  });
  it('polls queued to running to completed and displays returned counts', async () => {
    let poll = 0;
    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? response(job('queued')) : response(++poll === 1 ? job('running') : job('completed', { accepted_records: 3, review_records: 1, rejected_records: 2, skipped_records: 4, error_count: 0 })));
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />); const button = await screen.findByRole('button', { name: `تشغيل ${enabled.name}` });
    button.click(); await screen.findByText(/قيد التشغيل/)
    await screen.findByText(/مكتملة/, {}, { timeout: JOB_POLL_INTERVAL_MS * 2 }); expect(screen.getByText('3')).toBeInTheDocument(); expect(screen.getByText('للمراجعة')).toBeInTheDocument();
  });

  it('shows failed jobs with sanitized errors', async () => {
    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? response(job('failed', { error_count: 1 }, { message: 'failure at http://private.local token=secret' })) : response(job('failed', { error_count: 1 }, { message: 'failure at http://private.local token=secret' })));
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />); await userEvent.setup().click(await screen.findByRole('button', { name: `تشغيل ${enabled.name}` })); await screen.findByText(/فشلت/); expect(document.body).not.toHaveTextContent('private.local'); expect(document.body).not.toHaveTextContent('token=secret');
  });

  it('times out bounded polling and cleans polling up on unmount', async () => {
    const fetchMock = mockRole('analyst', (path) => response(job(path.includes('/sources/') ? 'queued' : 'running'))); vi.spyOn(window, 'confirm').mockReturnValue(true);
    const view = renderWithProviders(<Sources />); await screen.findByRole('button', { name: `تشغيل ${enabled.name}` }); vi.useFakeTimers();
    await act(async () => { screen.getByRole('button', { name: `تشغيل ${enabled.name}` }).click(); await Promise.resolve(); });
    await act(async () => { vi.advanceTimersByTime(JOB_POLL_MAX_MS); await Promise.resolve(); }); expect(screen.getByRole('alert')).toHaveTextContent('انتهت مهلة');
    const count = fetchMock.mock.calls.length; view.unmount(); await act(async () => { vi.advanceTimersByTime(JOB_POLL_INTERVAL_MS * 2); }); expect(fetchMock).toHaveBeenCalledTimes(count);
  });

  it('uses existing 401 expiry behavior and rejects malformed jobs', async () => {
    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? response({ detail: 'Authentication required' }, 401) : response(job('queued'))); vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<Sources />); await userEvent.setup().click(await screen.findByRole('button', { name: `تشغيل ${enabled.name}` })); await waitFor(() => expect(sessionStorage.getItem('cti_access_token')).toBeNull()); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ job_id: 'short', state: 'unknown' })); await expect(api.externalJob('job-1234567890')).rejects.toMatchObject({ status: 502, code: 'invalid_response' });
  });
});
