import { cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearToken } from '../api/client';
import { Manual } from '../pages/Manual';
import { renderWithProviders } from './fixtures';

const users = {
  viewer: { id: 'u1', username: 'viewer', role: 'viewer', is_active: true },
  analyst: { id: 'u2', username: 'analyst', role: 'analyst', is_active: true },
  admin: { id: 'u3', username: 'admin', role: 'admin', is_active: true },
} as const;
const job = (state: string, result: Record<string, unknown> | null = null, error: Record<string, unknown> | null = null) => ({
  schema_version: '1.0', job_id: 'job-manual-1234', command_id: 'cmd-manual-1234', state,
  created_at: '2026-09-06T00:00:00Z', updated_at: '2026-09-06T00:00:01Z', progress: {}, result, error,
});
const response = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);

function mockRole(role: keyof typeof users, handler?: (path: string, init?: RequestInit) => Promise<Response>) {
  sessionStorage.setItem('cti_access_token', 'token');
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const path = String(input);
    if (path.endsWith('/auth/me')) return response(users[role]);
    return handler ? handler(path, init) : response(job('completed'));
  });
}

beforeEach(() => { sessionStorage.clear(); clearToken(); vi.restoreAllMocks(); });
afterEach(() => cleanup());

describe('manual URL workflow', () => {
  it('hides and blocks the operation for viewers, while analyst and admin can use it', async () => {
    mockRole('viewer'); renderWithProviders(<Manual />, ['/manual']);
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'إدخال رابط يدوي' })).not.toBeInTheDocument());
    cleanup();
    mockRole('analyst'); renderWithProviders(<Manual />, ['/manual']);
    expect(await screen.findByRole('button', { name: 'تسجيل الرابط وتشغيله' })).toBeInTheDocument();
    cleanup();
    mockRole('admin'); renderWithProviders(<Manual />, ['/manual']);
    expect(await screen.findByRole('button', { name: 'تسجيل الرابط وتشغيله' })).toBeInTheDocument();
  });

  it('requires a valid HTTP(S) URL and explicit confirmation', async () => {
    const fetchMock = mockRole('analyst');
    renderWithProviders(<Manual />);
    const actor = userEvent.setup();
    const input = await screen.findByRole('textbox', { name: 'رابط HTTP أو HTTPS' });
    await actor.type(input, 'ftp://example.org/report');
    await actor.click(screen.getByRole('button', { name: 'تسجيل الرابط وتشغيله' }));
    expect(screen.getByRole('alert')).toHaveTextContent('HTTP أو HTTPS');
    expect(fetchMock.mock.calls.some(([value]) => String(value).endsWith('/manual-sources'))).toBe(false);
    await actor.clear(input); await actor.type(input, 'https://example.org/report');
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    await actor.click(screen.getByRole('button', { name: 'تسجيل الرابط وتشغيله' }));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('ليست معاينة'));
    expect(fetchMock.mock.calls.some(([value]) => String(value).endsWith('/manual-sources'))).toBe(false);
  });

  it('posts the exact contract once, prevents duplicates, and follows the returned job', async () => {
    let resolveStart!: (value: Response) => void;
    const pending = new Promise<Response>((resolve) => { resolveStart = resolve; });
    const fetchMock = mockRole('analyst', (path) => path.endsWith('/manual-sources') ? pending : response(job('completed', { accepted_records: 2, review_records: 1, rejected_records: 0, skipped_records: 3, error_count: 0 })));
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<Manual />);
    const actor = userEvent.setup();
    await actor.type(await screen.findByRole('textbox', { name: 'رابط HTTP أو HTTPS' }), 'https://example.org/report?token=hidden');
    const button = screen.getByRole('button', { name: 'تسجيل الرابط وتشغيله' });
    await actor.click(button); expect(button).toBeDisabled(); button.click();
    const posts = fetchMock.mock.calls.filter(([value]) => String(value).endsWith('/manual-sources'));
    expect(posts).toHaveLength(1);
    expect(posts[0][1]).toMatchObject({ method: 'POST', body: JSON.stringify({ url: 'https://example.org/report?token=hidden', force: false }) });
    resolveStart(await response(job('queued')));
    expect(await screen.findByText(/مكتملة/)).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('token=hidden');
  });

  it('shows safe submission failures and rejects malformed responses', async () => {
    mockRole('analyst', (path) => path.endsWith('/manual-sources') ? response({ detail: 'private http://internal.local token=secret' }, 500) : response(job('failed')));
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<Manual />);
    const actor = userEvent.setup();
    await actor.type(await screen.findByRole('textbox', { name: 'رابط HTTP أو HTTPS' }), 'https://example.org/report');
    await actor.click(screen.getByRole('button', { name: 'تسجيل الرابط وتشغيله' }));
    expect(await screen.findByText('لم تقبل الخدمة طلب الإرسال.')).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('internal.local');
    cleanup();
    mockRole('analyst', (path) => path.endsWith('/manual-sources') ? response({ job_id: 'short', state: 'unknown' }) : response(job('failed')));
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<Manual />);
    await actor.type(await screen.findByRole('textbox', { name: 'رابط HTTP أو HTTPS' }), 'https://example.org/report');
    await actor.click(screen.getByRole('button', { name: 'تسجيل الرابط وتشغيله' }));
    expect(await screen.findByText('لم تقبل الخدمة طلب الإرسال.')).toBeInTheDocument();
  });
});
