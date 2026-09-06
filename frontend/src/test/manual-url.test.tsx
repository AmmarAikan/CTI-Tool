import { cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearToken } from '../api/client';
import { Manual } from '../pages/Manual';
import { renderWithProviders } from './fixtures';

const users = { viewer: { id: 'u1', username: 'viewer', role: 'viewer', is_active: true }, analyst: { id: 'u2', username: 'analyst', role: 'analyst', is_active: true }, admin: { id: 'u3', username: 'admin', role: 'admin', is_active: true } } as const;
const preview = { schema_version: '1.0', preview_id: 'prv-12345678901234567890', state: 'pending', created_at: '2026-09-06T00:00:00Z', expires_at: '2099-09-06T00:15:00Z', display_url: 'https://example.org/report', page_type: 'article', title: 'تقرير تهديد منقّى', excerpt: 'مقتطف قصير خالٍ من البيانات الحساسة.', disposition: 'accepted', classification_label: 'cti_related', classification_confidence: .91, privacy_status: 'reviewed', review_reasons: [], content_sha256: 'sha256:' + 'a'.repeat(64), items_preview: [{ item_index: 1, title: 'المقال الأول', excerpt: 'ملخص آمن', page_type: 'article', disposition: 'accepted', classification_label: 'cti_related', classification_confidence: .91, privacy_status: 'reviewed', review_reasons: [], content_sha256: 'sha256:' + 'b'.repeat(64) }], items_preview_total: 1, items_preview_truncated: false, counts: { items: 1, accepted: 1, review: 0, rejected: 0, skipped: 0, errors: 0 } };
const job = (state: string) => ({ schema_version: '1.0', job_id: 'job-manual-1234', command_id: 'cmd-manual-1234', state, created_at: '2026-09-06T00:00:00Z', updated_at: '2026-09-06T00:00:01Z', progress: {}, result: state === 'completed' ? { accepted_records: 1 } : null, error: null });
const response = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
function mockRole(role: keyof typeof users, handler?: (path: string, init?: RequestInit) => Promise<Response>) {
  sessionStorage.setItem('cti_access_token', 'token');
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => String(input).endsWith('/auth/me') ? response(users[role]) : handler ? handler(String(input), init) : response(preview));
}
beforeEach(() => { sessionStorage.clear(); clearToken(); vi.restoreAllMocks(); vi.stubGlobal('crypto', { randomUUID: () => 'idem-1234567890' }); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('manual preview workflow', () => {
  it('denies viewers and allows analyst/admin', async () => {
    mockRole('viewer'); renderWithProviders(<Manual />, ['/manual']); await waitFor(() => expect(screen.queryByRole('heading', { name: 'معاينة رابط يدوي' })).not.toBeInTheDocument()); cleanup();
    mockRole('analyst'); renderWithProviders(<Manual />); expect(await screen.findByRole('button', { name: 'معاينة الرابط' })).toBeInTheDocument(); cleanup();
    mockRole('admin'); renderWithProviders(<Manual />); expect(await screen.findByRole('button', { name: 'معاينة الرابط' })).toBeInTheDocument();
  });

  it('creates one preview, renders only sanitized fields, and prevents duplicates', async () => {
    let resolve!: (value: Response) => void; const pending = new Promise<Response>((done) => { resolve = done; });
    const fetchMock = mockRole('analyst', (path) => path.endsWith('/previews') ? pending : response(job('completed')));
    renderWithProviders(<Manual />); const actor = userEvent.setup();
    await actor.type(await screen.findByRole('textbox'), 'https://example.org/report?token=hidden');
    const button = screen.getByRole('button', { name: 'معاينة الرابط' }); await actor.click(button); expect(button).toBeDisabled(); button.click();
    const calls = fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/previews')); expect(calls).toHaveLength(1);
    expect(calls[0][1]).toMatchObject({ method: 'POST', body: JSON.stringify({ url: 'https://example.org/report?token=hidden' }) });
    resolve(await response(preview)); expect(await screen.findByText(preview.title)).toBeInTheDocument();
    expect(screen.getByText(preview.items_preview[0].excerpt)).toBeInTheDocument(); expect(document.body).not.toHaveTextContent('token=hidden');
  });

  it('requires approval confirmation and follows the approval job', async () => {
    const fetchMock = mockRole('analyst', (path) => path.endsWith('/previews') ? response(preview) : path.endsWith('/approve') ? response(job('queued')) : response(job('completed')));
    renderWithProviders(<Manual />); const actor = userEvent.setup(); await actor.type(await screen.findByRole('textbox'), 'https://example.org/report'); await actor.click(screen.getByRole('button', { name: 'معاينة الرابط' }));
    vi.spyOn(window, 'confirm').mockReturnValue(false); await actor.click(await screen.findByRole('button', { name: 'اعتماد وحفظ' })); expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith('/approve'))).toBe(false);
    vi.mocked(window.confirm).mockReturnValue(true); await actor.click(screen.getByRole('button', { name: 'اعتماد وحفظ' }));
    expect(await screen.findByText(/مكتملة/)).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/approve')); expect(call?.[1]).toMatchObject({ method: 'POST', body: JSON.stringify({ expected_content_sha256: preview.content_sha256 }) });
  });

  it('renders twenty listing items, reports truncation, and approves the complete preview hash', async () => {
    const items = Array.from({ length: 20 }, (_, index) => ({
      ...preview.items_preview[0], item_index: index + 1, title: `مقال آمن ${index + 1}`,
      content_sha256: 'sha256:' + (index % 10).toString().repeat(64),
    }));
    const listing = { ...preview, page_type: 'listing', items_preview: items, items_preview_total: 24,
      items_preview_truncated: true, counts: { ...preview.counts, items: 24, accepted: 24 } };
    const fetchMock = mockRole('analyst', (path) => path.endsWith('/previews') ? response(listing)
      : path.endsWith('/approve') ? response(job('queued')) : response(job('completed')));
    renderWithProviders(<Manual />); const actor = userEvent.setup();
    await actor.type(await screen.findByRole('textbox'), 'https://example.org/listing');
    await actor.click(screen.getByRole('button', { name: 'معاينة الرابط' }));
    expect(await screen.findAllByRole('listitem')).toHaveLength(20);
    expect(screen.getByText('عرض 20 من 24')).toBeInTheDocument();
    expect(screen.getByText(/كامل المعاينة المجمدة/)).toBeInTheDocument();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await actor.click(screen.getByRole('button', { name: 'اعتماد وحفظ' }));
    const call = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/approve'));
    expect(call?.[1]).toMatchObject({ body: JSON.stringify({ expected_content_sha256: preview.content_sha256 }) });
  });

  it('rejects with a controlled reason and removes preview content', async () => {
    mockRole('analyst', (path) => path.endsWith('/previews') ? response(preview) : response({ schema_version: '1.0', preview_id: preview.preview_id, state: 'rejected', decided_at: '2026-09-06T00:01:00Z' }));
    renderWithProviders(<Manual />); const actor = userEvent.setup(); await actor.type(await screen.findByRole('textbox'), 'https://example.org/report'); await actor.click(screen.getByRole('button', { name: 'معاينة الرابط' }));
    await actor.selectOptions(await screen.findByRole('combobox'), 'duplicate'); await actor.click(screen.getByRole('button', { name: 'تجاهل' }));
    expect(await screen.findByText(/تم تجاهل المعاينة/)).toBeInTheDocument(); expect(screen.queryByText(preview.title)).not.toBeInTheDocument(); expect(screen.queryByText(preview.excerpt)).not.toBeInTheDocument();
  });

  it('handles expiry, disconnected service, malformed responses, and 401 safely', async () => {
    for (const [body, status, expected] of [[{ code: 'preview_expired', message: 'raw secret' }, 410, 'انتهت صلاحية'], [{}, 200, 'استجابة غير صالحة']] as const) {
      mockRole('analyst', () => response(body, status)); renderWithProviders(<Manual />); const actor = userEvent.setup(); await actor.type(await screen.findByRole('textbox'), 'https://example.org/report'); await actor.click(screen.getByRole('button', { name: 'معاينة الرابط' })); expect(await screen.findByText(new RegExp(expected))).toBeInTheDocument(); cleanup(); vi.restoreAllMocks();
    }
    mockRole('analyst', () => Promise.reject(new TypeError('offline'))); renderWithProviders(<Manual />); const actor = userEvent.setup(); await actor.type(await screen.findByRole('textbox'), 'https://example.org/report'); await actor.click(screen.getByRole('button', { name: 'معاينة الرابط' })); expect(await screen.findByText(/غير متصلة/)).toBeInTheDocument(); cleanup(); vi.restoreAllMocks();
    mockRole('analyst', () => response({ detail: 'expired' }, 401)); renderWithProviders(<Manual />); await actor.type(await screen.findByRole('textbox'), 'https://example.org/report'); await actor.click(screen.getByRole('button', { name: 'معاينة الرابط' })); await waitFor(() => expect(sessionStorage.getItem('cti_access_token')).toBeNull());
  });
});
