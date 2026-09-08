import { cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { InternalOverview, InternalSourcePage } from '../pages/InternalSources';
import { renderWithProviders } from './fixtures';

const json = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
const health = { configured: true, reachable: true, contract_valid: true, hmac_verification: true };
const page = { items: [{ id: 'cti-safe', integration: 'dionaea', source: 'Dionaea', event_type: 'dionaea_session', category: 'cti_related', severity: 'high', summary: 'جلسة رصد من مصيدة Dionaea', first_seen: '2026-09-07T10:00:00Z', last_seen: null, created_at: '2026-09-07T10:00:00Z' }], total: 1, limit: 10, offset: 0 };

beforeEach(() => { sessionStorage.clear(); vi.restoreAllMocks(); });
afterEach(cleanup);

describe('internal sources', () => {
  it('shows all integrations and keeps viewers read-only', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/auth/me') ? json({ id: 'u1', username: 'viewer', role: 'viewer', is_active: true }) : json(health));
    renderWithProviders(<InternalOverview />);
    await waitFor(() => expect(screen.getByText('سجلات الدخول')).toBeInTheDocument());
    expect(screen.getByText('Dionaea')).toBeInTheDocument();
    expect(screen.getByText('الوصول إلى الويب')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'سحب الآن' })).not.toBeInTheDocument();
  });

  it('confirms a pull and prevents duplicate submissions while pending', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    let resolvePull: ((value: Response) => void) | undefined;
    const pullResponse = new Promise<Response>((resolve) => { resolvePull = resolve; });
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input, options) => {
      if (String(input).endsWith('/auth/me')) return json({ id: 'u1', username: 'analyst', role: 'analyst', is_active: true });
      if (options?.method === 'POST') return pullResponse;
      return json(health);
    });
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<InternalOverview />);
    const buttons = await screen.findAllByRole('button', { name: 'سحب الآن' });
    await userEvent.setup().click(buttons[0]);
    expect(screen.getByRole('button', { name: 'جار السحب...' })).toBeDisabled();
    expect(fetchMock.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    resolvePull?.(await json({ run_id: 'run-1', pipeline: 'internal', status: 'completed', collected_count: 2, processed_count: 2, stored_count: 1, failed_count: 0 }));
    await waitFor(() => expect(screen.getByText(/اكتمل التشغيل/)).toBeInTheDocument());
  });

  it('rejects private pull details instead of silently accepting them', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ run_id: 'run-1', pipeline: 'internal', status: 'completed', collected_count: 1, processed_count: 1, stored_count: 1, failed_count: 0, details: { token: 'secret' } }));
    await expect(api.pullInternal('dionaea')).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('renders a bounded safe event page and rejects unknown sensitive fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).includes('/events?') ? json(page) : json(health));
    renderWithProviders(<InternalSourcePage integration="dionaea" />);
    await waitFor(() => expect(screen.getByText('جلسة رصد من مصيدة Dionaea')).toBeInTheDocument());
    expect(document.body).not.toHaveTextContent('source_ip');
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ ...page, items: [{ ...page.items[0], raw_log: 'token=secret 10.0.0.1' }] }));
    await expect(api.internalEvents('dionaea', 10)).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it.each(['dionaea', 'host-auth', 'web-access'] as const)('uses the same-origin safe list for %s', async (integration) => {
    const empty = { items: [], total: 0, limit: 10, offset: 0 };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).includes('/events?') ? json(empty) : json({ configured: false, reachable: false }));
    renderWithProviders(<InternalSourcePage integration={integration} />);
    await waitFor(() => expect(screen.getByText('لا توجد بيانات')).toBeInTheDocument());
    expect(fetchMock.mock.calls.some(([input]) => String(input).startsWith(`/api/v1/internal/sources/${integration}/events`))).toBe(true);
  });
});
