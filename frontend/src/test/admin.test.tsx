import { cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { AdminGuard, AdminPage } from '../pages/Admin';
import { renderWithProviders } from './fixtures';
import { AppErrorBoundary, NotFound } from '../components/AppErrorBoundary';

const json = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
const admin = { id: 'a1', username: 'admin', role: 'admin', is_active: true };
const viewer = { id: 'v1', username: 'viewer', role: 'viewer', is_active: true };
const analyst = { id: 'n1', username: 'analyst', role: 'analyst', is_active: true };
const managed = { id: 'u1', username: 'operator', role: 'viewer', is_active: true, created_at: '2026-09-07T10:00:00Z' };
const audit = { id: 'l1', actor: 'admin', action: 'admin_create_user', target_type: 'user', target_id: 'u1', outcome: 'success', created_at: '2026-09-07T10:01:00Z' };

beforeEach(() => { sessionStorage.clear(); vi.restoreAllMocks(); });
afterEach(cleanup);

function mockAdmin(extra?: (path: string, options?: RequestInit) => Promise<Response> | undefined) {
  sessionStorage.setItem('cti_access_token', 'token');
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, options) => {
    const path = String(input);
    const custom = extra?.(path, options); if (custom) return custom;
    if (path.endsWith('/auth/me')) return json(admin);
    if (path.includes('/admin/audit')) return json({ items: [audit], total: 1, limit: 20, offset: 0 });
    return json({ items: [managed], total: 1, limit: 20, offset: 0 });
  });
}

describe('administration frontend', () => {
  it('denies a direct viewer route without calling administration APIs', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/auth/me') ? json(viewer) : json({}));
    renderWithProviders(<AdminGuard><AdminPage /></AdminGuard>);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('الوصول غير مسموح'));
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/admin/users'))).toBe(false);
  });

  it('denies a direct analyst route without calling administration APIs', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/auth/me') ? json(analyst) : json({}));
    renderWithProviders(<AdminGuard><AdminPage /></AdminGuard>);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('الوصول غير مسموح'));
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/admin/'))).toBe(false);
  });

  it('lists users and safe audit records for administrators', async () => {
    mockAdmin(); renderWithProviders(<AdminGuard><AdminPage /></AdminGuard>);
    await waitFor(() => expect(screen.getByText('operator')).toBeInTheDocument());
    expect(screen.getByRole('cell', { name: 'إنشاء مستخدم' })).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('password_hash');
    expect(document.body).not.toHaveTextContent('details');
  });

  it('creates a user once and clears the submitted password', async () => {
    const created = { ...managed, id: 'u2', username: 'new.user', role: 'analyst' };
    const fetchMock = mockAdmin((path, options) => path.endsWith('/admin/users') && options?.method === 'POST' ? json(created, 201) : undefined);
    renderWithProviders(<AdminGuard><AdminPage /></AdminGuard>);
    await screen.findByText('operator'); const actor = userEvent.setup();
    await actor.type(screen.getByLabelText('اسم المستخدم'), 'new.user');
    const password = screen.getByLabelText('كلمة مرور المستخدم الجديد') as HTMLInputElement;
    await actor.type(password, 'SecurePassword123!');
    await actor.selectOptions(screen.getByLabelText('الدور'), 'analyst');
    await actor.click(screen.getByRole('button', { name: 'إنشاء المستخدم' }));
    await waitFor(() => expect(screen.getByText(/تم إنشاء المستخدم/)).toBeInTheDocument());
    expect(password.value).toBe('');
    expect(document.body).not.toHaveTextContent('SecurePassword123!');
    expect(fetchMock.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  });

  it('requires confirmation and blocks duplicate sensitive submissions', async () => {
    let resolveChange: ((value: Response) => void) | undefined;
    const pending = new Promise<Response>((resolve) => { resolveChange = resolve; });
    const fetchMock = mockAdmin((path, options) => path.endsWith('/active') && options?.method === 'PATCH' ? pending : undefined);
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<AdminGuard><AdminPage /></AdminGuard>);
    const disable = await screen.findByRole('button', { name: 'تعطيل' });
    await userEvent.setup().click(disable);
    expect(disable).toBeDisabled();
    expect(fetchMock.mock.calls.filter(([, options]) => options?.method === 'PATCH')).toHaveLength(1);
    resolveChange?.(await json({ ...managed, is_active: false }));
  });

  it('rejects malformed responses containing credential fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [{ ...managed, password_hash: 'secret' }], total: 1, limit: 25, offset: 0 }));
    await expect(api.adminUsers()).rejects.toMatchObject({ code: 'invalid_response' });
  });
});

describe('application fallbacks', () => {
  it('renders a global not-found destination', () => {
    renderWithProviders(<NotFound />);
    expect(screen.getByText('الصفحة غير موجودة')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'لوحة المتابعة' })).toHaveAttribute('href', '/');
  });

  it('does not disclose route exceptions in the safe fallback', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    function Broken(): never { throw new Error('token=secret http://10.0.0.8/internal'); }
    renderWithProviders(<AppErrorBoundary><Broken /></AppErrorBoundary>);
    expect(screen.getByRole('alert')).toHaveTextContent('تعذر عرض هذه الصفحة بأمان');
    expect(document.body).not.toHaveTextContent('secret');
    expect(document.body).not.toHaveTextContent('10.0.0.8');
  });
});
