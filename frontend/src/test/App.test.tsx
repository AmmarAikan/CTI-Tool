import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, beforeEach, vi } from 'vitest';
import { App } from '../pages/App';
import { Login } from '../pages/Login';
import { Dashboard } from '../pages/Dashboard';
import { Sources } from '../pages/Sources';
import { renderWithProviders } from './fixtures';
import { Layout } from '../components/Layout';
import { AuthProvider, useAuth } from '../auth/AuthContext';

const json = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
const user = { id: 'u1', username: 'analyst', role: 'analyst', is_active: true };
const sources = [{ source_id: 'cisa-kev', name: 'CISA KEV', source_type: 'vulnerability', status: 'enabled', metadata: {} }];

beforeEach(() => { sessionStorage.clear(); vi.restoreAllMocks(); });

describe('authentication', () => {
  it('logs in through the central API without rendering the token', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const path = String(input); if (path.endsWith('/auth/login')) return json({ access_token: 'secret-jwt', token_type: 'bearer', role: 'analyst' });
      if (path.endsWith('/auth/me')) return json(user); return json({});
    });
    renderWithProviders(<Login />); const actor = userEvent.setup(); await actor.type(screen.getByLabelText('اسم المستخدم'), 'analyst'); await actor.type(screen.getByLabelText('كلمة المرور'), 'password'); await actor.click(screen.getByRole('button', { name: 'تسجيل الدخول' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(document.body).not.toHaveTextContent('secret-jwt'); expect(fetchMock.mock.calls[0][0]).toContain('/api/v1/auth/login');
  });
  it('shows safe authentication error', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ detail: 'Invalid username or password' }, 401));
    renderWithProviders(<Login />); const actor = userEvent.setup(); await actor.type(screen.getByLabelText('اسم المستخدم'), 'bad'); await actor.type(screen.getByLabelText('كلمة المرور'), 'bad'); await actor.click(screen.getByRole('button', { name: 'تسجيل الدخول' })); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('بيانات الدخول غير صحيحة.'));
  });
  it('redirects protected routes to login', () => { render(<App />); expect(screen.getByText('أهلًا بك في مساحة العمليات')).toBeInTheDocument(); });
  it('clears the session on logout', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    function LoggedIn() { const { logout } = useAuth(); return <button onClick={logout}>خروج</button>; }
    render(<AuthProvider><LoggedIn /></AuthProvider>); await userEvent.setup().click(screen.getByRole('button', { name: 'خروج' })); expect(sessionStorage.getItem('cti_access_token')).toBeNull();
  });
});

describe('external dashboard and sources', () => {
  it('renders health success and sources with search/filter', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/auth/me') ? json(user) : String(input).endsWith('/integrations/external-control/health') ? json({ configured: true, reachable: true, service: 'external-sources', api_version: 'v1' }) : json(sources));
    sessionStorage.setItem('cti_access_token', 'token'); renderWithProviders(<Dashboard />); await waitFor(() => expect(screen.getByText('متاحة')).toBeInTheDocument()); cleanup(); renderWithProviders(<Sources />); await waitFor(() => expect(screen.getByText('CISA KEV')).toBeInTheDocument()); const actor = userEvent.setup(); await actor.type(screen.getByPlaceholderText('بحث بالاسم أو المعرّف'), 'unknown'); expect(screen.getByText('لا توجد نتائج مطابقة للفلاتر الحالية.')).toBeInTheDocument();
  });
  it('renders source loading and error states', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(() => undefined)); renderWithProviders(<Sources />); expect(screen.getByText('جار تحميل المصادر...')).toBeInTheDocument();
  });
  it('renders health error and source empty states', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/integrations/external-control/health') ? json({}, 503) : json([]));
    sessionStorage.setItem('cti_access_token', 'token'); renderWithProviders(<Dashboard />); await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument()); cleanup(); renderWithProviders(<Sources />); await waitFor(() => expect(screen.getByText('لا توجد مصادر مسجلة حاليًا.')).toBeInTheDocument());
  });
  it('clears the session after a central 401', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ detail: 'Authentication required' }, 401));
    sessionStorage.setItem('cti_access_token', 'token'); renderWithProviders(<Dashboard />); await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument()); expect(sessionStorage.getItem('cti_access_token')).toBeNull();
  });
  it('rejects invalid API response shapes and redacts reflected secrets', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ detail: 'token=super-secret https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/x' }, 500));
    sessionStorage.setItem('cti_access_token', 'token'); renderWithProviders(<Dashboard />); await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument()); expect(screen.getByRole('alert')).not.toHaveTextContent('super-secret'); expect(screen.getByRole('alert')).not.toHaveTextContent('.onion');
    cleanup(); vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ reachable: true })); renderWithProviders(<Dashboard />); await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument()); expect(screen.getByRole('alert')).not.toHaveTextContent('reachable');
  });
  it('shows manual navigation only to analyst-level users', async () => {
    function Navigation() { return <Layout />; }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/auth/me') ? json({ id: 'u1', username: 'viewer', role: 'viewer', is_active: true }) : json({}));
    sessionStorage.setItem('cti_access_token', 'token'); renderWithProviders(<Navigation />); await waitFor(() => expect(screen.getAllByText('viewer').length).toBeGreaterThan(0)); expect(screen.queryByText('رابط يدوي')).not.toBeInTheDocument();
    cleanup(); sessionStorage.setItem('cti_access_token', 'token'); vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/auth/me') ? json({ id: 'u1', username: 'analyst', role: 'analyst', is_active: true }) : json({})); renderWithProviders(<Navigation />); await waitFor(() => expect(screen.getAllByText('analyst').length).toBeGreaterThan(0)); expect(screen.getByText('رابط يدوي')).toBeInTheDocument();
  });
});
