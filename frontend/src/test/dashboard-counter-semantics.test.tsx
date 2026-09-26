import { cleanup, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Dashboard } from '../pages/Dashboard';
import { renderWithProviders } from './fixtures';

const response = (value: unknown) => Promise.resolve(new Response(JSON.stringify(value), {
  status: 200,
  headers: { 'Content-Type': 'application/json' },
}));

afterEach(() => { cleanup(); sessionStorage.clear(); vi.restoreAllMocks(); });

describe('Overview counter semantics', () => {
  it('labels all persisted IOC records separately from explicitly assessed indicators', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const path = String(input);
      if (path.endsWith('/auth/me')) return response({ id: 'user', username: 'analyst', role: 'analyst', is_active: true });
      if (path.endsWith('/health')) return response({ status: 'ok', database: true });
      if (path.endsWith('/dashboard/summary')) return response({ events: 2, indicators: 1, observables: 4,
        correlations: 0, sessions: 0, outliers: 0, by_severity: {}, by_pipeline: { external: 2 } });
      if (path.endsWith('/integrations/status')) return response({ external_feed: { configured: true },
        external_control_api: { configured: true }, misp: { configured: false },
        internal: { dionaea: { configured: false }, 'host-auth': { configured: false }, 'web-access': { configured: false } } });
      return response({ configured: true, reachable: true, service: 'safe' });
    });
    renderWithProviders(<Dashboard />);
    expect(await screen.findByText('كل القيم المرصودة')).toBeInTheDocument();
    expect(screen.getByText('المؤشرات المُقيّمة')).toBeInTheDocument();
    expect(screen.getByText(/كل قيم IOC المستخرجة والمحفوظة/)).toBeInTheDocument();
    const observables = screen.getByText('كل القيم المرصودة').closest('article');
    const assessed = screen.getByText('المؤشرات المُقيّمة').closest('article');
    expect(observables).toHaveTextContent('4');
    expect(assessed).toHaveTextContent('1');
  });
});
