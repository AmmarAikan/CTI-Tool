import { cleanup, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Dashboard } from '../pages/Dashboard';
import { api, clearToken } from '../api/client';
import { renderWithProviders } from './fixtures';

const json = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);
const health = { configured: true, reachable: true, service: 'external-sources', api_version: 'v1' };
const summary = { events: 12, indicators: 34, observables: 34, correlations: 5, sessions: 8, outliers: 2, by_severity: { high: 3 }, by_pipeline: { external: 12 } };
const recentEvent = {
  id: 'event-1',
  title: 'External source event',
  summary: 'A verified recent event summary.',
  source_type: 'rss',
  source_pipeline: 'external',
  category: 'vulnerability',
  severity: 'high',
  risk_score: 82,
  confidence: 0.91,
  processing_status: 'completed',
  first_seen: '2026-09-14T10:00:00Z',
  last_seen: '2026-09-14T10:10:00Z',
  created_at: '2026-09-14T10:11:00Z',
  indicator_count: 2,
  entity_count: 3,
};
const recentEvents = { items: [recentEvent], total: 1, limit: 5, offset: 0 };
const emptyEvents = { items: [], total: 0, limit: 5, offset: 0 };
const dashboardResponse = (input: RequestInfo | URL, dashboard: unknown = summary, events: unknown = recentEvents) => {
  const path = String(input);
  if (path.endsWith('/dashboard/summary')) return json(dashboard);
  if (path.includes('/intelligence/events?')) return json(events);
  return json(health);
};

beforeEach(() => { clearToken(); vi.restoreAllMocks(); });
afterEach(cleanup);

describe('dashboard summary', () => {
  it('uses the same-origin endpoint and strictly validates the live fields', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(summary));
    await expect(api.dashboardSummary()).resolves.toEqual(summary);
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/dashboard/summary', expect.any(Object));
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ ...summary, events: -1 }));
    await expect(api.dashboardSummary()).rejects.toMatchObject({ status: 502, code: 'invalid_response' });
  });

  it('renders confirmed statistics while preserving external health', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => dashboardResponse(input));
    renderWithProviders(<Dashboard />);
    await waitFor(() => expect(screen.getByText('متاحة')).toBeInTheDocument());
    expect(screen.getByText('أحداث التهديدات')).toBeInTheDocument();
    for (const value of ['12', '34', '5', '8', '2']) expect(screen.getByText(value)).toBeInTheDocument();
    expect(screen.queryByText('تشغيلات المعالجة')).not.toBeInTheDocument();
    expect(await screen.findByText('External source event')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /External source event/ })).toHaveAttribute('href', '/intelligence/events/event-1');
    expect(screen.getByRole('link', { name: 'المصادر' })).toHaveAttribute('href', '/external-sources');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/intelligence/events?limit=5&offset=0', expect.any(Object));
  });

  it('renders loading and empty states', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(() => undefined));
    renderWithProviders(<Dashboard />);
    expect(screen.getAllByText('جار تحميل إحصاءات المنصة...')).toHaveLength(2);
    cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => dashboardResponse(input, { ...summary, events: 0, indicators: 0, observables: 0, correlations: 0, sessions: 0, outliers: 0 }, emptyEvents));
    renderWithProviders(<Dashboard />);
    await waitFor(() => expect(screen.getByText('لا توجد بيانات إحصائية مسجلة حاليًا.')).toBeInTheDocument());
    expect(screen.getByText('لا توجد أحداث')).toBeInTheDocument();
  });

  it('renders invalid-response and disconnected states with retry', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => dashboardResponse(input, { ...summary, correlations: 1.5 }, emptyEvents));
    renderWithProviders(<Dashboard />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('تعذر تحميل البيانات'));
    cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/dashboard/summary') ? Promise.reject(new TypeError('offline')) : dashboardResponse(input, summary, emptyEvents));
    renderWithProviders(<Dashboard />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('الخدمة المركزية غير متصلة'));
    expect(screen.getByRole('button', { name: 'إعادة المحاولة' })).toBeInTheDocument();
  });
});
