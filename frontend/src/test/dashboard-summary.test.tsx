import { cleanup, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Dashboard } from '../pages/Dashboard';
import { api, clearToken } from '../api/client';
import { renderWithProviders } from './fixtures';

const json = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);
const health = { configured: true, reachable: true, service: 'external-sources', api_version: 'v1' };
const summary = { events: 12, indicators: 34, observables: 34, correlations: 5, sessions: 8, outliers: 2, by_severity: { high: 3 }, by_pipeline: { external: 12 } };

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
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/dashboard/summary') ? json(summary) : json(health));
    renderWithProviders(<Dashboard />);
    await waitFor(() => expect(screen.getByText('متاحة')).toBeInTheDocument());
    expect(screen.getByText('أحداث التهديدات')).toBeInTheDocument();
    for (const value of ['12', '34', '5', '8', '2']) expect(screen.getByText(value)).toBeInTheDocument();
    expect(screen.queryByText('تشغيلات المعالجة')).not.toBeInTheDocument();
  });

  it('renders loading and empty states', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(() => undefined));
    renderWithProviders(<Dashboard />);
    expect(screen.getByText('جار تحميل إحصاءات المنصة...')).toBeInTheDocument();
    cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/dashboard/summary') ? json({ ...summary, events: 0, indicators: 0, observables: 0, correlations: 0, sessions: 0, outliers: 0 }) : json(health));
    renderWithProviders(<Dashboard />);
    await waitFor(() => expect(screen.getByText('لا توجد بيانات إحصائية مسجلة حاليًا.')).toBeInTheDocument());
  });

  it('renders invalid-response and disconnected states with retry', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/dashboard/summary') ? json({ ...summary, correlations: 1.5 }) : json(health));
    renderWithProviders(<Dashboard />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('تعذر تحميل البيانات'));
    cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/dashboard/summary') ? Promise.reject(new TypeError('offline')) : json(health));
    renderWithProviders(<Dashboard />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('الخدمة المركزية غير متصلة'));
    expect(screen.getByRole('button', { name: 'إعادة المحاولة' })).toBeInTheDocument();
  });
});
