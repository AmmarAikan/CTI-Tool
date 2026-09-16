import { cleanup, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearToken } from '../api/client';
import { SystemReadiness } from '../pages/SystemReadiness';
import { renderWithProviders } from './fixtures';

const json = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);
const summary = { events: 3, indicators: 4, observables: 4, correlations: 1, sessions: 0, outliers: 0, by_severity: {}, by_pipeline: { external: 2, internal: 1 } };

beforeEach(() => { clearToken(); vi.restoreAllMocks(); });
afterEach(cleanup);

describe('system readiness', () => {
  it('shows actual service and data evidence with honest scope limitations', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const path = String(input);
      if (path.endsWith('/api/v1/health')) return json({ status: 'ok', database: true });
      if (path.endsWith('/intelligence/ml/status')) return json({ execution_model: 'central_backend', backend: 'transformer', primary_model: 'dnrti_bert_ner', secondary_model: 'dnrti_sklearn_ner', primary_loaded: true, secondary_loaded: false, quality_gates_passed: false, held_out_f1: 0.78 });
      if (path.endsWith('/intelligence/misp/health')) return json({ configured: true, reachable: true, failure_category: null });
      if (path.endsWith('/dashboard/summary')) return json(summary);
      return json({ configured: true, reachable: true, service: 'test-service', contract_valid: true });
    });
    renderWithProviders(<SystemReadiness />);
    await waitFor(() => expect(screen.getByText('تغطية البيانات')).toBeInTheDocument());
    expect(screen.getByText('قاعدة البيانات المركزية')).toBeInTheDocument();
    expect(screen.getByText('المحرك: transformer · بوابات الجودة: متدهورة.')).toBeInTheDocument();
    expect(screen.getByText(/خارجي: 2 · داخلي: 1 · ارتباطات مخزنة: 1/)).toBeInTheDocument();
    expect(screen.getByText(/لا تثبت هذه الصفحة جاهزية المنفذ العام/)).toBeInTheDocument();
    expect(screen.getByText(/بيانات العرض الاصطناعية تبقى في قاعدة SQLite معزولة/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.every(([, init]) => !init || init.method === undefined || init.method === 'GET')).toBe(true);
  });
});
