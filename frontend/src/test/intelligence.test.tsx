import { cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { AnalysisPage, CorrelationsPage, EventsPage, IndicatorsPage, MISPPage, OutliersPage } from '../pages/Intelligence';
import { renderWithProviders } from './fixtures';

const json = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
const event = { id: 'cti-1', title: 'CVE campaign', summary: 'Safe CTI summary', source_type: 'feed', source_pipeline: 'external', category: 'cti_related', severity: 'high', risk_score: 8, confidence: .9, processing_status: 'transformed', first_seen: '2026-09-07T10:00:00Z', last_seen: null, created_at: '2026-09-07T10:00:00Z', indicator_count: 1, entity_count: 1 };
const page = <T,>(items: T[]) => ({ items, total: items.length, limit: 20, offset: 0 });

beforeEach(() => { sessionStorage.clear(); vi.restoreAllMocks(); });
afterEach(cleanup);

describe('threat intelligence pages', () => {
  it('renders event filters/list and rejects unknown sensitive fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([event])));
    renderWithProviders(<EventsPage />);
    await waitFor(() => expect(screen.getByText('CVE campaign')).toBeInTheDocument());
    expect(screen.getByText('Safe CTI summary')).toBeInTheDocument();
    expect(screen.getByLabelText('الشدة')).toBeInTheDocument();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([{ ...event, raw_reference: { token: 'secret' } }])));
    await expect(api.intelligenceEvents()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('masks sensitive indicator values while retaining an accessible copy action', async () => {
    const indicator = { id: 'i-1', event_id: 'cti-1', type: 'ipv4', value: '203.0.113.7', confidence: .8, source_pipeline: 'external', severity: 'high', first_seen: null, last_seen: null };
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([indicator])));
    renderWithProviders(<IndicatorsPage />);
    await waitFor(() => expect(screen.getByText('••••••••')).toBeInTheDocument());
    expect(document.body).not.toHaveTextContent('203.0.113.7');
    expect(screen.getByRole('button', { name: 'نسخ' })).toBeInTheDocument();
  });

  it('renders correlations and outliers without arbitrary evidence, features, or IPs', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([{ id: 'c-1', source_event_id: 'cti-1', target_event_id: 'cti-2', type: 'text_similarity', score: .7, reason: 'similar_text' }])));
    renderWithProviders(<CorrelationsPage />);
    await waitFor(() => expect(screen.getByText('similar_text')).toBeInTheDocument());
    cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([{ id: 'o-1', event_id: null, started_at: '2026-09-07T10:00:00Z', ended_at: '2026-09-07T10:02:00Z', alert_count: 3, is_outlier: true, anomaly_score: .8, detector: 'isolation_forest' }])));
    renderWithProviders(<OutliersPage />);
    await waitFor(() => expect(screen.getByText('شاذ')).toBeInTheDocument());
    expect(document.body).not.toHaveTextContent('source_ip');
    expect(document.body).not.toHaveTextContent('features');
  });
});

describe('analysis and MISP', () => {
  it('states the real in-process execution model and renders safe runs', async () => {
    const ml = { execution_model: 'central_backend', backend: 'transformer', primary_model: 'dnrti_bert_ner', secondary_model: 'dnrti_sklearn_ner', primary_loaded: true, secondary_loaded: false, quality_gates_passed: true, held_out_f1: .8 };
    const run = { id: '12345678-1234-1234-1234-123456789012', pipeline: 'external', status: 'completed', collected: 2, processed: 2, stored: 2, failed: 0, error_category: null, started_at: '2026-09-07T10:00:00Z', completed_at: '2026-09-07T10:00:02Z', duration_seconds: 2 };
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/ml/status') ? json(ml) : json(page([run])));
    renderWithProviders(<AnalysisPage />);
    await waitFor(() => expect(screen.getByText('transformer')).toBeInTheDocument());
    expect(screen.getByText(/داخل Central Backend مباشرة/)).toBeInTheDocument();
    expect(screen.queryByText(/worker|heartbeat|queue/i)).not.toBeInTheDocument();
  });

  it('keeps viewers read-only on MISP', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => { const path = String(input); if (path.endsWith('/auth/me')) return json({ id: 'u1', username: 'viewer', role: 'viewer', is_active: true }); if (path.endsWith('/misp/health')) return json({ configured: true, reachable: true }); return json({ ...page([event]), limit: 50 }); });
    renderWithProviders(<MISPPage />);
    await waitFor(() => expect(screen.getByText('متصل')).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'إرسال إلى MISP' })).not.toBeInTheDocument();
  });

  it('requires confirmation and prevents duplicate admin MISP sends', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    let resolveSend: ((response: Response) => void) | undefined;
    const pending = new Promise<Response>((resolve) => { resolveSend = resolve; });
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, options) => { const path = String(input); if (path.endsWith('/auth/me')) return json({ id: 'a1', username: 'admin', role: 'admin', is_active: true }); if (path.endsWith('/misp/health')) return json({ configured: true, reachable: true }); if (path.endsWith('/misp-preview')) return json({ event_id: 'cti-1', title: 'CVE campaign', configured: true, published: false, distribution: 0, attributes: [{ type: 'vulnerability', category: 'External analysis', value: 'CVE-2026-1', to_ids: false }] }); if (options?.method === 'POST') return pending; return json({ ...page([event]), limit: 50 }); });
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<MISPPage />);
    await userEvent.setup().selectOptions(await screen.findByLabelText('الحدث'), 'cti-1');
    const send = await screen.findByRole('button', { name: 'إرسال إلى MISP' });
    await userEvent.setup().click(send);
    expect(screen.getByRole('button', { name: 'جار الإرسال...' })).toBeDisabled();
    resolveSend?.(await json({ event_id: 'cti-1', created: true, attributes_requested: 1, attributes_added: 1, attributes_verified: 1, published: false }));
    await waitFor(() => expect(screen.getByText(/اكتمل التحقق/)).toBeInTheDocument());
  });
});
