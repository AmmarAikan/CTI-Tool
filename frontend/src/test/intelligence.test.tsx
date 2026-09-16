import { cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { AnalysisPage, AttackPage, CorrelationsPage, EventDetailPage, EventsPage, IndicatorsPage, IntelligenceOverview, MISPPage, OutliersPage } from '../pages/Intelligence';
import { renderWithProviders } from './fixtures';

const json = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
const event = { id: 'cti-1', title: 'CVE campaign', summary: 'Safe CTI summary', source_type: 'feed', source_pipeline: 'external', category: 'cti_related', severity: 'high', risk_score: 8, confidence: .9, processing_status: 'transformed', first_seen: '2026-09-07T10:00:00Z', last_seen: null, created_at: '2026-09-07T10:00:00Z', indicator_count: 1, entity_count: 1 };
const page = <T,>(items: T[]) => ({ items, total: items.length, limit: 20, offset: 0 });
const assessed = { semantic_role: 'observable', validation_status: 'valid', assessment: 'unknown', assessment_confidence: 0, actionable: false, evidence_count: 0, evidence_providers: [], reason_code: 'needs_enrichment' } as const;
const mispCandidate = { event_id: 'cti-1', title: 'CVE campaign', source_pipeline: 'external', severity: 'high', risk_score: 91, included: 1, omitted: 0, omitted_by_reason: { external_reference: 0, invalid: 0, non_actionable: 0, unsupported: 0 }, ready: true, readiness_reason: 'ready', delivery_count: 0, last_delivered_at: null, last_misp_event_id: null };

beforeEach(() => { sessionStorage.clear(); vi.restoreAllMocks(); });
afterEach(cleanup);

describe('threat intelligence pages', () => {
  it('renders the localized intelligence overview from API metrics', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ events: 2, observables: 3, indicators: 1, correlations: 0, sessions: 0, outliers: 0, by_severity: { high: 2 }, by_pipeline: { external: 2 } }));
    renderWithProviders(<IntelligenceOverview />);
    expect(await screen.findByRole('heading', { name: 'نظرة عامة' })).toBeInTheDocument();
    expect(await screen.findByText('كل القيم المرصودة')).toBeInTheDocument();
  });

  it('renders event filters/list and rejects unknown sensitive fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([event])));
    renderWithProviders(<EventsPage />);
    await waitFor(() => expect(screen.getByText('CVE campaign')).toBeInTheDocument());
    expect(screen.getByText('Safe CTI summary')).toBeInTheDocument();
    expect(screen.getByLabelText('الشدة')).toBeInTheDocument();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([{ ...event, raw_reference: { token: 'secret' } }])));
    await expect(api.intelligenceEvents()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('shows and copies complete indicator values without redaction', async () => {
    const indicator = { id: 'i-1', event_id: 'cti-1', type: 'url', value: 'https://example.org/report?id=42', confidence: .8, source_pipeline: 'external', severity: 'high', first_seen: null, last_seen: null, ...assessed };
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).includes('indicators-summary') ? json({ total: 1, by_role: { observable: 1 }, by_assessment: { unknown: 1 }, by_validation: { valid: 1 }, by_type: { url: 1 } }) : json(page([indicator])));
    renderWithProviders(<IndicatorsPage />);
    const actor = userEvent.setup();
    await waitFor(() => expect(screen.getByText(indicator.value)).toBeInTheDocument());
    expect(document.body).not.toHaveTextContent('[redacted]');
    expect(document.body).not.toHaveTextContent('••••••••');
    await actor.click(screen.getByRole('button', { name: 'نسخ' }));
    expect(await navigator.clipboard.readText()).toBe(indicator.value);
    expect(screen.getByRole('status')).toHaveTextContent('تم النسخ');
  });

  it('shows complete indicator values in event details', async () => {
    const indicator = { id: 'i-1', event_id: 'cti-1', type: 'ipv4', value: '203.0.113.7', confidence: .8, source_pipeline: 'external', severity: 'high', first_seen: null, last_seen: null, ...assessed };
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/attack') ? json({ event_id: 'cti-1', catalog_version: 'ATT&CK v19.1', source: 'built_in_subset', official_dataset_url: 'https://github.com/mitre-attack/attack-stix-data', techniques: [] }) : json({ ...event, indicators: [indicator], entities: [], relationships: [] }));
    renderWithProviders(<Routes><Route path="/intelligence/events/:eventId" element={<EventDetailPage />} /></Routes>, ['/intelligence/events/cti-1']);
    await waitFor(() => expect(screen.getByText(new RegExp(`ipv4: ${indicator.value.replaceAll('.', '\\.')}`))).toBeInTheDocument());
    expect(document.body).not.toHaveTextContent('[redacted]');
    expect(document.body).not.toHaveTextContent('••••••••');
  });

  it('renders explainable cross-source correlations and rejects arbitrary evidence', async () => {
    const correlation = {
      id: 'c-1',
      source_event_id: 'cti-1',
      target_event_id: 'cti-2',
      type: 'simple_indicator_match',
      score: 1,
      reason: 'same_domain',
      source_event: {
        event_id: 'cti-1', title: 'External campaign', source_pipeline: 'external',
        source_type: 'feed', source_id: 'source-1', source_name: 'External Feed',
        severity: 'high', risk_score: 82, created_at: '2026-09-07T10:00:00Z',
      },
      target_event: {
        event_id: 'cti-2', title: 'Internal honeypot event', source_pipeline: 'internal',
        source_type: 'honeypot', source_id: 'source-2', source_name: 'Internal Honeypot',
        severity: 'medium', risk_score: 64, created_at: '2026-09-07T10:01:00Z',
      },
      cross_source: true,
      score_basis: 'exact_observable_match',
      evidence_status: 'available',
      factors: [{ kind: 'shared_observable', label: 'domain', value: 'command.example' }],
      created_at: '2026-09-07T10:02:00Z',
    };
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([correlation])));
    renderWithProviders(<CorrelationsPage />);
    expect(await screen.findByText('تطابق قيمة مرصودة')).toBeInTheDocument();
    expect(screen.getByText('ارتباط داخلي وخارجي')).toBeInTheDocument();
    expect(screen.getByText('command.example')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'External campaign' })).toHaveAttribute('href', '/intelligence/events/cti-1');
    expect(screen.getByRole('link', { name: 'Internal honeypot event' })).toHaveAttribute('href', '/intelligence/events/cti-2');
    expect(document.body).not.toHaveTextContent('raw_reference');
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(page([{ ...correlation, evidence: { secret: true } }])));
    await expect(api.intelligenceCorrelations()).rejects.toMatchObject({ code: 'invalid_response' });
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
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => { const path = String(input); if (path.endsWith('/auth/me')) return json({ id: 'u1', username: 'viewer', role: 'viewer', is_active: true }); if (path.endsWith('/misp/health')) return json({ configured: true, reachable: true }); if (path.includes('/misp/deliveries')) return json(page([])); if (path.includes('/misp/candidates?')) return json({ ...page([mispCandidate]), configured: true }); throw new Error(`Unexpected request: ${path}`); });
    renderWithProviders(<MISPPage />);
    await waitFor(() => expect(screen.getByText('متصل')).toBeInTheDocument());
    expect(await screen.findByText('CVE campaign')).toBeInTheDocument();
    expect(screen.getByText(/معرّف MISP حتمي واحد/)).toBeInTheDocument();
    expect(screen.getByText('جاهز للمشاركة')).toBeInTheDocument();
    expect(screen.queryByLabelText('تحديد CVE campaign للمشاركة')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'إرسال الأحداث المحددة' })).not.toBeInTheDocument();
  });

  it('rejects unknown fields in MISP candidate responses', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ ...page([{ ...mispCandidate, api_key: 'secret' }]), configured: true }));
    await expect(api.mispCandidates()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('requires confirmation and prevents duplicate admin MISP sends', async () => {
    sessionStorage.setItem('cti_access_token', 'token');
    let resolveSend: ((response: Response) => void) | undefined;
    const pending = new Promise<Response>((resolve) => { resolveSend = resolve; });
    const batchRequests: RequestInit[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, options) => {
      const path = String(input);
      if (path.endsWith('/auth/me')) return json({ id: 'a1', username: 'admin', role: 'admin', is_active: true });
      if (path.endsWith('/misp/health')) return json({ configured: true, reachable: true });
      if (path.includes('/misp/deliveries')) return json(page([]));
      if (path.includes('/misp/candidates?')) return json({ ...page([mispCandidate]), configured: true });
      if (path.endsWith('/misp-preview')) return json({ event_id: 'cti-1', title: 'CVE campaign', configured: true, published: false, distribution: 0, attributes: [{ type: 'vulnerability', category: 'External analysis', value: 'CVE-2026-1', to_ids: false }], tags: ['cti-platform:external'], included: 1, omitted: 0, omitted_by_reason: { external_reference: 0, invalid: 0, non_actionable: 0, unsupported: 0 } });
      if (path.endsWith('/misp/batch') && options?.method === 'POST') { batchRequests.push(options); return pending; }
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<MISPPage />);
    const actor = userEvent.setup();
    await actor.click(await screen.findByRole('button', { name: 'مراجعة المعاينة' }));
    expect(await screen.findByText('CVE-2026-1')).toBeInTheDocument();
    await actor.click(screen.getByLabelText('تحديد CVE campaign للمشاركة'));
    const send = screen.getByRole('button', { name: 'إرسال الأحداث المحددة' });
    await actor.click(send);
    expect(screen.getByRole('button', { name: 'جار الإرسال والتحقق...' })).toBeDisabled();
    expect(batchRequests).toHaveLength(1);
    expect(JSON.parse(String(batchRequests[0].body))).toEqual({ event_ids: ['cti-1'], confirm_unpublished: true });
    resolveSend?.(await json({ batch_id: '11111111-1111-4111-8111-111111111111', requested: 1, delivered: 1, skipped: 0, failed: 0, published: 0, items: [{ event_id: 'cti-1', status: 'delivered', reason: null, created: true, attributes_requested: 1, attributes_added: 1, attributes_verified: 1, published: false, misp_event_id: '42', misp_event_uuid: '22222222-2222-4222-8222-222222222222' }] }));
    await waitFor(() => expect(screen.getByText(/تم التسليم: 1/)).toBeInTheDocument());
    expect(screen.getByRole('link', { name: 'فتح حدث MISP' })).toHaveAttribute('href', expect.stringContaining('/events/view/42'));
  });

  it('shows evidence-backed MITRE ATT&CK candidates', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/attack') ? json({ event_id: 'cti-1', catalog_version: 'ATT&CK v19.1', source: 'built_in_subset', official_dataset_url: 'https://github.com/mitre-attack/attack-stix-data', techniques: [{ technique_id: 'T1059.001', name: 'PowerShell', tactic: 'execution', confidence: .65, mapping_source: 'rule_based_candidate', evidence: 'PowerShell was used', url: 'https://attack.mitre.org/techniques/T1059/001/' }] }) : json(page([event])));
    renderWithProviders(<AttackPage />);
    await screen.findByRole('option', { name: 'CVE campaign' });
    await userEvent.setup().selectOptions(screen.getByLabelText('الحدث'), 'cti-1');
    expect(await screen.findByText(/T1059.001/)).toBeInTheDocument();
    expect(screen.getByText(/مرشح آلي للمراجعة/)).toBeInTheDocument();
  });
});
