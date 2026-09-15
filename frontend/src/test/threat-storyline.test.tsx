import { cleanup, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { ThreatStorylinePage } from '../pages/ThreatStoryline';
import { renderWithProviders } from './fixtures';

const json = (body: unknown, status = 200) => Promise.resolve({
  ok: status < 400,
  status,
  json: () => Promise.resolve(body),
} as Response);

const event = {
  id: 'cti-1',
  title: 'PowerShell campaign T1059.001',
  summary: 'Safe external campaign summary.',
  source_type: 'research',
  source_pipeline: 'external',
  category: 'cti_related',
  severity: 'high',
  risk_score: 78,
  confidence: .9,
  processing_status: 'transformed',
  first_seen: '2026-09-07T09:55:00Z',
  last_seen: '2026-09-07T10:05:00Z',
  created_at: '2026-09-07T10:00:00Z',
  indicator_count: 1,
  entity_count: 1,
};

const correlation = {
  id: '50000000-0000-0000-0000-000000000004',
  source_event_id: 'cti-1',
  target_event_id: 'cti-2',
  type: 'simple_indicator_match',
  score: 1,
  reason: 'same_domain',
  source_event: {
    event_id: 'cti-1',
    title: 'PowerShell campaign T1059.001',
    source_pipeline: 'external',
    source_type: 'research',
    source_id: 'source-1',
    source_name: 'Research Feed',
    severity: 'high',
    risk_score: 78,
    created_at: '2026-09-07T10:00:00Z',
  },
  target_event: {
    event_id: 'cti-2',
    title: 'Internal honeypot event',
    source_pipeline: 'internal',
    source_type: 'honeypot',
    source_id: 'source-2',
    source_name: 'Internal Honeypot',
    severity: 'medium',
    risk_score: 62,
    created_at: '2026-09-07T10:05:00Z',
  },
  cross_source: true,
  score_basis: 'exact_observable_match',
  evidence_status: 'available',
  factors: [{ kind: 'shared_observable', label: 'domain', value: 'command.example' }],
  created_at: '2026-09-07T10:05:00Z',
};

const storyline = {
  event,
  source_name: 'Research Feed',
  risk_method: 'deterministic_rule_score',
  risk_factors: [
    { key: 'base_severity_or_cvss', value: 28 },
    { key: 'confidence', value: 9 },
  ],
  risk_context: { source_count: 2, correlation_count: 1 },
  evidence_counts: {
    observables: 1,
    entities: 1,
    relationships: 1,
    correlations: 1,
    attack_mappings: 1,
  },
  observables: [{
    id: '50000000-0000-0000-0000-000000000001',
    event_id: 'cti-1',
    type: 'domain',
    value: 'command.example',
    confidence: .88,
    source_pipeline: 'external',
    severity: 'high',
    first_seen: null,
    last_seen: null,
    semantic_role: 'observable',
    validation_status: 'valid',
    assessment: 'suspicious',
    assessment_confidence: .7,
    actionable: false,
    evidence_count: 1,
    evidence_providers: ['correlation'],
    reason_code: 'needs_enrichment',
  }],
  entities: [{ type: 'threat_actor', value: 'Nebula', confidence: .77 }],
  relationships: [{ subject: 'Nebula', relation: 'uses', object: 'command.example', confidence: .76 }],
  correlations: [correlation],
  attack: {
    event_id: 'cti-1',
    catalog_version: 'ATT&CK v19.1',
    source: 'built_in_subset',
    official_dataset_url: 'https://github.com/mitre-attack/attack-stix-data',
    techniques: [{
      technique_id: 'T1059.001',
      name: 'PowerShell',
      tactic: 'execution',
      confidence: .98,
      mapping_source: 'explicit_id',
      evidence: 'Explicit T1059.001 in safe external report.',
      url: 'https://attack.mitre.org/techniques/T1059/001/',
    }],
  },
  milestones: [
    {
      id: 'cti-1:observed',
      kind: 'observed',
      occurred_at: '2026-09-07T09:55:00Z',
      event_id: 'cti-1',
      related_event_id: null,
      title: 'PowerShell campaign T1059.001',
      detail: 'Safe external campaign summary.',
      source_pipeline: 'external',
      evidence_status: 'recorded',
      confidence: .9,
      score: null,
    },
    {
      id: '50000000-0000-0000-0000-000000000004',
      kind: 'correlated',
      occurred_at: '2026-09-07T10:05:00Z',
      event_id: 'cti-1',
      related_event_id: 'cti-2',
      title: 'Internal honeypot event',
      detail: 'same_domain',
      source_pipeline: 'internal',
      evidence_status: 'recorded',
      confidence: null,
      score: 1,
    },
    {
      id: 'cti-1:T1059.001',
      kind: 'attack_mapping',
      occurred_at: null,
      event_id: 'cti-1',
      related_event_id: null,
      title: 'T1059.001 - PowerShell',
      detail: 'Explicit T1059.001 in safe external report.',
      source_pipeline: 'external',
      evidence_status: 'derived',
      confidence: .98,
      score: null,
    },
  ],
  evidence_truncated: false,
  limitations: [
    'chronology_not_causality',
    'internal_raw_telemetry_hidden',
  ],
};

beforeEach(() => {
  sessionStorage.clear();
  sessionStorage.setItem('cti_language', 'en');
  vi.restoreAllMocks();
});
afterEach(cleanup);

describe('Threat Storyline', () => {
  it('renders real evidence, chronology, risk rationale, and safe pivots', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const path = String(input);
      if (path.includes('/intelligence/events?')) {
        return json({ items: [event], total: 1, limit: 20, offset: 0 });
      }
      if (path.endsWith('/intelligence/events/cti-1/storyline')) return json(storyline);
      return json({ detail: 'not found' }, 404);
    });

    renderWithProviders(
      <Routes>
        <Route path="/intelligence/storyline/:eventId" element={<ThreatStorylinePage />} />
      </Routes>,
      ['/intelligence/storyline/cti-1'],
    );

    expect(await screen.findByRole('heading', { name: 'Threat Storyline' })).toBeInTheDocument();
    expect((await screen.findAllByText('PowerShell campaign T1059.001')).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/command\.example/).length).toBeGreaterThan(0);
    expect(screen.getByText('Base severity or CVSS')).toBeInTheDocument();
    expect(screen.getAllByText('This view orders recorded evidence by time; it does not claim one event caused another.').length).toBeGreaterThan(0);
    expect(screen.getByText('Raw internal telemetry is hidden while retaining safe provenance and outcome.')).toBeInTheDocument();
    expect(screen.getByText('T1059.001 - PowerShell')).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'Internal honeypot event' }).some((item) => item.getAttribute('href') === '/intelligence/events/cti-2')).toBe(true);
    expect(document.body).not.toHaveTextContent('private sensor payload');
    expect(document.body).not.toHaveTextContent('raw_reference');
  });

  it('rejects arbitrary fields from the storyline contract', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ ...storyline, raw_reference: { secret: true } }));
    await expect(api.intelligenceStoryline('cti-1')).rejects.toMatchObject({ code: 'invalid_response' });
  });
});
