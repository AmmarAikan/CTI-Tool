import { cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api, clearToken } from '../api/client';
import { IntelligenceSearchPage } from '../pages/IntelligenceSearch';
import { renderWithProviders } from './fixtures';

const json = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
const result = (overrides: Record<string, unknown> = {}) => ({
  kind: 'event',
  id: 'search-event',
  label: 'Needle Operation',
  context: 'Safe investigation context.',
  match_field: 'title',
  match_quality: 'prefix',
  source_pipeline: 'external',
  source_type: 'research',
  source_id: 'search-source',
  source_name: 'Needle Intelligence Feed',
  event_id: 'search-event',
  related_event_id: null,
  severity: 'high',
  confidence: 0.9,
  created_at: '2026-09-15T10:00:00Z',
  ...overrides,
});
const payload = {
  query: 'needle',
  items: [
    result(),
    result({
      kind: 'source', id: 'search-source', label: 'Needle Intelligence Feed',
      context: 'research', match_field: 'name', event_id: null, severity: null,
      confidence: null,
    }),
    result({
      kind: 'correlation', id: 'correlation-1', label: 'cross_source',
      context: 'Shared needle evidence', match_field: 'reason', match_quality: 'contains',
      source_pipeline: null, source_type: null, source_id: null, source_name: null,
      event_id: 'search-event', related_event_id: 'search-related-event', severity: null,
      confidence: 0.92,
    }),
  ],
  returned: 3,
  limit_per_type: 5,
  truncated: false,
};

beforeEach(() => { clearToken(); sessionStorage.clear(); vi.restoreAllMocks(); });
afterEach(cleanup);

describe('global intelligence search', () => {
  it('strictly validates the response identity and rejects unsafe shape drift', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(payload));
    await expect(api.intelligenceSearch(' needle ', 5)).resolves.toMatchObject({ query: 'needle', returned: 3 });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/intelligence/search?q=needle&limit_per_type=5', expect.any(Object));

    fetchMock.mockImplementation(() => json({ ...payload, returned: 4 }));
    await expect(api.intelligenceSearch('needle', 5)).rejects.toMatchObject({ code: 'invalid_response' });
    fetchMock.mockImplementation(() => json({ ...payload, items: [{ ...payload.items[0], raw_reference: { secret: true } }], returned: 1 }));
    await expect(api.intelligenceSearch('needle', 5)).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('submits one bounded search and pivots to existing ACTIT records', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(payload));
    renderWithProviders(<Routes><Route path="/intelligence/search" element={<IntelligenceSearchPage />} /></Routes>, ['/intelligence/search']);
    expect(screen.getByText('نطاق البحث الآمن')).toBeInTheDocument();
    const actor = userEvent.setup();
    await actor.type(screen.getByLabelText('ابحث في كل الاستخبارات'), 'needle');
    await actor.click(screen.getByRole('button', { name: 'ابدأ التحقيق' }));

    expect(await screen.findByText('Needle Operation')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /needle/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Needle Operation' })).toHaveAttribute('href', '/intelligence/events/search-event');
    expect(screen.getByRole('link', { name: 'Needle Intelligence Feed' })).toHaveAttribute('href', '/external-sources');
    expect(screen.getByRole('link', { name: 'الحدث المرتبط' })).toHaveAttribute('href', '/intelligence/events/search-related-event');
    expect(document.body).not.toHaveTextContent('raw_reference');
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  });

  it('does not call the API for an invalid query', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(payload));
    renderWithProviders(<IntelligenceSearchPage />);
    const actor = userEvent.setup();
    await actor.type(screen.getByLabelText('ابحث في كل الاستخبارات'), 'x');
    await actor.click(screen.getByRole('button', { name: 'ابدأ التحقيق' }));
    expect(screen.getByRole('alert')).toHaveTextContent('اكتب حرفين على الأقل');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('shows a trustworthy empty state for a completed search', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ query: 'unknown', items: [], returned: 0, limit_per_type: 5, truncated: false }));
    renderWithProviders(<Routes><Route path="/intelligence/search" element={<IntelligenceSearchPage />} /></Routes>, ['/intelligence/search?q=unknown']);
    expect(await screen.findByText('لا توجد سجلات استخبارات مطابقة.')).toBeInTheDocument();
  });
});
