import { cleanup, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { clearToken } from '../api/client';
import { Exports } from '../pages/Exports';
import { Reviews } from '../pages/Reviews';
import { renderWithProviders } from './fixtures';

const response = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
beforeEach(() => { sessionStorage.clear(); clearToken(); vi.restoreAllMocks(); });

describe('external reviews states', () => {
  it('accepts an empty review artifact and the confirmed no-artifact response', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-1', records: [] })); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByText('لا توجد مراجعات حتى الآن')).toBeInTheDocument()); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: { code: 'review_not_found', message: 'none' } }, 404)); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByText('لا توجد مراجعات حتى الآن')).toBeInTheDocument());
  });
  it('preserves populated rendering and rejects malformed or unrelated 404 responses', async () => {
    const record = { record_id: 'record-1', title: 'تقرير آمن', source_type: 'rss', review_reason: 'review', review_reasons: ['review'], classification_label: null, privacy_status: null, collected_at: null, published: null };
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-1', records: [record] })); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByText('تقرير آمن')).toBeInTheDocument()); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: { code: 'different_not_found', message: 'none' } }, 404)); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('تعذر تحميل البيانات')); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-1', records: [], secret: 'x' })); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
  });
  it('renders multiple real-shape records with nullable classification, RSS dates, and redacted title URLs', async () => {
    const records = [
      { record_id: 'record-rss', title: 'تنبيه عام https://public.example/advisory تفاصيل إضافية', source_type: 'rss', review_reason: 'classification_review', review_reasons: ['classification_review'], classification_label: null, privacy_status: 'reviewed', collected_at: '2026-09-09T02:01:00Z', published: 'Wed, 09 Sep 2026 02:00:02 GMT' },
      { record_id: 'record-iso', title: 'تقرير ثانٍ', source_type: 'vulnerability', review_reason: 'privacy_review', review_reasons: ['privacy_review'], classification_label: 'public', privacy_status: 'reviewed', collected_at: null, published: '2026-09-09T04:00:02+02:00' },
    ];
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-real', records })); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByText('تنبيه عام [redacted] تفاصيل إضافية')).toBeInTheDocument());
    expect(screen.getByText('تقرير ثانٍ')).toBeInTheDocument(); expect(screen.getByText('2 سجل')).toBeInTheDocument(); expect(document.body).not.toHaveTextContent('public.example');
    cleanup(); vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-real', records: [{ ...records[0], published: 'Wed, 31 Feb 2026 02:00:02 GMT' }] })); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('تعذر تحميل البيانات'));
  });
  it('distinguishes 401 and 503 states', async () => {
    sessionStorage.setItem('cti_access_token', 'token'); vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: 'expired' }, 401)); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('انتهت جلسة الدخول')); expect(sessionStorage.getItem('cti_access_token')).toBeNull(); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: { code: 'review_unavailable', message: 'unavailable' } }, 503)); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('خدمة المراجعات غير متاحة')); expect(screen.getByRole('button', { name: 'إعادة المحاولة' })).toBeInTheDocument();
  });
});

describe('external exports states', () => {
  it('accepts a populated prefixed SHA-256 and the confirmed no-export response', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-1', status: 'completed', dataset_sha256: `sha256:${'a'.repeat(64)}`, accepted_records: 2, review_records: 1, completed_at: null })); renderWithProviders(<Exports />);
    await waitFor(() => expect(screen.getByText('السجلات المقبولة')).toBeInTheDocument()); expect(screen.getByText('aaaaaaaaaaaa…aaaaaaaa')).toBeInTheDocument(); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: { code: 'export_not_found', message: 'none' } }, 404)); renderWithProviders(<Exports />);
    await waitFor(() => expect(screen.getByText('لا يوجد تصدير متاح حتى الآن')).toBeInTheDocument());
  });
  it('keeps unrelated 404, malformed, 401, and 503 responses distinct', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: { code: 'different_not_found', message: 'none' } }, 404)); renderWithProviders(<Exports />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('تعذر تحميل البيانات')); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-1', status: 'completed', dataset_sha256: 'bad', accepted_records: 0, review_records: 0 })); renderWithProviders(<Exports />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument()); cleanup();
    sessionStorage.setItem('cti_access_token', 'token'); vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: 'expired' }, 401)); renderWithProviders(<Exports />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('انتهت جلسة الدخول')); expect(sessionStorage.getItem('cti_access_token')).toBeNull(); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: 'unavailable' }, 503)); renderWithProviders(<Exports />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('خدمة التصدير غير متاحة')); expect(screen.getByRole('button', { name: 'إعادة المحاولة' })).toBeInTheDocument();
  });
});
