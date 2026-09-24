import { act, cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, clearToken } from '../api/client';
import { JobMonitor, JOB_POLL_INTERVAL_MS, Sources } from '../pages/Sources';
import { renderWithProviders } from './fixtures';

const enabled = { source_id: 'source-one', name: 'المصدر الأول', source_type: 'rss', status: 'enabled', metadata: {} };
const disabled = { source_id: 'source-two', name: 'المصدر الثاني', source_type: 'cert', status: 'disabled', metadata: {} };
const otherEnabled = { source_id: 'source-three', name: 'المصدر الثالث', source_type: 'rss', status: 'enabled', metadata: {} };
const users = { viewer: { id: 'u1', username: 'viewer', role: 'viewer', is_active: true }, analyst: { id: 'u2', username: 'analyst', role: 'analyst', is_active: true }, admin: { id: 'u3', username: 'admin', role: 'admin', is_active: true } } as const;
const job = (state: string, result: Record<string, unknown> | null = null, error: Record<string, unknown> | null = null) => ({ schema_version: '1.0', job_id: 'job-1234567890', command_id: 'cmd-1234567890', state, created_at: '2026-09-06T00:00:00Z', updated_at: '2026-09-06T00:00:01Z', progress: {}, result, error });
const response = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);

function mockRole(role: keyof typeof users, handler?: (path: string, init?: RequestInit) => Promise<Response>) {
  sessionStorage.setItem('cti_access_token', 'token');
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const path = String(input);
    if (path.endsWith('/auth/me')) return response(users[role]);
    if (path.endsWith('/integrations/external-control/sources')) return response([enabled, disabled, otherEnabled]);
    return handler ? handler(path, init) : response(job('queued'));
  });
}

beforeEach(() => { sessionStorage.clear(); clearToken(); vi.restoreAllMocks(); });
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe('single external source job', () => {
  it('keeps viewers read-only and shows the action to analyst and admin', async () => {
    mockRole('viewer'); renderWithProviders(<Sources />); await screen.findByText(enabled.name); expect(screen.queryByRole('button', { name: `تشغيل ${enabled.name}` })).not.toBeInTheDocument(); cleanup();
    mockRole('analyst'); renderWithProviders(<Sources />); expect(await screen.findByRole('button', { name: `تشغيل ${enabled.name}` })).toBeEnabled(); cleanup();
    mockRole('admin'); renderWithProviders(<Sources />); expect(await screen.findByRole('button', { name: `تشغيل ${enabled.name}` })).toBeEnabled();
  });

  it('shows credential-free readiness, method labels, and limitations without technical identifiers', async () => {
    sessionStorage.setItem('cti_language', 'en');
    const publicSources = [
      { source_id: 'reddit-hidden-id', name: 'Reddit netsec', source_type: 'reddit', status: 'ready', metadata: { transport: 'rss_with_browser_fallback', limitation: 'public_feed_availability' } },
      { source_id: 'telegram-hidden-id', name: 'Telegram public', source_type: 'telegram', status: 'ready', metadata: { transport: 'telegram_public_preview', limitation: 'configured_public_channels_only' } },
    ];
    sessionStorage.setItem('cti_access_token', 'token');
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/auth/me')
      ? response(users.viewer) : response(publicSources));
    renderWithProviders(<Sources />);
    expect(await screen.findByText('RSS first with bounded browser fallback')).toBeInTheDocument();
    expect(screen.getByText('Public Channel Preview')).toBeInTheDocument();
    expect(screen.getByText(/browser fallback runs only when insufficient/i)).toBeInTheDocument();
    expect(screen.getByText(/configured public channels/i)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('reddit-hidden-id');
    expect(document.body).not.toHaveTextContent('telegram-hidden-id');
    expect(screen.queryByRole('button', { name: /تشغيل/ })).not.toBeInTheDocument();
  });

  it('disables a disabled source and requires confirmation', async () => {
    const fetchMock = mockRole('analyst'); renderWithProviders(<Sources />);
    expect(await screen.findByRole('button', { name: `تشغيل ${disabled.name}` })).toBeDisabled();
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    await userEvent.setup().click(screen.getByRole('button', { name: `تشغيل ${enabled.name}` }));
    expect(window.confirm).toHaveBeenCalled(); expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/jobs'))).toBe(false);
  });

  it('keeps approved state distinct from repeated operational disable and enable actions', async () => {
    sessionStorage.setItem('cti_language','en');sessionStorage.setItem('cti_access_token','token');
    let current={...enabled};
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{const path=String(input);if(path.endsWith('/auth/me'))return response(users.analyst);if(path.endsWith('/integrations/external-control/sources'))return response([current]);if(path.endsWith(`/sources/${current.source_id}/disable`)&&init?.method==='POST'){current={...current,status:'disabled'};return response(current)}if(path.endsWith(`/sources/${current.source_id}/enable`)&&init?.method==='POST'){current={...current,status:'enabled'};return response(current)}return response({},404)});
    vi.spyOn(window,'confirm').mockReturnValue(true);renderWithProviders(<Sources/>);const actor=userEvent.setup();await screen.findByText(current.name);
    await actor.click(screen.getByRole('button',{name:'Disable'}));const enableButton=await screen.findByRole('button',{name:'Enable'});expect(screen.getByLabelText('Status: disabled')).toBeInTheDocument();
    await actor.click(enableButton);await waitFor(()=>expect(screen.getByLabelText('Status: enabled')).toBeInTheDocument());const row=screen.getByText(current.name).closest('tr')!;expect(within(row).queryByText('pending_review')).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([input])=>String(input).endsWith(`/sources/${current.source_id}/disable`))).toHaveLength(1);expect(fetchMock.mock.calls.filter(([input])=>String(input).endsWith(`/sources/${current.source_id}/enable`))).toHaveLength(1);
  });

  it('starts only the selected source and prevents duplicate submissions', async () => {
    let resolveStart!: (value: Response) => void;
    const pending = new Promise<Response>((resolve) => { resolveStart = resolve; });
    const fetchMock = mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? pending : response(job('queued')));
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />); const button = await screen.findByRole('button', { name: `تشغيل ${enabled.name}` });
    await userEvent.setup().click(button); expect(button).toBeDisabled(); await userEvent.setup().click(button);
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/sources/source-one/jobs'))).toHaveLength(1);
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('source-two/jobs'))).toBe(false);
    resolveStart(await response(job('queued'))); await screen.findByText(/في الانتظار/);
  });

  it('keeps job state and result counts on the selected source row only', async () => {    let resolveStart!: (value: Response) => void; const pendingStart = new Promise<Response>((resolve) => { resolveStart = resolve; });    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? pendingStart : response(job('completed', { accepted_records: 7 }))); vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />);    const selectedButton = await screen.findByRole('button', { name: `تشغيل ${enabled.name}` }); const otherButton = screen.getByRole('button', { name: `تشغيل ${otherEnabled.name}` });    await userEvent.setup().click(selectedButton); expect(selectedButton).toBeDisabled(); expect(selectedButton).toHaveTextContent('جار الإرسال'); expect(otherButton).toBeEnabled(); expect(otherButton).toHaveTextContent('تشغيل');    resolveStart(await response(job('completed', { accepted_records: 7 }))); await waitFor(() => { const selectedRow = screen.getAllByText(enabled.name)[0].closest('tr')!; const detailRow = selectedRow.nextElementSibling as HTMLElement; expect(within(detailRow).getByText(/مكتملة/)).toBeInTheDocument(); expect(within(detailRow).getByText('7')).toBeInTheDocument(); }); const otherRow = screen.getByText(otherEnabled.name).closest('tr')!; expect(within(otherRow).queryByText(/مكتملة|قيد التشغيل/)).not.toBeInTheDocument(); expect(within(otherRow).getByRole('button',{name:`تشغيل ${otherEnabled.name}`})).toBeEnabled();  });
  it('polls queued to running to completed and displays returned counts', async () => {
    let poll = 0;
    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? response(job('queued')) : response(++poll === 1 ? job('running') : job('completed', { accepted_records: 3, review_records: 1, rejected_records: 2, skipped_records: 4, error_count: 0 })));
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />); const button = await screen.findByRole('button', { name: `تشغيل ${enabled.name}` });
    button.click(); await screen.findByText(/قيد التشغيل/)
    await screen.findByText(/مكتملة/, {}, { timeout: JOB_POLL_INTERVAL_MS * 2 }); expect(screen.getByText('3')).toBeInTheDocument(); expect(screen.getByText('للمراجعة')).toBeInTheDocument();
  });

  it('shows failed jobs with sanitized errors', async () => {
    const failure = { code: 'job_failed', message: 'failure at http://private.local token=secret', retryable: false, details: {} };
    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? response(job('failed', { error_count: 1 }, failure)) : response(job('failed', { error_count: 1 }, failure)));
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />); await userEvent.setup().click(await screen.findByRole('button', { name: `تشغيل ${enabled.name}` })); await screen.findByText(/فشلت/); expect(document.body).not.toHaveTextContent('private.local'); expect(document.body).not.toHaveTextContent('token=secret');
  });

  it('shows provider temporary unavailability for a valid failed provider job', async () => {
    sessionStorage.setItem('cti_language', 'en');
    const failure = { code: 'provider_temporarily_unavailable', message: 'discovery provider is temporarily unavailable', retryable: true, details: {} };
    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? response(job('failed', {}, failure)) : response(job('failed', {}, failure)));
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />);
    await userEvent.setup().click(await screen.findByRole('button', { name: `Run ${enabled.name}` }));
    expect(await screen.findByText('The discovery provider is unavailable')).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('Connection temporarily interrupted');
  });

  it('shows a valid failed CISA result as source failure rather than interrupted transport', async () => {
    sessionStorage.setItem('cti_language', 'en'); sessionStorage.setItem('cti_access_token', 'token');
    const cisa = { source_id: 'cisa-advisories', name: 'CISA', source_type: 'cert', status: 'enabled', metadata: {} };
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const path=String(input);
      if(path.endsWith('/auth/me')) return response(users.analyst);
      if(path.endsWith('/integrations/external-control/sources')) return response([cisa]);
      return response(job('failed', { status:'failed', error_count:50, sources:{'cisa-advisories':{
        status:'failed', error_count:50, collection_method:'official_csaf',
        failure_categories:{csaf_document_media_type:50}}}}));
    });
    vi.spyOn(window,'confirm').mockReturnValue(true); renderWithProviders(<Sources />);
    await userEvent.setup().click(await screen.findByRole('button',{name:'Run CISA'}));
    expect(await screen.findByText('CISA is currently unavailable.')).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('Connection temporarily interrupted');
  });

  it('runs all enabled sources once for analysts, monitors aggregate results, and hides it from viewers', async () => {
    mockRole('viewer'); renderWithProviders(<Sources />); await screen.findByText(enabled.name); expect(screen.queryByRole('button', { name: 'تشغيل جميع المصادر المفعّلة' })).not.toBeInTheDocument(); cleanup();
    let resolveStart!: (value: Response) => void; const pending = new Promise<Response>((resolve) => { resolveStart = resolve; });
    const fetchMock = mockRole('analyst', (path, init) => path.endsWith('/integrations/external-control/jobs') && init?.method === 'POST' ? pending : response(job('completed', { accepted_records: 4, sources: { 'source-one': { status: 'completed', accepted_records: 4 } } })));
    vi.spyOn(window, 'confirm').mockReturnValue(true); renderWithProviders(<Sources />); const button = await screen.findByRole('button', { name: 'تشغيل جميع المصادر المفعّلة' });
    await userEvent.setup().click(button); expect(button).toBeDisabled(); await userEvent.setup().click(button);
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/integrations/external-control/jobs'))).toHaveLength(1);
    const body = JSON.parse(String((fetchMock.mock.calls.find(([input]) => String(input).endsWith('/integrations/external-control/jobs'))?.[1] as RequestInit).body));
    expect(body).toEqual({ source_ids: [], scope: 'all_enabled', force: false });
    resolveStart(await response(job('completed', { accepted_records: 4, sources: { 'source-one': { status: 'completed', accepted_records: 4 } } })));
    expect(await screen.findByText('4')).toBeInTheDocument();
  });

  it('pauses bounded monitoring without reporting job failure and cleans polling up on unmount', async () => {
    const fetchMock = mockRole('analyst', () => response(job('running')));
    const view = renderWithProviders(<JobMonitor sourceId="source-one" job={{...job('running'),counts:{},sources:{}} as never} onUpdate={()=>undefined} maxPollingMs={25}/>);
    expect(await screen.findByText(/لا تزال الوظيفة قيد التشغيل/)).toBeInTheDocument();expect(screen.queryByRole('alert')).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'استئناف المتابعة'})).toBeEnabled();
    const count = fetchMock.mock.calls.length; view.unmount(); await new Promise(resolve=>window.setTimeout(resolve,JOB_POLL_INTERVAL_MS+25));expect(fetchMock).toHaveBeenCalledTimes(count);
  });

  it('uses existing 401 expiry behavior and rejects malformed jobs', async () => {
    mockRole('analyst', (path) => path.endsWith('/sources/source-one/jobs') ? response({ detail: 'Authentication required' }, 401) : response(job('queued'))); vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<Sources />); await userEvent.setup().click(await screen.findByRole('button', { name: `تشغيل ${enabled.name}` })); await waitFor(() => expect(sessionStorage.getItem('cti_access_token')).toBeNull()); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ job_id: 'short', state: 'unknown' })); await expect(api.externalJob('job-1234567890')).rejects.toMatchObject({ status: 502, code: 'invalid_response' });
  });
});
