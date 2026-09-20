import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { clearToken } from '../api/client';
import { Exports } from '../pages/Exports';
import { Reviews } from '../pages/Reviews';
import { DarkWebWatches } from '../pages/DarkWebWatches';
import { AcceptedRecords } from '../pages/AcceptedRecords';
import { renderWithProviders } from './fixtures';

const response = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) } as Response);
beforeEach(() => { sessionStorage.clear(); clearToken(); vi.restoreAllMocks(); });

describe('external reviews states', () => {
  it('accepts the exact live reviews root with 86 records and nullable classification labels',async()=>{
    sessionStorage.setItem('cti_language','en');const records=Array.from({length:86},(_,index)=>({record_id:`live-review-${String(index).padStart(4,'0')}`,title:`Live review ${index}`,source_type:'rss',review_reason:'classification_review',review_reasons:['classification_review'],classification_label:index===0?null:'cti_related',privacy_status:'reviewed',collected_at:'2026-09-20T00:00:00Z',published:null,content_sha256:`sha256:${index.toString(16).padStart(64,'0')}`,review_version:'external_review_v2',summary:'Safe summary',excerpt:'Sanitized excerpt',source:'Safe source',category:'advisory',status:'pending'}));
    vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({records,run_id:'live-run-123'}));renderWithProviders(<Reviews/>);expect(await screen.findByText('86 records')).toBeInTheDocument();expect(screen.getByText('Unclassified / Unknown')).toBeInTheDocument();expect(screen.getByText('Live review 85')).toBeInTheDocument();
  });
  it('isolates one malformed review while retaining valid records',async()=>{
    sessionStorage.setItem('cti_language','en');sessionStorage.setItem('cti_access_token','token');const valid={record_id:'live-review-valid',title:'Valid review',source_type:'rss',review_reason:'classification_review',review_reasons:['classification_review'],classification_label:null,privacy_status:'reviewed',collected_at:null,published:null,content_sha256:`sha256:${'a'.repeat(64)}`,review_version:'external_review_v2',summary:'Safe',excerpt:'Sanitized',source:'Safe source',category:'advisory',status:'pending'};
    vi.spyOn(globalThis,'fetch').mockImplementation(input=>String(input).endsWith('/auth/me')?response({id:'u',username:'analyst',role:'analyst',is_active:true}):response({records:[valid,{...valid,record_id:'live-review-bad',classification_label:{unsafe:true}}],run_id:'live-run-123'}));renderWithProviders(<Reviews/>);expect(await screen.findByText('Valid review')).toBeInTheDocument();expect(screen.getByText('Safely ignored 1 malformed records.')).toBeInTheDocument();
  });
  it('accepts an empty review artifact and the confirmed no-artifact response', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-1', records: [] })); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByText('لا توجد مراجعات حتى الآن')).toBeInTheDocument()); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: { code: 'review_not_found', message: 'none' } }, 404)); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByText('لا توجد مراجعات حتى الآن')).toBeInTheDocument());
  });
  it('preserves populated rendering and rejects malformed or unrelated 404 responses', async () => {
    const record = { record_id: 'record-1', title: 'تقرير آمن', source_type: 'rss', review_reason: 'review', review_reasons: ['review'], classification_label: null, privacy_status: null, collected_at: null, published: null, content_sha256: `sha256:${'a'.repeat(64)}`, review_version:'external_review_v2',summary:'ملخص آمن',excerpt: 'محتوى منقّى', source: 'مصدر آمن', category: 'advisory', status: 'pending' };
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-1', records: [record] })); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByText('تقرير آمن')).toBeInTheDocument()); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ detail: { code: 'different_not_found', message: 'none' } }, 404)); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('تعذر تحميل البيانات')); cleanup();
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ run_id: 'run-1', records: [], secret: 'x' })); renderWithProviders(<Reviews />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
  });
  it('renders multiple real-shape records with nullable classification, RSS dates, and redacted title URLs', async () => {
    const records = [
      { record_id: 'record-rss', title: 'تنبيه عام https://public.example/advisory تفاصيل إضافية', source_type: 'rss', review_reason: 'classification_review', review_reasons: ['classification_review'], classification_label: null, privacy_status: 'reviewed', collected_at: '2026-09-09T02:01:00Z', published: 'Wed, 09 Sep 2026 02:00:02 GMT', content_sha256: `sha256:${'b'.repeat(64)}`, review_version:'external_review_v2',summary:'Safe summary',excerpt: 'Sanitized RSS content', source: 'Safe RSS', category: 'advisory', status: 'pending' },
      { record_id: 'record-iso', title: 'تقرير ثانٍ', source_type: 'vulnerability', review_reason: 'privacy_review', review_reasons: ['privacy_review'], classification_label: 'public', privacy_status: 'reviewed', collected_at: null, published: '2026-09-09T04:00:02+02:00', content_sha256:'sha256:'+'a'.repeat(64),review_version:'external_review_v2',summary:'Safe summary',excerpt:'Sanitized review content', source:'Safe source', category:'advisory', status:'pending' },
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
  it('confirms an exact review decision and shows backend-confirmed success',async()=>{
    sessionStorage.setItem('cti_access_token','token');const record={record_id:'record-1234567890',title:'Safe',source_type:'rss',review_reason:'privacy_review',review_reasons:['privacy_review'],classification_label:'cti_related',privacy_status:'reviewed',collected_at:null,published:null,content_sha256:`sha256:${'a'.repeat(64)}`,review_version:'external_review_v2',summary:'Safe summary',excerpt:'Sanitized',source:'Source',category:'advisory',status:'pending'};
    let completed=false;const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'analyst',role:'analyst',is_active:true});if(path.endsWith('/reviews/latest'))return response({run_id:'run-1',records:completed?[]:[record]});if(path.endsWith(`/reviews/${record.record_id}/decision`)&&init?.method==='POST'){completed=true;return response({schema_version:'1.0',record_id:record.record_id,content_sha256:record.content_sha256,decision:'approved',reason:null,decided_at:'2026-09-19T00:00:00Z',export_run_id:'ext-run-1',processing_state:'completed',retryable:false})}return response({},404)});
    vi.spyOn(window,'confirm').mockReturnValue(true);renderWithProviders(<Reviews/>);await userEvent.setup().click(await screen.findByRole('button',{name:'اعتماد وحفظ'}));
    expect(await screen.findByRole('status')).toHaveTextContent('تم اعتماد السجل');expect(screen.queryByText('Safe')).not.toBeInTheDocument();
    const call=fetchMock.mock.calls.find(([input])=>String(input).endsWith(`/reviews/${record.record_id}/decision`));expect(call?.[1]?.body).toBe(JSON.stringify({expected_content_sha256:record.content_sha256,decision:'approved',reason:null}));
  });
  it('rejects with the exact identity and reports stale-content conflicts',async()=>{
    sessionStorage.setItem('cti_language','en');sessionStorage.setItem('cti_access_token','token');
    const record={record_id:'record-1234567890',title:'Safe',source_type:'rss',review_reason:'privacy_review',review_reasons:['privacy_review'],classification_label:'cti_related',privacy_status:'reviewed',collected_at:null,published:null,content_sha256:`sha256:${'b'.repeat(64)}`,review_version:'external_review_v2',summary:'Safe summary',excerpt:'Sanitized',source:'Source',category:'advisory',status:'pending'};
    let conflict=false;
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'analyst',role:'analyst',is_active:true});if(path.endsWith('/reviews/latest'))return response({run_id:'run-1',records:[record]});if(path.endsWith(`/reviews/${record.record_id}/decision`)&&init?.method==='POST')return conflict?response({detail:{code:'review_content_changed',message:'changed'}},409):response({schema_version:'1.0',record_id:record.record_id,content_sha256:record.content_sha256,decision:'rejected',reason:'duplicate',decided_at:'2026-09-19T00:00:00Z',export_run_id:null,processing_state:'completed',retryable:false});return response({},404)});
    vi.spyOn(window,'confirm').mockReturnValue(true);renderWithProviders(<Reviews/>);const actor=userEvent.setup();await screen.findByText('Safe');await actor.selectOptions(screen.getByLabelText('Discard reason'),'duplicate');await actor.click(screen.getByRole('button',{name:'Reject'}));
    expect(await screen.findByRole('status')).toHaveTextContent('Record ignored');const call=fetchMock.mock.calls.find(([input])=>String(input).endsWith(`/reviews/${record.record_id}/decision`));expect(call?.[1]?.body).toBe(JSON.stringify({expected_content_sha256:record.content_sha256,decision:'rejected',reason:'duplicate'}));
    cleanup();conflict=true;renderWithProviders(<Reviews/>);await actor.click(await screen.findByRole('button',{name:'Approve & save'}));expect(await screen.findByRole('alert')).toHaveTextContent('record changed');
  });
  it('does not show success or remove the visible item when confirmed processing fails',async()=>{
    sessionStorage.setItem('cti_language','en');sessionStorage.setItem('cti_access_token','token');const record={record_id:'record-1234567890',title:'Retryable review',source_type:'rss',review_reason:'privacy_review',review_reasons:['privacy_review'],classification_label:'cti_related',privacy_status:'reviewed',collected_at:null,published:null,content_sha256:`sha256:${'c'.repeat(64)}`,review_version:'external_review_v2',summary:'Safe summary',excerpt:'Sanitized',source:'Source',category:'advisory',status:'pending'};
    vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'analyst',role:'analyst',is_active:true});if(path.endsWith('/reviews/latest'))return response({run_id:'run-1',records:[record]});if(path.endsWith(`/reviews/${record.record_id}/decision`)&&init?.method==='POST')return response({detail:{code:'review_processing_failed',message:'retryable'}},502);return response({},404)});
    vi.spyOn(window,'confirm').mockReturnValue(true);renderWithProviders(<Reviews/>);await userEvent.setup().click(await screen.findByRole('button',{name:'Approve & save'}));expect(await screen.findByRole('alert')).toBeInTheDocument();expect(screen.getByText('Retryable review')).toBeInTheDocument();expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
  it('shows a durably decided approval as processing without decision controls',async()=>{
    sessionStorage.setItem('cti_language','en');const record={record_id:'record-processing-123',title:'Processing review',source_type:'rss',review_reason:'privacy_review',review_reasons:['privacy_review'],classification_label:'cti_related',privacy_status:'reviewed',collected_at:null,published:null,content_sha256:`sha256:${'e'.repeat(64)}`,review_version:'external_review_v2',summary:'Safe summary',excerpt:'Sanitized',source:'Source',category:'advisory',status:'approved_processing'};
    vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({run_id:'run-1',records:[record]}));renderWithProviders(<Reviews/>);expect(await screen.findByText('Decision saved; Central processing is in progress.')).toBeInTheDocument();expect(screen.queryByRole('button',{name:'Approve & save'})).not.toBeInTheDocument();expect(screen.getByText('Processing review')).toBeInTheDocument();
  });
});

describe('accepted records read-only view',()=>{
  it('accepts the exact 20-item live Accepted Records page and isolates a malformed item',async()=>{
    sessionStorage.setItem('cti_language','en');const make=(index:number)=>({id:`accepted-live-${index}`,title:`Accepted live ${index}`,source:'Trusted source',source_type:'rss',category:index===0?null:'advisory',summary:'Safe summary',published:null,collected_at:'2026-09-20T00:00:00Z',accepted_at:'2026-09-20T00:01:00Z',processing_state:'processed',classification:index===0?null:'cti_related',privacy_status:'reviewed',entity_count:0,indicator_count:0,correlation_count:0});const items=Array.from({length:20},(_,index)=>make(index));
    vi.spyOn(globalThis,'fetch').mockImplementation((input)=>String(input).includes('/accepted-records?')?response({items,limit:20,offset:0,total:20}):response({id:'u',username:'viewer',role:'viewer',is_active:true}));renderWithProviders(<AcceptedRecords/>);expect(await screen.findByText('Accepted live 19')).toBeInTheDocument();cleanup();
    sessionStorage.setItem('cti_access_token','token');vi.spyOn(globalThis,'fetch').mockImplementation((input)=>String(input).includes('/accepted-records?')?response({items:[make(0),{...make(1),processing_state:null}],limit:20,offset:0,total:2}):response({id:'u',username:'analyst',role:'analyst',is_active:true}));renderWithProviders(<AcceptedRecords/>);expect(await screen.findByText('Accepted live 0')).toBeInTheDocument();expect(screen.getByText('Safely ignored 1 malformed records.')).toBeInTheDocument();
    cleanup();vi.spyOn(globalThis,'fetch').mockImplementation((input)=>String(input).includes('/accepted-records?')?response({items:[{...make(1),processing_state:null}],limit:20,offset:0,total:1}):response({id:'u',username:'analyst',role:'analyst',is_active:true}));renderWithProviders(<AcceptedRecords/>);expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load data');
  });
  it('recovers one transient authenticated 401 and keeps confirmed cached records',async()=>{
    sessionStorage.setItem('cti_language','en');sessionStorage.setItem('cti_access_token','token');const item={id:'accepted-auth-live',title:'Authenticated record',source:'Trusted',source_type:'rss',category:null,summary:'Safe',published:null,collected_at:null,accepted_at:'2026-09-20T00:00:00Z',processing_state:'processed',classification:null,privacy_status:'reviewed',entity_count:0,indicator_count:0,correlation_count:0};let listCalls=0,transient=false;
    vi.spyOn(globalThis,'fetch').mockImplementation((input)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'viewer',role:'viewer',is_active:true});if(path.includes('/accepted-records?')){listCalls+=1;if(transient&&listCalls===2)return response({detail:'transient'},401);return response({items:[item],limit:20,offset:0,total:1})}return response({},404)});
    const view=renderWithProviders(<AcceptedRecords/>);expect(await screen.findByText('Authenticated record')).toBeInTheDocument();transient=true;await view.queryClient.invalidateQueries({queryKey:['external','accepted-records']});await waitFor(()=>expect(listCalls).toBe(3));expect(screen.getByText('Authenticated record')).toBeInTheDocument();expect(sessionStorage.getItem('cti_access_token')).toBe('token');expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('retains confirmed records and shows a non-blocking warning after a transient refresh failure',async()=>{
    sessionStorage.setItem('cti_language','en');
    const item={id:'accepted-record-stale',title:'Confirmed record',source:'Trusted',source_type:'rss',category:'advisory',summary:'Safe',published:null,collected_at:null,accepted_at:'2026-09-20T00:00:00Z',processing_state:'processed',classification:null,privacy_status:null,entity_count:0,indicator_count:0,correlation_count:0};
    let unavailable=false;vi.spyOn(globalThis,'fetch').mockImplementation((input)=>String(input).includes('/accepted-records?')?(unavailable?response({detail:'temporary'},503):response({items:[item],total:1,limit:20,offset:0})):response({id:'u',username:'viewer',role:'viewer',is_active:true}));
    const view=renderWithProviders(<AcceptedRecords/>);expect(await screen.findByText('Confirmed record')).toBeInTheDocument();unavailable=true;await view.queryClient.invalidateQueries({queryKey:['external','accepted-records']});
    expect(await screen.findByText('Refresh is temporarily unavailable. Showing the last confirmed data.')).toBeInTheDocument();expect(screen.getByText('Confirmed record')).toBeInTheDocument();expect(screen.queryByText('Failed to load data')).not.toBeInTheDocument();
  });
  it('aborts stale accepted-record requests and keeps the newest search response',async()=>{
    sessionStorage.setItem('cti_language','en');let firstAborted=false;let resolveFirst!:(value:Response)=>void;const first=new Promise<Response>(resolve=>{resolveFirst=resolve});
    vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'viewer',role:'viewer',is_active:true});if(path.includes('search=older')){init?.signal?.addEventListener('abort',()=>{firstAborted=true});return first}if(path.includes('search=newer'))return response({items:[],total:0,limit:20,offset:0});return response({items:[],total:0,limit:20,offset:0})});
    renderWithProviders(<AcceptedRecords/>);const actor=userEvent.setup();const search=await screen.findByPlaceholderText('Search safe title or text');await actor.type(search,'older');await actor.clear(search);await actor.type(search,'newer');await waitFor(()=>expect(firstAborted).toBe(true));resolveFirst(await response({items:[],total:0,limit:20,offset:0}));expect(screen.getByDisplayValue('newer')).toBeInTheDocument();
  });
  it('reads Central records without exposing a synchronization mutation',async()=>{
    sessionStorage.setItem('cti_access_token','token');
    const page={items:[],total:0,limit:20,offset:0};
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation((input)=>{
      const path=String(input);
      if(path.endsWith('/auth/me'))return response({id:'u',username:'analyst',role:'analyst',is_active:true});
      if(path.includes('/intelligence/accepted-records?'))return response(page);
      return response({},404);
    });
    renderWithProviders(<AcceptedRecords/>);expect(await screen.findByText('لا توجد سجلات مقبولة.')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'مزامنة السجلات المقبولة'})).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([,init])=>init?.method==='POST')).toBe(false);
  });
  it('opens accessible details in a focus-managed modal without moving the list',async()=>{
    sessionStorage.setItem('cti_language','en');sessionStorage.setItem('cti_access_token','token');
    const item={id:'accepted-record-1',title:'Safe accepted record',source:'Trusted source',source_type:'rss',category:'advisory',summary:'Safe summary',published:null,collected_at:'2026-09-19T00:00:00Z',accepted_at:'2026-09-19T00:01:00Z',processing_state:'processed',classification:'cti_related',privacy_status:'reviewed',entity_count:1,indicator_count:1,correlation_count:1};
    const detail={...item,content:'Plain safe content',entities:[{type:'organization',value:'Example Org',confidence:.9,event_id:'event-1',record_title:'Safe accepted record'}],indicators:[{type:'domain',value:'example.invalid',confidence:.8,event_id:'event-1',record_title:'Safe accepted record'}],correlations:[{source_event_id:'event-1',target_event_id:'event-2',type:'shared_indicator',score:.7,explanation:'Shared safe indicator'}]};
    vi.spyOn(globalThis,'fetch').mockImplementation((input)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'analyst',role:'analyst',is_active:true});if(path.includes('/intelligence/accepted-records?'))return response({items:[item],total:1,limit:20,offset:0});if(path.endsWith(`/intelligence/accepted-records/${item.id}`))return response(detail);return response({},404)});
    renderWithProviders(<AcceptedRecords/>);const actor=userEvent.setup();const button=await screen.findByRole('button',{name:'View details'});await actor.click(button);const dialog=await screen.findByRole('dialog',{name:'Safe accepted record'});expect(dialog).toHaveTextContent('Plain safe content');expect(dialog).toHaveTextContent('Example Org');expect(dialog).toHaveTextContent('example.invalid');expect(dialog).toHaveTextContent('Shared safe indicator');expect(document.body.style.overflow).toBe('hidden');
    fireEvent.keyDown(document,{key:'Escape'});await waitFor(()=>expect(screen.queryByRole('dialog')).not.toBeInTheDocument());await waitFor(()=>expect(button).toHaveFocus());expect(document.body.style.overflow).toBe('');
    await actor.click(button);await screen.findByRole('dialog');await actor.click(screen.getByRole('button',{name:'Close'}));await waitFor(()=>expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await actor.click(button);const backdrop=(await screen.findByRole('dialog')).parentElement as HTMLElement;fireEvent.mouseDown(backdrop);await waitFor(()=>expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
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

describe('dark web provider identity', () => {
  it('offers and submits only the exact enabled and ready provider', async () => {
    sessionStorage.setItem('cti_access_token','token');
    const watch={watch_id:'dww-1234567890abcdef',keyword:'Acme',keywords:['Acme'],match_mode:'any',provider_id:'ready-provider',scan_interval_seconds:3600,enabled:true,created_at:'2026-09-14T00:00:00Z',updated_at:'2026-09-14T00:00:00Z',last_scan_at:null,last_success_at:null,result_count:0,new_result_count:0,checkpoint_hash:null};
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'analyst',role:'analyst',is_active:true});if(path.endsWith('/dark-web/watches'))return response({schema_version:'1.0',items:[]});if(path.endsWith('/dark-web/discovery/providers'))return response([{provider_id:'not-ready',enabled:true,ready:false,through_tor:true},{provider_id:'ready-provider',enabled:true,ready:true,through_tor:true}]);if(init?.method==='POST'&&path.endsWith('/dark-web/discovery/watches'))return response(watch,201);return response([])});
    vi.spyOn(window,'confirm').mockReturnValue(true);renderWithProviders(<DarkWebWatches/>);const actor=userEvent.setup();
    const providerSelect=await screen.findByLabelText('مزود الاكتشاف');expect(providerSelect).not.toHaveTextContent('not-ready');await actor.selectOptions(providerSelect,'ready-provider');
    await actor.type(screen.getByLabelText('كلمة المراقبة'),'Acme');await actor.click(screen.getByRole('button',{name:'إضافة كلمة'}));await actor.click(screen.getByRole('button',{name:'إضافة'}));
    await waitFor(()=>expect(fetchMock.mock.calls.some(([input,init])=>String(input).endsWith('/dark-web/discovery/watches')&&init?.method==='POST'&&JSON.parse(String(init.body)).provider_id==='ready-provider')).toBe(true));
  });

  it('keeps direct monitoring operational when discovery is unavailable', async () => {
    sessionStorage.setItem('cti_language','en');sessionStorage.setItem('cti_access_token','token');
    const direct={source_id:'dws-1234567890abcdef12345678',name:'onion-ref:'+'a'.repeat(64),source_type:'dark_web',status:'enabled',metadata:{origin:'promoted',method:'tor'}};
    const queued={schema_version:'1.0',job_id:'job-1234567890',command_id:'cmd-1234567890',state:'queued',created_at:'2026-09-20T00:00:00Z',updated_at:'2026-09-20T00:00:00Z',progress:{},result:null,error:null};
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'analyst',role:'analyst',is_active:true});if(path.endsWith('/integrations/external-control/sources'))return response([direct]);if(path.endsWith('/dark-web/discovery/providers'))return response([]);if(path.endsWith('/dark-web/watches'))return response({schema_version:'1.0',items:[]});if(path.includes('/dark-web/alerts?'))return response({schema_version:'1.0',items:[],total:0,unread:0,limit:25,offset:0});if(path.endsWith(`/sources/${direct.source_id}/jobs`)&&init?.method==='POST')return response(queued,202);return response([],200)});
    vi.spyOn(window,'confirm').mockReturnValue(true);renderWithProviders(<DarkWebWatches/>);
    expect(await screen.findByText('General discovery is temporarily unavailable. Direct Onion-source monitoring remains operational.')).toBeInTheDocument();
    expect(screen.getByRole('heading',{name:'Direct Onion monitoring'})).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Add'})).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button',{name:'Scan now'}));
    await waitFor(()=>expect(fetchMock.mock.calls.some(([input,init])=>String(input).endsWith(`/sources/${direct.source_id}/jobs`)&&init?.method==='POST')).toBe(true));
    expect(fetchMock.mock.calls.some(([input,init])=>String(input).includes('/discovery/watches')&&init?.method==='POST')).toBe(false);
    expect(screen.getAllByText(direct.source_id).some(node=>Boolean(node.closest('details')))).toBe(true);
  });

  it('renders Arabic safely and keeps viewers read-only', async () => {
    sessionStorage.setItem('cti_access_token','token');
    const direct={source_id:'manual-1234567890',name:'مصدر آمن',source_type:'manual_url',status:'enabled',metadata:{origin:'user',method:'dark_web'}};
    vi.spyOn(globalThis,'fetch').mockImplementation((input)=>{const path=String(input);if(path.endsWith('/auth/me'))return response({id:'u',username:'viewer',role:'viewer',is_active:true});if(path.endsWith('/integrations/external-control/sources'))return response([direct]);if(path.endsWith('/dark-web/discovery/providers'))return response([]);if(path.endsWith('/dark-web/watches'))return response({schema_version:'1.0',items:[]});if(path.includes('/dark-web/alerts?'))return response({schema_version:'1.0',items:[],total:0,unread:0,limit:25,offset:0});return response([])});
    renderWithProviders(<DarkWebWatches/>);
    expect(await screen.findByRole('heading',{name:'المراقبة المباشرة لمصادر Onion'})).toBeInTheDocument();
    expect(screen.getByText('مصدر آمن')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'فحص الآن'})).not.toBeInTheDocument();
    expect(screen.queryByText(direct.source_id)).not.toBeInTheDocument();
  });
});
