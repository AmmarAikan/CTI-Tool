import { QueryClient } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, clearToken, type ExternalJob } from '../api/client';
import { externalImportIdentity, refreshAfterExternalImport } from '../api/externalImportLifecycle';

const methods = ['cert','configured_onion_get','dark_web','hackernews','official_csaf','official_listing','official_rss','reddit','reddit_browser_fallback','reddit_oauth','reddit_public_rss','rss','telegram','vulnerability'];
const response=(body:unknown)=>Promise.resolve(new Response(JSON.stringify(body),{status:200,headers:{'Content-Type':'application/json'}}));

afterEach(()=>{vi.restoreAllMocks();sessionStorage.clear();clearToken()});

describe('shared exact External import lifecycle',()=>{
  it('accepts every canonical collection method and retains exact export identity',async()=>{
    sessionStorage.setItem('cti_access_token','token');let current=methods[0];
    vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({schema_version:'1.0',job_id:'job-methods-1234567890',command_id:'cmd-methods-1234567890',state:'completed',created_at:'2026-09-01T00:00:00Z',updated_at:'2026-09-01T00:00:01Z',progress:{},result:{accepted_records:1,sources:{source:{status:'completed',collection_method:current,accepted_records:1}},export:{status:'completed',run_id:'export-methods-1234567890',dataset_sha256:'a'.repeat(64),accepted_records:1,review_records:0}},error:null}));
    for(const method of methods){current=method;const job=await api.externalJob('job-methods-1234567890');expect(job.sources.source.collection_method).toBe(method);expect(externalImportIdentity(job)).toBe(`job-methods-1234567890:export-methods-1234567890:${'a'.repeat(64)}`)}
  });

  it('requires job, export run, and digest and awaits all active refresh targets',async()=>{
    const job={job_id:'job-identity-123456',state:'completed',export:{run_id:'export-identity-123456',dataset_sha256:'b'.repeat(64)}} as ExternalJob;
    expect(externalImportIdentity(job)).toBe(`job-identity-123456:export-identity-123456:${'b'.repeat(64)}`);
    expect(externalImportIdentity({...job,export:undefined})).toBeUndefined();
    const client=new QueryClient();const invalidate=vi.spyOn(client,'invalidateQueries').mockResolvedValue();
    await refreshAfterExternalImport(client,{run_id:'central-run-123',status:'completed',imported:1,updated:0,unchanged:0,failed:0,total:1});
    expect(invalidate).toHaveBeenCalledTimes(8);
    expect(invalidate.mock.calls.every(([filters])=>filters?.refetchType==='active')).toBe(true);
  });
});
