import { beforeEach, describe, expect, it } from 'vitest';
import type { ExternalJob } from '../api/client';
import { acceptExternalJobUpdate, forgetActiveExternalJob, loadActiveExternalJobs, rememberActiveExternalJob } from '../api/externalJobLifecycle';

const makeJob=(state:ExternalJob['state'],updated_at:string):ExternalJob=>({job_id:'job-lifecycle-123456789',command_id:'cmd-lifecycle-123456789',state,created_at:'2026-09-24T00:00:00Z',updated_at,counts:{},sources:{}});

describe('shared external job lifecycle',()=>{
  beforeEach(()=>sessionStorage.clear());
  it('persists only bounded validated identifiers and removes the exact context',()=>{
    rememberActiveExternalJob('processing-center','source-one','job-lifecycle-123456789');
    rememberActiveExternalJob('bad context','source-one','job-ignored-123456789');
    expect(loadActiveExternalJobs()).toEqual([expect.objectContaining({context:'processing-center',sourceId:'source-one',jobId:'job-lifecycle-123456789'})]);
    forgetActiveExternalJob('processing-center','another-job-123456789');expect(loadActiveExternalJobs()).toHaveLength(1);
    forgetActiveExternalJob('processing-center','job-lifecycle-123456789');expect(loadActiveExternalJobs()).toEqual([]);
  });
  it('does not let stale or non-terminal responses overwrite terminal state',()=>{
    const completed=makeJob('completed','2026-09-24T00:02:00Z');
    expect(acceptExternalJobUpdate(completed,makeJob('running','2026-09-24T00:03:00Z'))).toBe(completed);
    const running=makeJob('running','2026-09-24T00:02:00Z');
    expect(acceptExternalJobUpdate(running,makeJob('queued','2026-09-24T00:01:00Z'))).toBe(running);
  });
});
