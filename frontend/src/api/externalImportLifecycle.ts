import { useEffect, useRef, useState } from 'react';
import { api, ApiError, type AcceptedSyncResult, type ExternalJob } from './client';

export type ExternalImportStage = 'terminal_detected' | 'import_ready' | 'import_request_started' | 'import_succeeded' | 'import_failed' | 'import_aborted';
export type ExternalImportState = { stage: ExternalImportStage; code: string; identity?: string; result?: AcceptedSyncResult; error?: unknown };

type Claim = { promise: Promise<AcceptedSyncResult>; controller: AbortController };
const inFlight = new Map<string, Claim>();
const completed = new Set<string>();

export function externalImportIdentity(job?: ExternalJob) {
  if (!job || !['completed', 'partial'].includes(job.state)) return undefined;
  const exported = job.export;
  if (!exported || exported.status !== 'completed' || !exported.run_id || !exported.dataset_sha256) return undefined;
  return `${job.job_id}:${exported.run_id}:${exported.dataset_sha256}`;
}

function isAbort(error: unknown) { return error instanceof DOMException && error.name === 'AbortError'; }

export function safeExternalImportCode(error: unknown) {
  if (error instanceof ApiError) return error.code;
  if (error instanceof TypeError) return 'network_request_failed';
  return 'local_import_failed';
}

export function useExternalImportLifecycle(job: ExternalJob | undefined, onSuccess: (result: AcceptedSyncResult) => void) {
  const identity = externalImportIdentity(job);
  const jobId = identity ? job!.job_id : undefined;
  const callback = useRef(onSuccess);
  callback.current = onSuccess;
  const [retry, setRetry] = useState(0);
  const [state, setState] = useState<ExternalImportState>(() => ({stage:'terminal_detected',code:'awaiting_terminal'}));

  useEffect(() => {
    if (!job || !['completed','partial'].includes(job.state)) return;
    if (!identity || !jobId) { setState({stage:'terminal_detected',code:'export_not_ready'}); return; }
    if (completed.has(identity)) { setState({stage:'import_succeeded',code:'already_completed',identity}); return; }
    setState({stage:'import_ready',code:'export_completed',identity});
    const existing = inFlight.get(identity);
    const controller = existing?.controller ?? new AbortController();
    // api.importExternalJob invokes fetch synchronously before the Promise is claimed.
    const promise = existing?.promise ?? api.importExternalJob(jobId, controller.signal);
    if (!existing) inFlight.set(identity, {promise, controller});
    setState({stage:'import_request_started',code:existing?'joined_in_flight':'http_post_started',identity});
    let mounted = true;
    void promise.then(result => {
      if (inFlight.get(identity)?.promise === promise) inFlight.delete(identity);
      completed.add(identity);
      if (mounted) { setState({stage:'import_succeeded',code:'http_parse_succeeded',identity,result}); callback.current(result); }
    }).catch(error => {
      if (inFlight.get(identity)?.promise === promise) inFlight.delete(identity);
      if (!mounted || isAbort(error)) return;
      setState({stage:'import_failed',code:safeExternalImportCode(error),identity,error});
    });
    return () => {
      mounted = false;
      if (inFlight.get(identity)?.promise === promise) { controller.abort(); inFlight.delete(identity); }
    };
  }, [identity, jobId, retry]);

  return { state, retry: () => setRetry(value => value + 1) };
}

export function resetExternalImportLifecycleForTests() { inFlight.forEach(claim => claim.controller.abort());inFlight.clear();completed.clear(); }
