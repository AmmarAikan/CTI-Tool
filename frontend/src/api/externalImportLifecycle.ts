import type { QueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { api, ApiError, type AcceptedSyncResult, type ExternalJob } from './client';
import { externalQueryKeys } from './externalQueryKeys';

export type ExternalImportStage = 'terminal_detected' | 'import_ready' | 'import_request_started' | 'import_succeeded' | 'import_failed' | 'import_aborted';
export type ExternalImportState = { stage: ExternalImportStage; code: string; identity?: string; result?: AcceptedSyncResult; error?: unknown };
type Claim = { promise: Promise<AcceptedSyncResult>; controller: AbortController };
const inFlight = new Map<string, Claim>();
const completed = new Set<string>();

export function externalImportIdentity(job?: ExternalJob): string | undefined {
  if (!job || !['completed', 'partial'].includes(job.state)) return undefined;
  const value = job.export;
  if (value?.status !== 'completed') return undefined;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(value.run_id) || !/^[a-f0-9]{64}$/i.test(value.dataset_sha256 || '')) return undefined;
  return `${job.job_id}:${value.run_id}:${value.dataset_sha256}`;
}

export function externalImportBlockReason(job: ExternalJob): 'export_incomplete' | 'export_identity_missing' | undefined {
  if (!['completed', 'partial'].includes(job.state)) return undefined;
  if (job.export?.status !== 'completed') return 'export_incomplete';
  return externalImportIdentity(job) ? undefined : 'export_identity_missing';
}

export function isAbortError(error: unknown) { return error instanceof DOMException && error.name === 'AbortError'; }
export function isRetryableExternalImportError(error: unknown) { return error instanceof TypeError || (error instanceof ApiError && error.retryable && [408,503,504].includes(error.status)); }
export function safeExternalImportCode(error: unknown) { if(error instanceof ApiError)return error.code;if(error instanceof TypeError)return 'network_request_failed';return 'local_import_failed'; }

export function useExternalImportLifecycle(job:ExternalJob|undefined,onSuccess:(result:AcceptedSyncResult)=>void) {
  const identity=externalImportIdentity(job);const jobId=identity?job!.job_id:undefined;const callback=useRef(onSuccess);callback.current=onSuccess;
  const [retryGeneration,setRetryGeneration]=useState(0);const [state,setState]=useState<ExternalImportState>({stage:'terminal_detected',code:'awaiting_terminal'});
  useEffect(()=>{if(!job||!['completed','partial'].includes(job.state))return;if(!identity||!jobId){setState({stage:'terminal_detected',code:externalImportBlockReason(job)||'export_not_ready'});return}if(completed.has(identity)){setState({stage:'import_succeeded',code:'already_completed',identity});return}setState({stage:'import_ready',code:'export_completed',identity});const existing=inFlight.get(identity);const controller=existing?.controller??new AbortController();const promise=existing?.promise??api.importExternalJob(jobId,controller.signal);if(!existing)inFlight.set(identity,{promise,controller});setState({stage:'import_request_started',code:existing?'joined_in_flight':'http_post_started',identity});let mounted=true;void promise.then(result=>{if(inFlight.get(identity)?.promise===promise)inFlight.delete(identity);completed.add(identity);if(mounted){setState({stage:'import_succeeded',code:'http_parse_succeeded',identity,result});callback.current(result)}}).catch(error=>{if(inFlight.get(identity)?.promise===promise)inFlight.delete(identity);if(!mounted||isAbortError(error))return;setState({stage:'import_failed',code:safeExternalImportCode(error),identity,error})});return()=>{mounted=false;if(inFlight.get(identity)?.promise===promise){controller.abort();inFlight.delete(identity)}}},[identity,jobId,retryGeneration]);
  return {state,retry:()=>setRetryGeneration(value=>value+1)};
}

export async function refreshAfterExternalImport(queryClient:QueryClient,result:AcceptedSyncResult){await Promise.all([queryClient.invalidateQueries({queryKey:['external','accepted-records'],refetchType:'active'}),queryClient.invalidateQueries({queryKey:externalQueryKeys.reviews(),refetchType:'active'}),queryClient.invalidateQueries({queryKey:externalQueryKeys.processingRun(result.run_id),refetchType:'active'}),queryClient.invalidateQueries({queryKey:['center-summary'],exact:true,refetchType:'active'}),queryClient.invalidateQueries({queryKey:['center-events'],exact:true,refetchType:'active'}),queryClient.invalidateQueries({queryKey:['center-indicators'],exact:true,refetchType:'active'}),queryClient.invalidateQueries({queryKey:['dashboard-summary'],exact:true,refetchType:'active'}),queryClient.invalidateQueries({queryKey:['indicator-summary'],exact:true,refetchType:'active'})])}
export function resetExternalImportLifecycleForTests(){inFlight.forEach(claim=>claim.controller.abort());inFlight.clear();completed.clear()}
