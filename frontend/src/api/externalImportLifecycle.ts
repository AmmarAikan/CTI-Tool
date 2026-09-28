import type { QueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { api, ApiError, type AcceptedSyncResult, type ExternalIngestionOperation, type ExternalJob } from './client';
import { externalQueryKeys } from './externalQueryKeys';

export type ExternalImportStage='terminal_detected'|'import_ready'|'import_request_started'|'monitoring_paused'|'import_succeeded'|'import_failed'|'import_aborted';
export type ExternalImportState={stage:ExternalImportStage;code:string;identity?:string;operationId?:string;result?:AcceptedSyncResult;error?:unknown};
const STORAGE='cti_external_ingestion_operations_v1';
export const EXTERNAL_IMPORT_MONITORING_MAX_MS=120_000;

export function externalImportIdentity(job?:ExternalJob):string|undefined {
  if(!job||!['completed','partial'].includes(job.state)||job.export?.status!=='completed') return;
  const value=job.export;
  if(!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(value.run_id)||!/^[a-f0-9]{64}$/i.test(value.dataset_sha256||'')) return;
  return `${job.job_id}:${value.run_id}:${value.dataset_sha256}`;
}
export function externalImportBlockReason(job:ExternalJob):'export_incomplete'|'export_identity_missing'|undefined {
  if(!['completed','partial'].includes(job.state)) return;
  if(job.export?.status!=='completed') return 'export_incomplete';
  return externalImportIdentity(job)?undefined:'export_identity_missing';
}
export function isAbortError(error:unknown){return error instanceof DOMException&&error.name==='AbortError'}
export function isRetryableExternalImportError(error:unknown){return error instanceof TypeError||(error instanceof ApiError&&error.retryable)}
export function safeExternalImportCode(error:unknown){if(error instanceof ApiError)return error.code;if(error instanceof TypeError)return'network_request_failed';return'local_import_failed'}
function load():Record<string,string>{try{const value=JSON.parse(sessionStorage.getItem(STORAGE)||'{}');return value&&typeof value==='object'?value:{}}catch{return{}}}
function remember(identity:string,id:string){try{sessionStorage.setItem(STORAGE,JSON.stringify({...load(),[identity]:id}))}catch{/* optional */}}
function resultOf(value:ExternalIngestionOperation):AcceptedSyncResult{return{run_id:value.pipeline_run_id||value.operation_id,status:value.state,imported:value.created,updated:value.updated,unchanged:value.unchanged,failed:value.failed,total:value.imported+value.unchanged}}

export function useExternalImportLifecycle(job:ExternalJob|undefined,onSuccess:(result:AcceptedSyncResult)=>void){
  const identity=externalImportIdentity(job),jobId=identity?job!.job_id:undefined,callback=useRef(onSuccess);
  callback.current=onSuccess;
  const[retryGeneration,setRetryGeneration]=useState(0);
  const[monitorGeneration,setMonitorGeneration]=useState(0);
  const[state,setState]=useState<ExternalImportState>({stage:'terminal_detected',code:'awaiting_terminal'});
  useEffect(()=>{
    if(!job||!['completed','partial'].includes(job.state))return;
    if(!identity||!jobId){setState({stage:'terminal_detected',code:externalImportBlockReason(job)||'export_not_ready'});return}
    let mounted=true,timer:number|undefined;
    const monitoringStarted=Date.now();
    const controller=new AbortController(),existing=load()[identity];
    setState({stage:'import_ready',code:'export_completed',identity,operationId:existing});
    const consume=(value:ExternalIngestionOperation):boolean=>{
      if(!mounted)return true;
      if(value.state==='completed'||value.state==='partial'){
        const result=resultOf(value);setState({stage:'import_succeeded',code:'central_commit_proven',identity,operationId:value.operation_id,result});callback.current(result);return true;
      }
      if(value.state==='failed_terminal'||value.state==='failed_retryable'){
        setState({stage:'import_failed',code:value.error?.code||'ingestion_failed',identity,operationId:value.operation_id,error:new ApiError(409,value.error?.code||'ingestion_failed',value.error?.message||'External ingestion failed',value.retryable)});return true;
      }
      setState({stage:'import_request_started',code:value.stage,identity,operationId:value.operation_id});return false;
    };
    const poll=async(operationId:string)=>{try{const value=await api.externalIngestion(operationId,controller.signal);if(consume(value))return;if(Date.now()-monitoringStarted>=EXTERNAL_IMPORT_MONITORING_MAX_MS){setState({stage:'monitoring_paused',code:'monitoring_window_expired',identity,operationId});return}timer=window.setTimeout(()=>void poll(operationId),2000)}catch(error){if(!mounted||isAbortError(error))return;setState({stage:'import_failed',code:safeExternalImportCode(error),identity,operationId,error})}};
    const start=async()=>{try{const value=existing?(retryGeneration?await api.retryExternalIngestion(existing,controller.signal):await api.externalIngestion(existing,controller.signal)):await api.createExternalIngestion(jobId,controller.signal);remember(identity,value.operation_id);if(consume(value))return;void poll(value.operation_id)}catch(error){if(!mounted||isAbortError(error))return;setState({stage:'import_failed',code:safeExternalImportCode(error),identity,error})}};
    void start();
    return()=>{mounted=false;if(timer)window.clearTimeout(timer);controller.abort()};
  },[identity,jobId,retryGeneration,monitorGeneration]);
  return{state,retry:()=>setRetryGeneration(value=>value+1),resume:()=>setMonitorGeneration(value=>value+1)};
}

export async function refreshAfterExternalImport(queryClient:QueryClient,result:AcceptedSyncResult){await Promise.all([queryClient.invalidateQueries({queryKey:['external','accepted-records'],refetchType:'active'}),queryClient.invalidateQueries({queryKey:externalQueryKeys.reviews(),refetchType:'active'}),queryClient.invalidateQueries({queryKey:externalQueryKeys.processingRun(result.run_id),refetchType:'active'}),queryClient.invalidateQueries({queryKey:['center-summary'],exact:true,refetchType:'active'}),queryClient.invalidateQueries({queryKey:['center-events'],exact:true,refetchType:'active'}),queryClient.invalidateQueries({queryKey:['center-indicators'],exact:true,refetchType:'active'}),queryClient.invalidateQueries({queryKey:['dashboard-summary'],exact:true,refetchType:'active'}),queryClient.invalidateQueries({queryKey:['indicator-summary'],exact:true,refetchType:'active'})])}
export function resetExternalImportLifecycleForTests(){try{sessionStorage.removeItem(STORAGE)}catch{/* optional */}}
