import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type JobState, type JobSummary } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { isRetryableJobPollingError, JOB_POLL_INTERVAL_MS, JOB_POLL_MAX_MS, JOB_POLL_TRANSIENT_RETRIES, jobPollingRetryDelay, safePollingError, TERMINAL_STATES } from './Sources';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';

const labels: Record<JobState, TranslationKey> = { queued: 'queued', running: 'processing', completed: 'completed', partial: 'partial', failed: 'failed', cancellation_requested: 'cancellation_requested', cancelled: 'cancelled' };
const active = (state: JobState) => !TERMINAL_STATES.includes(state);

export function Jobs() {
  const {t,number,dateTime}=useI18n(); const { can } = useAuth(); const queryClient = useQueryClient();
  const [search,setSearch]=useState(''),[state,setState]=useState('all'),[selected,setSelected]=useState<JobSummary>(),[timedOut,setTimedOut]=useState(false);
  const cancelGeneration=useRef(0);
  const history=useQuery({queryKey:['external-jobs'],queryFn:api.externalJobs,retry:false});
  const queryKey=['external-job',selected?.job_id] as const;
  const detail=useQuery({queryKey,queryFn:({signal})=>api.externalJob(selected!.job_id,signal),enabled:Boolean(selected&&active(selected.state)&&!timedOut),refetchInterval:q=>q.state.data&&TERMINAL_STATES.includes(q.state.data.state)?false:JOB_POLL_INTERVAL_MS,retry:(count,error)=>isRetryableJobPollingError(error)&&count<JOB_POLL_TRANSIENT_RETRIES,retryDelay:jobPollingRetryDelay});
  const cancel=useMutation({mutationFn:({jobId}:{jobId:string;generation:number})=>api.cancelExternalJob(jobId),onSuccess:(job,request)=>{if(request.generation!==cancelGeneration.current||selected?.job_id!==request.jobId)return;setSelected(old=>old?.job_id===job.job_id?{...old,state:job.state,updated_at:job.updated_at}:old);void history.refetch();}});
  useEffect(()=>{const value=detail.data;if(value&&selected?.job_id===value.job_id)setSelected(old=>old?.job_id===value.job_id?{...old,state:value.state,updated_at:value.updated_at,counts:value.counts}:old);},[detail.data,selected?.job_id]);
  useEffect(()=>{if(!selected||!active(selected.state)||timedOut)return;const timer=window.setTimeout(()=>setTimedOut(true),JOB_POLL_MAX_MS);return()=>window.clearTimeout(timer);},[selected?.job_id,selected?.state,timedOut]);
  useEffect(()=>{if(timedOut)void queryClient.cancelQueries({queryKey,exact:true});},[queryClient,timedOut,selected?.job_id]);
  useEffect(()=>()=>{cancelGeneration.current+=1;void queryClient.cancelQueries({queryKey,exact:true});},[queryClient,selected?.job_id]);
  const jobs=history.data?.jobs||[],filtered=useMemo(()=>jobs.filter(job=>(state==='all'||job.state===state)&&[job.job_id,job.source_id].some(value=>value?.toLowerCase().includes(search.toLowerCase()))),[jobs,state,search]);
  function choose(job:JobSummary){cancelGeneration.current+=1;setTimedOut(false);setSelected(job);}
  function requestCancel(job:JobSummary){if(cancel.isPending||!active(job.state)||!window.confirm(t('confirmCancel')))return;const generation=cancelGeneration.current+1;cancelGeneration.current=generation;cancel.reset();cancel.mutate({jobId:job.job_id,generation});}
  function retryStatus(){setTimedOut(false);void detail.refetch();}
  const selectedState=detail.data&&detail.data.job_id===selected?.job_id?detail.data.state:selected?.state;
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">{t('jobs')} / 03</span><h2>{t('jobHistory')}</h2><p>{t('jobHistoryDescription')}</p></div><span className="count-label">{t('jobsCount',{count:number(filtered.length)})}</span></div>
    <div className="filters"><label className="search-wrap"><span className="sr-only">{t('search')}</span><input value={search} onChange={event=>setSearch(event.target.value)} placeholder={t('searchJob')}/></label><select aria-label={t('filterJobState')} value={state} onChange={event=>setState(event.target.value)}><option value="all">{t('allStates')}</option>{Object.entries(labels).map(([value,label])=><option key={value} value={value}>{t(label)}</option>)}</select></div>
    {history.isLoading&&<LoadingState label={t('loadingJobs')}/>} {history.isError&&(history.error instanceof ApiError&&history.error.status===401?<div className="state-panel error-panel" role="alert">{t('sessionExpired')}</div>:history.error instanceof TypeError?<div className="state-panel error-panel" role="alert"><strong>{t('disconnected')}</strong><button className="button button-secondary" onClick={()=>void history.refetch()}>{t('retry')}</button></div>:<ErrorState onRetry={()=>void history.refetch()}/>)}
    {!history.isLoading&&!history.isError&&jobs.length===0&&<EmptyState label={t('noJobs')}/>} {jobs.length>0&&filtered.length===0&&<EmptyState label={t('noMatches')}/>} {filtered.length>0&&<div className="table-shell"><table><thead><tr><th>{t('job')}</th><th>{t('source')}</th><th>{t('status')}</th><th>{t('lastUpdated')}</th><th>{t('counters')}</th><th>{t('action')}</th></tr></thead><tbody>{filtered.map(job=><tr key={job.job_id}><td><code>{job.job_id}</code></td><td>{job.source_id||t('general')}</td><td><StatusBadge status={t(labels[job.state])}/></td><td>{dateTime(job.updated_at)}</td><td>{number(Object.values(job.counts).reduce((sum,count)=>sum+(count||0),0))}</td><td><button className="button button-secondary" onClick={()=>choose(job)}>{t('follow')}</button>{can('analyst')&&active(job.state)&&<button className="button button-danger" disabled={cancel.isPending||job.state==='cancellation_requested'} onClick={()=>requestCancel(job)}>{t('cancel')}</button>}</td></tr>)}</tbody></table></div>}
    {cancel.isError&&<div className="state-panel error-panel" role="alert">{safePollingError(cancel.error,t)}</div>}
    {selected&&<div className="safe-summary" aria-live="polite"><strong>{t('follow')} <code>{selected.job_id}</code></strong>{detail.isFetching&&detail.failureCount===0&&<span> {t('updating')}</span>}{detail.failureCount>0&&!detail.error&&<p>{t('jobStatusReconnecting',{count:number(detail.failureCount)})}</p>}<p>{t('status')}: {t(labels[selectedState||selected.state])}</p>{detail.isError&&<p className="job-error">{safePollingError(detail.error,t)} <button className="button button-secondary" onClick={retryStatus}>{t('retry')}</button></p>}{timedOut&&<p className="job-error">{t('pollTimeout')} <button className="button button-secondary" onClick={retryStatus}>{t('retry')}</button></p>}</div>}
  </section>;
}
