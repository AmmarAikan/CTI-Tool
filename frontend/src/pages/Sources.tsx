import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {externalQueryKeys} from '../api/externalQueryKeys';
import { Link } from 'react-router-dom';
import { api, ApiError, type ExternalJob, type JobState, type Source } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { useI18n } from '../i18n/I18nContext';
import './Sources.css';
import { acceptExternalJobUpdate, forgetActiveExternalJob, JOB_INTERACTIVE_MONITOR_MS, JOB_POLL_INTERVAL_MS, JOB_POLL_TRANSIENT_RETRIES, jobPollingRetryDelay, loadActiveExternalJobs, rememberActiveExternalJob, TERMINAL_JOB_STATES } from '../api/externalJobLifecycle';

export { JOB_POLL_INTERVAL_MS, JOB_POLL_TRANSIENT_RETRIES, jobPollingRetryDelay } from '../api/externalJobLifecycle';
export const JOB_POLL_MAX_MS = JOB_INTERACTIVE_MONITOR_MS;
export const TERMINAL_STATES: JobState[] = TERMINAL_JOB_STATES;
const COUNT_LABELS = { accepted_records: 'accepted', review_records: 'forReview', rejected_records: 'rejected', skipped_records: 'skipped', error_count: 'errors', discovered:'discoveredCount', rejected:'rejected', unreachable:'unreachableCount', verified:'verified', matched:'matchedCount', new:'newResult', unchanged:'knownResult', privacy_blocked:'privacyBlockedCount', errors:'errors' } as const;

export function safePollingError(error: unknown, t: ReturnType<typeof useI18n>['t']) {
  if (error instanceof ApiError && error.status === 401) return t('sessionExpired');
  if (error instanceof ApiError && error.status === 403) return t('forbidden');
  if (error instanceof ApiError && error.status === 404) return t('jobNotFound');
  if (error instanceof ApiError && [408, 504].includes(error.status)) return t('jobPollingTimeout');
  if (error instanceof ApiError && error.status === 503) return t('externalControlUnavailable');
  if (error instanceof ApiError && error.status === 502) return t('externalResponseIncompatible');
  if (error instanceof ApiError && ['invalid_response','invalid_error_response'].includes(error.code)) return t('malformed');
  if (error instanceof TypeError) return t('disconnected');
  return t('jobPollingFailed');
}

export function isRetryableJobPollingError(error: unknown) {
  return error instanceof TypeError || (error instanceof ApiError && error.retryable && [408, 503, 504].includes(error.status));
}

function JobPanel({ job, label, pollingError, reconnecting, paused, onRefresh, onResume }: { job?: ExternalJob; label: string; pollingError?: unknown; reconnecting: boolean; paused: boolean; onRefresh: () => void; onResume: () => void }) {
  const {t,number}=useI18n();
  const {can}=useAuth();
  if (paused) return <div className="job-panel" role="status"><strong>{t('monitoringPaused')}</strong><span>{t('monitoringPausedHint')}</span>{can('analyst')&&job&&<details><summary>{t('technicalDetails')}</summary><code dir="ltr">{job.job_id}</code></details>}<button className="button button-secondary" onClick={onRefresh}>{t('refreshStatus')}</button><button className="button button-secondary" onClick={onResume}>{t('resumeMonitoring')}</button></div>;
  if (pollingError) return <div className="job-panel error-panel" role="alert"><strong>{safePollingError(pollingError, t)}</strong><span>{t('manualRefreshHint')}</span>{can('analyst')&&job&&<details><summary>{t('technicalDetails')}</summary><code dir="ltr">{job.job_id}</code></details>}<button className="button button-secondary" onClick={onRefresh}>{t('retry')}</button></div>;
  if (!job) return null;
  const terminal=TERMINAL_STATES.includes(job.state),success=job.state==='completed'||job.state==='partial';
  return <div className={`job-panel ${terminal?success?'success-panel':'error-panel':''}`} role="status" aria-live="polite"><div><strong>{label}</strong><StatusBadge status={job.state} /></div>{reconnecting && <span>{t('jobStatusReconnecting')}</span>}{Object.entries(job.counts).length > 0 && <dl className="job-counts">{Object.entries(job.counts).map(([key, value]) => <div key={key}><dt>{t(COUNT_LABELS[key as keyof typeof COUNT_LABELS])}</dt><dd>{value}</dd></div>)}</dl>}{job.error && <span className="job-error">{t(job.error.code==='provider_temporarily_unavailable'?'providerUnavailable':'jobReportedFailure')}</span>}{terminal&&<small>{t('completedAt',{value:job.updated_at})}</small>}{success&&(job.counts.review_records||0)>0&&<Link to="/reviews">{t('reviews')}</Link>}{can('analyst')&&<details><summary>{t('technicalDetails')}</summary><code dir="ltr">{job.job_id}</code>{Object.keys(job.sources).length > 0 && <div className="source-result-list">{Object.entries(job.sources).map(([id, value]) => <div key={id}><code>{id}</code><span>{value.status}</span><small>{t('recordCount',{count:number(Object.values(value.counts).reduce((sum,count)=>sum+(count||0),0))})}</small></div>)}</div>}</details>}{terminal && <button className="button button-secondary" onClick={onRefresh}>{t('refreshStatus')}</button>}</div>;
}

function RunButton({ source, busy, onRun }: { source: Source; busy: boolean; onRun: (source: Source) => void }) {
  const {t}=useI18n();
  const available = ['enabled', 'ready'].includes(source.status);
  return <button className="button button-secondary" disabled={!available || busy} aria-label={t('runSource',{name:source.name})} title={!available ? t('sourceDisabled') : undefined} onClick={() => onRun(source)}>{busy ? t('submitting') : t('run')}</button>;
}

export function JobMonitor({ sourceId, label=sourceId, job, onUpdate, maxPollingMs = JOB_POLL_MAX_MS }: { sourceId: string; label?: string; job: ExternalJob; onUpdate: (sourceId: string, job: ExternalJob) => void; maxPollingMs?: number }) {
  const [paused, setPaused] = useState(false);
  const terminal = TERMINAL_STATES.includes(job.state);
  const queryKey = ['external-job', job.job_id] as const;
  const query = useQuery({ queryKey, queryFn: ({ signal }) => api.externalJob(job.job_id, signal), enabled: !terminal && !paused, retry: (failureCount, error) => isRetryableJobPollingError(error) && failureCount < JOB_POLL_TRANSIENT_RETRIES, retryDelay: jobPollingRetryDelay, refetchInterval: JOB_POLL_INTERVAL_MS });
  useEffect(() => { setPaused(false); }, [job.job_id]);
  useEffect(() => { if (query.data?.job_id === job.job_id) onUpdate(sourceId, query.data); }, [job.job_id, onUpdate, query.data, sourceId]);
  useEffect(() => {
    if (terminal || paused) return;
    const timer = window.setTimeout(() => setPaused(true), maxPollingMs);
    return () => window.clearTimeout(timer);
  }, [job.job_id, maxPollingMs, terminal, paused]);
  function refresh() { void query.refetch(); }
  function resume() { setPaused(false); }
  return <JobPanel job={job} label={label} pollingError={query.error} reconnecting={query.failureCount > 0 && !query.error} paused={paused} onRefresh={refresh} onResume={resume} />;
}

function SourceRows({ source, canRun, pending, job, submissionError, importError, onRun, onUpdate, onManage }: { source: Source; canRun: boolean; pending: boolean; job?: ExternalJob; submissionError?: string; importError?:string; onRun: (source: Source) => void; onUpdate: (sourceId: string, job: ExternalJob) => void; onManage:(source:Source,action:'enable'|'disable'|'delete')=>void }) {
  const {t}=useI18n();
  const {can}=useAuth();
  const active = Boolean(job && !TERMINAL_STATES.includes(job.state));
  const transport = source.metadata.transport === 'rss_with_browser_fallback' ? t('publicRssFallback') : source.metadata.transport === 'reddit_public_rss' ? t('publicRss') : source.metadata.transport === 'telegram_public_preview' ? t('publicChannelPreview') : undefined;
  const limitation = source.metadata.limitation === 'public_feed_availability' ? t('redditPublicLimitation') : source.metadata.limitation === 'configured_public_channels_only' ? t('telegramPublicLimitation') : undefined;
  const method = job?.sources[source.source_id]?.collection_method;
  const redditState = source.source_type === 'reddit' && method === 'reddit_public_rss' ? t('rssSucceeded') : source.source_type === 'reddit' && method === 'reddit_browser_fallback' ? t('browserFallbackUsed') : source.source_type === 'reddit' && job?.state === 'failed' ? `${t('redditTemporarilyUnavailable')}. ${t('retryAvailable')}` : undefined;
  const cisaState = source.source_id === 'cisa-advisories' && job?.sources[source.source_id]?.status === 'failed' ? t('cisaUnavailable') : undefined;
  return <>
    <tr><td><strong>{source.name}</strong>{can('analyst')&&<details><summary>{t('technicalDetails')}</summary><code dir="ltr">{source.source_id}</code></details>}</td><td><span className="type-label">{transport || source.source_type}</span>{limitation&&<small>{limitation}</small>}</td><td><StatusBadge status={source.status} /></td><td>{Object.keys(source.metadata || {}).length > 0 ? <span className="safe-label">{t('available')}</span> : <span className="muted-text">{t('none')}</span>}</td>{canRun && <td><RunButton source={source} busy={pending || active} onRun={onRun} /> <button className="button button-secondary" disabled={active||pending} onClick={()=>onManage(source,source.status==='disabled'?'enable':'disable')}>{source.status==='disabled'?t('enable'):t('disable')}</button>{source.metadata.origin==='user'&&can('admin')&&<button className="button button-secondary" disabled={active||pending} onClick={()=>onManage(source,'delete')}>{t('delete')}</button>}</td>}</tr>
    {(job || submissionError) && <tr className="job-detail-row"><td colSpan={canRun ? 5 : 4}>{redditState&&<p>{redditState}</p>}{cisaState&&<p>{cisaState}</p>}{submissionError ? <div className="job-panel error-panel" role="alert"><strong>{t('startSourceFailed')}</strong><span>{submissionError}</span></div> : job && <JobMonitor sourceId={source.source_id} label={source.name} job={job} onUpdate={onUpdate} />}{importError&&<div className="job-panel error-panel" role="alert">{importError}</div>}</td></tr>}
  </>;
}

export function Sources() {
  const { can } = useAuth();
  const {t,number}=useI18n();
  const queryClient=useQueryClient();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [type, setType] = useState('all');
  const [jobs, setJobs] = useState<Record<string, ExternalJob>>({});
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [submissionErrors, setSubmissionErrors] = useState<Record<string, string>>({});
  const [importErrors,setImportErrors]=useState<Record<string,string>>({});
  const [centralRuns,setCentralRuns]=useState<Record<string,string>>({});
  const importedJobs=useState(()=>new Set<string>())[0];
  const [allJob, setAllJob] = useState<ExternalJob>();
  const [allError, setAllError] = useState('');
  const query = useQuery({ queryKey: externalQueryKeys.sources(), queryFn: api.externalSources, retry: false });
  const start = useMutation({ mutationFn: (sourceId: string) => api.startExternalSourceJob(sourceId), onMutate: (sourceId) => { setPending((value) => ({ ...value, [sourceId]: true })); setSubmissionErrors((value) => { const next = { ...value }; delete next[sourceId]; return next; }); }, onSuccess: (job, sourceId) => {rememberActiveExternalJob(`sources-${sourceId}`,sourceId,job.job_id);setJobs((value) => ({ ...value, [sourceId]: job }));}, onError: (error, sourceId) => setSubmissionErrors((value) => ({ ...value, [sourceId]: error instanceof TypeError ? t('disconnected') : t('requestRejected') })), onSettled: (_data, _error, sourceId) => setPending((value) => ({ ...value, [sourceId]: false })) });
  const startAll = useMutation({ mutationFn: api.startAllExternalSources, onMutate: () => setAllError(''), onSuccess: job=>{rememberActiveExternalJob('sources-all','all-enabled',job.job_id);setAllJob(job);}, onError: (error) => { if (error instanceof TypeError) setAllError(t('disconnected')); else if (error instanceof ApiError && error.status === 409) setAllError(t('aggregateActive')); else if (error instanceof ApiError && error.status === 401) setAllError(t('sessionExpired')); else if (error instanceof ApiError && error.status === 403) setAllError(t('runAllForbidden')); else if (error instanceof ApiError && error.status === 408) setAllError(t('requestTimeout')); else setAllError(t('runAllRejected')); } });
  const importJob=useMutation({mutationFn:({jobId}:{sourceId:string;jobId:string})=>api.importExternalJob(jobId),onSuccess:(value,request)=>{setCentralRuns(current=>({...current,[request.sourceId]:value.run_id}));setImportErrors(current=>{const next={...current};delete next[request.sourceId];return next});void queryClient.invalidateQueries({queryKey:['external','accepted-records']});void queryClient.invalidateQueries({queryKey:externalQueryKeys.reviews()});void queryClient.invalidateQueries({queryKey:externalQueryKeys.processingRun(value.run_id)});void queryClient.invalidateQueries({queryKey:['center-summary'],exact:true});void queryClient.invalidateQueries({queryKey:['dashboard-summary'],exact:true});void queryClient.invalidateQueries({queryKey:['indicator-summary'],exact:true});},onError:(error,request)=>setImportErrors(current=>({...current,[request.sourceId]:error instanceof ApiError&&error.status===502?t('importProcessingFailed'):error instanceof ApiError&&error.status===409?t('importNotReady'):t('externalControlUnavailable')}))});
  const manage=useMutation({mutationFn:async({source,action}:{source:Source;action:'enable'|'disable'|'delete'})=>{if(action==='enable')await api.enableExternalSource(source.source_id);else if(action==='disable')await api.disableExternalSource(source.source_id);else await api.deleteExternalSource(source.source_id);},onSuccess:()=>void query.refetch()});
  const sources = query.data || [];
  useEffect(()=>{let cancelled=false;const stored=loadActiveExternalJobs().filter(item=>item.context==='sources-all'||item.context.startsWith('sources-'));void Promise.all(stored.map(async item=>{try{const recovered=await api.externalJob(item.jobId);if(cancelled)return;if(TERMINAL_STATES.includes(recovered.state)){forgetActiveExternalJob(item.context,recovered.job_id);void queryClient.invalidateQueries({queryKey:externalQueryKeys.reviews()});}if(item.context==='sources-all'){setAllJob(recovered);if(['completed','partial'].includes(recovered.state)&&!importedJobs.has(recovered.job_id)){importedJobs.add(recovered.job_id);importJob.mutate({sourceId:'all-enabled',jobId:recovered.job_id});}}else{setJobs(current=>({...current,[item.sourceId]:recovered}));if(['completed','partial'].includes(recovered.state)&&!importedJobs.has(recovered.job_id)){importedJobs.add(recovered.job_id);importJob.mutate({sourceId:item.sourceId,jobId:recovered.job_id});}}}catch{/* job history remains available for explicit recovery */}}));return()=>{cancelled=true};},[]);
  const types = [...new Set(sources.map((source) => source.source_type))];
  const filtered = useMemo(() => sources.filter((source) => `${source.name} ${source.source_id}`.toLowerCase().includes(search.toLowerCase()) && (status === 'all' || source.status === status) && (type === 'all' || source.source_type === type)), [sources, search, status, type]);
  function run(source: Source) {
    if (!['enabled','ready'].includes(source.status) || pending[source.source_id] || (jobs[source.source_id] && !TERMINAL_STATES.includes(jobs[source.source_id].state))) return;
    if (window.confirm(t('confirmRunSource',{name:source.name}))) start.mutate(source.source_id);
  }
  function updateJob(sourceId: string, job: ExternalJob) { setJobs((value) => {const current=value[sourceId];return !current||current.job_id!==job.job_id?value:{...value,[sourceId]:acceptExternalJobUpdate(current,job)}}); if(TERMINAL_STATES.includes(job.state)){forgetActiveExternalJob(`sources-${sourceId}`,job.job_id);void queryClient.invalidateQueries({queryKey:externalQueryKeys.reviews()});} if(['completed','partial'].includes(job.state)&&!importedJobs.has(job.job_id)){importedJobs.add(job.job_id);importJob.mutate({sourceId,jobId:job.job_id});} }
  const allActive = Boolean(allJob && !TERMINAL_STATES.includes(allJob.state));
  function runAll() { if (startAll.isPending || allActive) return; if (window.confirm(t('confirmRunAll'))) startAll.mutate(); }
  function manageSource(source:Source,action:'enable'|'disable'|'delete'){if(manage.isPending)return;if(window.confirm(t('confirmManageSource',{action:t(action),name:source.name})))manage.mutate({source,action});}

  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">{t('sourcesEyebrow')}</span><h2>{t('external')}</h2><p>{t('sourcesDescription')}</p></div><span className="count-label">{t('sourcesCount',{count:number(filtered.length)})}</span></div>
    {can('analyst') && <section className="run-all-panel" aria-label={t('runAll')}><button className="button" type="button" disabled={startAll.isPending || allActive} onClick={runAll}>{startAll.isPending ? t('submitting') : t('runAllEnabled')}</button><p className="muted-text">{t('runAllHint')}</p>{allError && <div className="job-panel error-panel" role="alert">{allError}</div>}{allJob && <JobMonitor sourceId="all-enabled" job={allJob} onUpdate={(_id, next) => {setAllJob(current=>current?acceptExternalJobUpdate(current,next):next);if(TERMINAL_STATES.includes(next.state)){forgetActiveExternalJob('sources-all',next.job_id);void queryClient.invalidateQueries({queryKey:externalQueryKeys.reviews()});}if(['completed','partial'].includes(next.state)&&!importedJobs.has(next.job_id)){importedJobs.add(next.job_id);importJob.mutate({sourceId:'all-enabled',jobId:next.job_id});}}} />}</section>}
    <div className="filters"><label className="search-wrap"><span className="sr-only">{t('search')}</span><input placeholder={t('searchSource')} value={search} onChange={(event) => setSearch(event.target.value)} /></label><select aria-label={t('filterStatus')} value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">{t('allStates')}</option><option value="ready">{t('ready')}</option><option value="enabled">{t('enabled')}</option><option value="requires_configuration">{t('requiresConfiguration')}</option><option value="temporarily_unavailable">{t('temporarilyUnavailable')}</option><option value="unsupported_configuration">{t('unsupportedConfiguration')}</option><option value="disabled">{t('disabled')}</option><option value="pending_review">{t('pendingReview')}</option></select><select aria-label={t('filterType')} value={type} onChange={(event) => setType(event.target.value)}><option value="all">{t('allTypes')}</option>{types.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>
    {query.isLoading && <LoadingState label={t('loadingSources')} />}{query.isError && <ErrorState onRetry={() => void query.refetch()} />}{!query.isLoading && !query.isError && sources.length === 0 && <EmptyState label={t('noSources')} />}{!query.isLoading && !query.isError && sources.length > 0 && filtered.length === 0 && <EmptyState label={t('noFilteredSources')} />}
    {filtered.length > 0 && <div className="table-shell"><table><thead><tr><th>{t('source')}</th><th>{t('type')}</th><th>{t('status')}</th><th>{t('safeData')}</th>{can('analyst') && <th>{t('action')}</th>}</tr></thead><tbody>{filtered.map((source) => <SourceRows key={source.source_id} source={source} canRun={can('analyst')} pending={Boolean(pending[source.source_id])} job={jobs[source.source_id]} submissionError={submissionErrors[source.source_id]} importError={importErrors[source.source_id]} onRun={run} onUpdate={updateJob} onManage={manageSource} />)}</tbody></table>{Object.entries(centralRuns).map(([sourceId,runId])=><div className="job-panel" role="status" key={sourceId}><strong>{t('centralImportComplete')}</strong><span><Link to="/accepted-records">{t('acceptedRecords')}</Link> · <Link to="/processing-center">{t('processingCenter')}</Link></span>{can('analyst')&&<details><summary>{t('technicalDetails')}</summary><code dir="ltr">{sourceId} · {runId}</code></details>}</div>)}</div>}
  </section>;
}
