import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, ApiError, type ExternalJob, type JobState, type Source } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { useI18n } from '../i18n/I18nContext';
import './Sources.css';

export const JOB_POLL_INTERVAL_MS = 2_000;
export const JOB_POLL_MAX_MS = 120_000;
export const TERMINAL_STATES: JobState[] = ['completed', 'partial', 'failed', 'cancelled'];
const COUNT_LABELS = { accepted_records: 'accepted', review_records: 'forReview', rejected_records: 'rejected', skipped_records: 'skipped', error_count: 'errors' } as const;

function JobPanel({ job, pollingError, timedOut, onRefresh }: { job?: ExternalJob; pollingError: boolean; timedOut: boolean; onRefresh: () => void }) {
  const {t,number}=useI18n();
  if (timedOut) return <div className="job-panel error-panel" role="alert"><strong>{t('jobPollingTimeout')}</strong><span>{t('manualRefreshHint')}</span><button className="button button-secondary" onClick={onRefresh}>{t('refreshStatus')}</button></div>;
  if (pollingError) return <div className="job-panel error-panel" role="alert"><strong>{t('jobPollingFailed')}</strong><span>{t('connectionHint')}</span><button className="button button-secondary" onClick={onRefresh}>{t('retry')}</button></div>;
  if (!job) return null;
  return <div className="job-panel" role="status" aria-live="polite"><div><strong>{t('status')}</strong><StatusBadge status={job.state} /></div>{Object.entries(job.counts).length > 0 && <dl className="job-counts">{Object.entries(job.counts).map(([key, value]) => <div key={key}><dt>{t(COUNT_LABELS[key as keyof typeof COUNT_LABELS])}</dt><dd>{value}</dd></div>)}</dl>}{Object.keys(job.sources).length > 0 && <div className="source-result-list">{Object.entries(job.sources).map(([id, value]) => <div key={id}><code>{id}</code><span>{value.status}</span><small>{t('recordCount',{count:number(Object.values(value.counts).reduce((sum,count)=>sum+(count||0),0))})}</small></div>)}</div>}{job.error && <span className="job-error">{job.error}</span>}{TERMINAL_STATES.includes(job.state) && <button className="button button-secondary" onClick={onRefresh}>{t('refreshStatus')}</button>}</div>;
}

function RunButton({ source, busy, onRun }: { source: Source; busy: boolean; onRun: (source: Source) => void }) {
  const {t}=useI18n();
  const disabled = source.status !== 'enabled' || busy;
  return <button className="button button-secondary" disabled={disabled} aria-label={t('runSource',{name:source.name})} title={source.status !== 'enabled' ? t('sourceDisabled') : undefined} onClick={() => onRun(source)}>{busy ? t('submitting') : t('run')}</button>;
}

export function JobMonitor({ sourceId, job, onUpdate }: { sourceId: string; job: ExternalJob; onUpdate: (sourceId: string, job: ExternalJob) => void }) {
  const [timedOut, setTimedOut] = useState(false);
  const terminal = TERMINAL_STATES.includes(job.state);
  const query = useQuery({ queryKey: ['external-job', job.job_id], queryFn: () => api.externalJob(job.job_id), enabled: !terminal && !timedOut, retry: false, refetchInterval: JOB_POLL_INTERVAL_MS });
  useEffect(() => { if (query.data) onUpdate(sourceId, query.data); }, [onUpdate, query.data, sourceId]);
  useEffect(() => {
    if (terminal || timedOut) return;
    const timer = window.setTimeout(() => setTimedOut(true), JOB_POLL_MAX_MS);
    return () => window.clearTimeout(timer);
  }, [job.job_id, terminal, timedOut]);
  function refresh() { setTimedOut(false); void query.refetch(); }
  return <JobPanel job={job} pollingError={query.isError} timedOut={timedOut} onRefresh={refresh} />;
}

function SourceRows({ source, canRun, pending, job, submissionError, onRun, onUpdate }: { source: Source; canRun: boolean; pending: boolean; job?: ExternalJob; submissionError?: string; onRun: (source: Source) => void; onUpdate: (sourceId: string, job: ExternalJob) => void }) {
  const {t}=useI18n();
  const active = Boolean(job && !TERMINAL_STATES.includes(job.state));
  return <>
    <tr><td><strong>{source.name}</strong><code dir="ltr">{source.source_id}</code></td><td><span className="type-label">{source.source_type}</span></td><td><StatusBadge status={source.status} /></td><td>{Object.keys(source.metadata || {}).length > 0 ? <span className="safe-label">{t('available')}</span> : <span className="muted-text">{t('none')}</span>}</td>{canRun && <td><RunButton source={source} busy={pending || active} onRun={onRun} /></td>}</tr>
    {(job || submissionError) && <tr className="job-detail-row"><td colSpan={canRun ? 5 : 4}>{submissionError ? <div className="job-panel error-panel" role="alert"><strong>{t('startSourceFailed')}</strong><span>{submissionError}</span></div> : job && <JobMonitor sourceId={source.source_id} job={job} onUpdate={onUpdate} />}</td></tr>}
  </>;
}

export function Sources() {
  const { can } = useAuth();
  const {t,number}=useI18n();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [type, setType] = useState('all');
  const [jobs, setJobs] = useState<Record<string, ExternalJob>>({});
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [submissionErrors, setSubmissionErrors] = useState<Record<string, string>>({});
  const [allJob, setAllJob] = useState<ExternalJob>();
  const [allError, setAllError] = useState('');
  const query = useQuery({ queryKey: ['external-sources'], queryFn: api.externalSources, retry: false });
  const start = useMutation({ mutationFn: (sourceId: string) => api.startExternalSourceJob(sourceId), onMutate: (sourceId) => { setPending((value) => ({ ...value, [sourceId]: true })); setSubmissionErrors((value) => { const next = { ...value }; delete next[sourceId]; return next; }); }, onSuccess: (job, sourceId) => setJobs((value) => ({ ...value, [sourceId]: job })), onError: (error, sourceId) => setSubmissionErrors((value) => ({ ...value, [sourceId]: error instanceof TypeError ? t('disconnected') : t('requestRejected') })), onSettled: (_data, _error, sourceId) => setPending((value) => ({ ...value, [sourceId]: false })) });
  const startAll = useMutation({ mutationFn: api.startAllExternalSources, onMutate: () => setAllError(''), onSuccess: setAllJob, onError: (error) => { if (error instanceof TypeError) setAllError(t('disconnected')); else if (error instanceof ApiError && error.status === 409) setAllError(t('aggregateActive')); else if (error instanceof ApiError && error.status === 401) setAllError(t('sessionExpired')); else if (error instanceof ApiError && error.status === 403) setAllError(t('runAllForbidden')); else if (error instanceof ApiError && error.status === 408) setAllError(t('requestTimeout')); else setAllError(t('runAllRejected')); } });
  const sources = query.data || [];
  const types = [...new Set(sources.map((source) => source.source_type))];
  const filtered = useMemo(() => sources.filter((source) => `${source.name} ${source.source_id}`.toLowerCase().includes(search.toLowerCase()) && (status === 'all' || source.status === status) && (type === 'all' || source.source_type === type)), [sources, search, status, type]);
  function run(source: Source) {
    if (source.status !== 'enabled' || pending[source.source_id] || (jobs[source.source_id] && !TERMINAL_STATES.includes(jobs[source.source_id].state))) return;
    if (window.confirm(t('confirmRunSource',{name:source.name}))) start.mutate(source.source_id);
  }
  function updateJob(sourceId: string, job: ExternalJob) { setJobs((value) => value[sourceId] === job ? value : { ...value, [sourceId]: job }); }
  const allActive = Boolean(allJob && !TERMINAL_STATES.includes(allJob.state));
  function runAll() { if (startAll.isPending || allActive) return; if (window.confirm(t('confirmRunAll'))) startAll.mutate(); }

  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">{t('sourcesEyebrow')}</span><h2>{t('external')}</h2><p>{t('sourcesDescription')}</p></div><span className="count-label">{t('sourcesCount',{count:number(filtered.length)})}</span></div>
    {can('analyst') && <section className="run-all-panel" aria-label={t('runAll')}><button className="button" type="button" disabled={startAll.isPending || allActive} onClick={runAll}>{startAll.isPending ? t('submitting') : t('runAllEnabled')}</button><p className="muted-text">{t('runAllHint')}</p>{allError && <div className="job-panel error-panel" role="alert">{allError}</div>}{allJob && <JobMonitor sourceId="all-enabled" job={allJob} onUpdate={(_id, job) => setAllJob(job)} />}</section>}
    <div className="filters"><label className="search-wrap"><span className="sr-only">{t('search')}</span><input placeholder={t('searchSource')} value={search} onChange={(event) => setSearch(event.target.value)} /></label><select aria-label={t('filterStatus')} value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">{t('allStates')}</option><option value="enabled">{t('enabled')}</option><option value="disabled">{t('disabled')}</option><option value="pending_review">{t('pendingReview')}</option></select><select aria-label={t('filterType')} value={type} onChange={(event) => setType(event.target.value)}><option value="all">{t('allTypes')}</option>{types.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>
    {query.isLoading && <LoadingState label={t('loadingSources')} />}{query.isError && <ErrorState onRetry={() => void query.refetch()} />}{!query.isLoading && !query.isError && sources.length === 0 && <EmptyState label={t('noSources')} />}{!query.isLoading && !query.isError && sources.length > 0 && filtered.length === 0 && <EmptyState label={t('noFilteredSources')} />}
    {filtered.length > 0 && <div className="table-shell"><table><thead><tr><th>{t('source')}</th><th>{t('type')}</th><th>{t('status')}</th><th>{t('safeData')}</th>{can('analyst') && <th>{t('action')}</th>}</tr></thead><tbody>{filtered.map((source) => <SourceRows key={source.source_id} source={source} canRun={can('analyst')} pending={Boolean(pending[source.source_id])} job={jobs[source.source_id]} submissionError={submissionErrors[source.source_id]} onRun={run} onUpdate={updateJob} />)}</tbody></table></div>}
  </section>;
}
