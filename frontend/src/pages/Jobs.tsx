import { useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, ApiError, type JobState, type JobSummary } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { JOB_POLL_INTERVAL_MS, JOB_POLL_MAX_MS, TERMINAL_STATES } from './Sources';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';

const labels: Record<JobState, TranslationKey> = { queued: 'queued', running: 'processing', completed: 'completed', partial: 'partial', failed: 'failed', cancellation_requested: 'cancellation_requested', cancelled: 'cancelled' };
const active = (state: JobState) => !TERMINAL_STATES.includes(state);

export function Jobs() {
  const {t,number,dateTime}=useI18n();
  const { can } = useAuth(); const [search, setSearch] = useState(''); const [state, setState] = useState('all'); const [selected, setSelected] = useState<JobSummary>(); const [started, setStarted] = useState(0);
  const history = useQuery({ queryKey: ['external-jobs'], queryFn: api.externalJobs, retry: false });
  const detail = useQuery({ queryKey: ['external-job', selected?.job_id], queryFn: () => api.externalJob(selected!.job_id), enabled: Boolean(selected && active(selected.state) && Date.now() - started < JOB_POLL_MAX_MS), refetchInterval: (q) => q.state.data && TERMINAL_STATES.includes(q.state.data.state) ? false : JOB_POLL_INTERVAL_MS, retry: false });
  const cancel = useMutation({ mutationFn: api.cancelExternalJob, onSuccess: (job) => { setSelected((old) => old ? { ...old, state: job.state, updated_at: job.updated_at } : old); void history.refetch(); } });
  const jobs = history.data?.jobs || []; const filtered = useMemo(() => jobs.filter((j) => (state === 'all' || j.state === state) && [j.job_id, j.source_id].some((v) => v?.toLowerCase().includes(search.toLowerCase()))), [jobs, state, search]);
  const choose = (job: JobSummary) => { setSelected(job); setStarted(Date.now()); };
  const requestCancel = (job: JobSummary) => { if (!cancel.isPending && window.confirm(t('confirmCancel'))) cancel.mutate(job.job_id); };
  const retry = () => void history.refetch();
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">{t('jobs')} / 03</span><h2>{t('jobHistory')}</h2><p>{t('jobHistoryDescription')}</p></div><span className="count-label">{t('jobsCount',{count:number(filtered.length)})}</span></div>
    <div className="filters"><label className="search-wrap"><span className="sr-only">{t('search')}</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t('searchJob')} /></label><select aria-label={t('filterJobState')} value={state} onChange={(e) => setState(e.target.value)}><option value="all">{t('allStates')}</option>{Object.entries(labels).map(([v, l]) => <option key={v} value={v}>{t(l)}</option>)}</select></div>
    {history.isLoading && <LoadingState label={t('loadingJobs')} />}{history.isError && (history.error instanceof ApiError && history.error.status === 401 ? <div className="state-panel error-panel" role="alert">{t('sessionExpired')}</div> : history.error instanceof TypeError ? <div className="state-panel error-panel" role="alert"><strong>{t('disconnected')}</strong><button className="button button-secondary" onClick={retry}>{t('retry')}</button></div> : <ErrorState onRetry={retry} />)}
    {!history.isLoading && !history.isError && jobs.length === 0 && <EmptyState label={t('noJobs')} />}{jobs.length > 0 && filtered.length === 0 && <EmptyState label={t('noMatches')} />}
    {filtered.length > 0 && <div className="table-shell"><table><thead><tr><th>{t('job')}</th><th>{t('source')}</th><th>{t('status')}</th><th>{t('lastUpdated')}</th><th>{t('counters')}</th><th>{t('action')}</th></tr></thead><tbody>{filtered.map((j) => <tr key={j.job_id}><td><code>{j.job_id}</code></td><td>{j.source_id || t('general')}</td><td><StatusBadge status={t(labels[j.state])} /></td><td>{dateTime(j.updated_at)}</td><td>{number(Object.values(j.counts).reduce((a, b) => a + (b || 0), 0))}</td><td><button className="button button-secondary" onClick={() => choose(j)}>{t('follow')}</button>{can('analyst') && active(j.state) && <button className="button button-danger" disabled={cancel.isPending || j.state === 'cancellation_requested'} onClick={() => requestCancel(j)}>{t('cancel')}</button>}</td></tr>)}</tbody></table></div>}
    {selected && <div className="safe-summary" aria-live="polite"><strong>{t('follow')} {selected.job_id}</strong>{detail.isFetching && <span> {t('updating')}</span>}{detail.data && <p>{t('status')}: {t(labels[detail.data.state])}</p>}{detail.isError && <p className="job-error">{t('jobUpdateFailed')} <button className="button button-secondary" onClick={() => { setStarted(Date.now()); void detail.refetch(); }}>{t('retry')}</button></p>}{active(selected.state) && Date.now() - started >= JOB_POLL_MAX_MS && <p className="job-error">{t('pollTimeout')}</p>}</div>}
  </section>;
}
