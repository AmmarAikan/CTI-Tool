import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, type ExternalJob, type JobState, type Source } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import './Sources.css';

export const JOB_POLL_INTERVAL_MS = 2_000;
export const JOB_POLL_MAX_MS = 120_000;
const TERMINAL_STATES: JobState[] = ['completed', 'partial', 'failed', 'cancelled'];
const STATE_LABELS: Record<JobState, string> = { queued: 'في الانتظار', running: 'قيد التشغيل', completed: 'مكتملة', partial: 'مكتملة جزئيًا', failed: 'فشلت', cancellation_requested: 'جار الإلغاء', cancelled: 'ملغاة' };
const COUNT_LABELS = { accepted_records: 'مقبولة', review_records: 'للمراجعة', rejected_records: 'مرفوضة', skipped_records: 'متخطاة', error_count: 'أخطاء' } as const;

function JobPanel({ job, pollingError, timedOut, onRefresh }: { job?: ExternalJob; pollingError: boolean; timedOut: boolean; onRefresh: () => void }) {
  if (timedOut) return <div className="job-panel error-panel" role="alert"><strong>انتهت مهلة متابعة الوظيفة</strong><span>يمكن طلب تحديث الحالة يدويًا.</span><button className="button button-secondary" onClick={onRefresh}>تحديث الحالة</button></div>;
  if (pollingError) return <div className="job-panel error-panel" role="alert"><strong>تعذر تحديث حالة الوظيفة</strong><span>تحقق من الاتصال بالخدمة المركزية.</span><button className="button button-secondary" onClick={onRefresh}>إعادة المحاولة</button></div>;
  if (!job) return null;
  return <div className="job-panel" role="status" aria-live="polite"><div><strong>حالة آخر تشغيل: {STATE_LABELS[job.state]}</strong><StatusBadge status={job.state} /></div>{Object.entries(job.counts).length > 0 && <dl className="job-counts">{Object.entries(job.counts).map(([key, value]) => <div key={key}><dt>{COUNT_LABELS[key as keyof typeof COUNT_LABELS]}</dt><dd>{value}</dd></div>)}</dl>}{job.error && <span className="job-error">{job.error}</span>}{TERMINAL_STATES.includes(job.state) && <button className="button button-secondary" onClick={onRefresh}>تحديث الحالة</button>}</div>;
}

function RunButton({ source, busy, onRun }: { source: Source; busy: boolean; onRun: (source: Source) => void }) {
  const disabled = source.status !== 'enabled' || busy;
  return <button className="button button-secondary" disabled={disabled} aria-label={`تشغيل ${source.name}`} title={source.status !== 'enabled' ? 'المصدر غير مفعّل' : undefined} onClick={() => onRun(source)}>{busy ? 'جار الإرسال...' : 'تشغيل'}</button>;
}

function JobMonitor({ sourceId, job, onUpdate }: { sourceId: string; job: ExternalJob; onUpdate: (sourceId: string, job: ExternalJob) => void }) {
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
  const active = Boolean(job && !TERMINAL_STATES.includes(job.state));
  return <>
    <tr><td><strong>{source.name}</strong><code dir="ltr">{source.source_id}</code></td><td><span className="type-label">{source.source_type}</span></td><td><StatusBadge status={source.status} /></td><td>{Object.keys(source.metadata || {}).length > 0 ? <span className="safe-label">متاحة</span> : <span className="muted-text">لا توجد</span>}</td>{canRun && <td><RunButton source={source} busy={pending || active} onRun={onRun} /></td>}</tr>
    {(job || submissionError) && <tr className="job-detail-row"><td colSpan={canRun ? 5 : 4}>{submissionError ? <div className="job-panel error-panel" role="alert"><strong>تعذر بدء تشغيل المصدر</strong><span>{submissionError}</span></div> : job && <JobMonitor sourceId={source.source_id} job={job} onUpdate={onUpdate} />}</td></tr>}
  </>;
}

export function Sources() {
  const { can } = useAuth();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [type, setType] = useState('all');
  const [jobs, setJobs] = useState<Record<string, ExternalJob>>({});
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [submissionErrors, setSubmissionErrors] = useState<Record<string, string>>({});
  const query = useQuery({ queryKey: ['external-sources'], queryFn: api.externalSources, retry: false });
  const start = useMutation({ mutationFn: (sourceId: string) => api.startExternalSourceJob(sourceId), onMutate: (sourceId) => { setPending((value) => ({ ...value, [sourceId]: true })); setSubmissionErrors((value) => { const next = { ...value }; delete next[sourceId]; return next; }); }, onSuccess: (job, sourceId) => setJobs((value) => ({ ...value, [sourceId]: job })), onError: (error, sourceId) => setSubmissionErrors((value) => ({ ...value, [sourceId]: error instanceof TypeError ? 'الخدمة المركزية غير متصلة.' : 'لم تقبل الخدمة طلب التشغيل.' })), onSettled: (_data, _error, sourceId) => setPending((value) => ({ ...value, [sourceId]: false })) });
  const sources = query.data || [];
  const types = [...new Set(sources.map((source) => source.source_type))];
  const filtered = useMemo(() => sources.filter((source) => `${source.name} ${source.source_id}`.toLowerCase().includes(search.toLowerCase()) && (status === 'all' || source.status === status) && (type === 'all' || source.source_type === type)), [sources, search, status, type]);
  function run(source: Source) {
    if (source.status !== 'enabled' || pending[source.source_id] || (jobs[source.source_id] && !TERMINAL_STATES.includes(jobs[source.source_id].state))) return;
    if (window.confirm(`هل تريد تشغيل المصدر «${source.name}»؟`)) start.mutate(source.source_id);
  }
  function updateJob(sourceId: string, job: ExternalJob) { setJobs((value) => value[sourceId] === job ? value : { ...value, [sourceId]: job }); }

  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">المصادر / 02</span><h2>المصادر الخارجية</h2><p>المصادر المسجلة وحالتها التشغيلية الآمنة.</p></div><span className="count-label">{filtered.length} مصدر</span></div>
    <div className="filters"><label className="search-wrap"><span className="sr-only">بحث</span><input placeholder="بحث بالاسم أو المعرّف" value={search} onChange={(event) => setSearch(event.target.value)} /></label><select aria-label="تصفية الحالة" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">كل الحالات</option><option value="enabled">مفعّل</option><option value="disabled">معطّل</option><option value="pending_review">قيد المراجعة</option></select><select aria-label="تصفية النوع" value={type} onChange={(event) => setType(event.target.value)}><option value="all">كل الأنواع</option>{types.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>
    {query.isLoading && <LoadingState label="جار تحميل المصادر..." />}{query.isError && <ErrorState onRetry={() => void query.refetch()} />}{!query.isLoading && !query.isError && sources.length === 0 && <EmptyState label="لا توجد مصادر مسجلة حاليًا." />}{!query.isLoading && !query.isError && sources.length > 0 && filtered.length === 0 && <EmptyState label="لا توجد نتائج مطابقة للفلاتر الحالية." />}
    {filtered.length > 0 && <div className="table-shell"><table><thead><tr><th>المصدر</th><th>النوع</th><th>الحالة</th><th>بيانات آمنة</th>{can('analyst') && <th>إجراء</th>}</tr></thead><tbody>{filtered.map((source) => <SourceRows key={source.source_id} source={source} canRun={can('analyst')} pending={Boolean(pending[source.source_id])} job={jobs[source.source_id]} submissionError={submissionErrors[source.source_id]} onRun={run} onUpdate={updateJob} />)}</tbody></table></div>}
  </section>;
}
