import { useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, ApiError, type JobState, type JobSummary } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { JOB_POLL_INTERVAL_MS, JOB_POLL_MAX_MS, TERMINAL_STATES } from './Sources';

const labels: Record<JobState, string> = { queued: 'في الانتظار', running: 'قيد التشغيل', completed: 'مكتملة', partial: 'جزئية', failed: 'فشلت', cancellation_requested: 'جار الإلغاء', cancelled: 'ملغاة' };
const active = (state: JobState) => !TERMINAL_STATES.includes(state);

export function Jobs() {
  const { can } = useAuth(); const [search, setSearch] = useState(''); const [state, setState] = useState('all'); const [selected, setSelected] = useState<JobSummary>(); const [started, setStarted] = useState(0);
  const history = useQuery({ queryKey: ['external-jobs'], queryFn: api.externalJobs, retry: false });
  const detail = useQuery({ queryKey: ['external-job', selected?.job_id], queryFn: () => api.externalJob(selected!.job_id), enabled: Boolean(selected && active(selected.state) && Date.now() - started < JOB_POLL_MAX_MS), refetchInterval: (q) => q.state.data && TERMINAL_STATES.includes(q.state.data.state) ? false : JOB_POLL_INTERVAL_MS, retry: false });
  const cancel = useMutation({ mutationFn: api.cancelExternalJob, onSuccess: (job) => { setSelected((old) => old ? { ...old, state: job.state, updated_at: job.updated_at } : old); void history.refetch(); } });
  const jobs = history.data?.jobs || []; const filtered = useMemo(() => jobs.filter((j) => (state === 'all' || j.state === state) && [j.job_id, j.source_id].some((v) => v?.toLowerCase().includes(search.toLowerCase()))), [jobs, state, search]);
  const choose = (job: JobSummary) => { setSelected(job); setStarted(Date.now()); };
  const requestCancel = (job: JobSummary) => { if (!cancel.isPending && window.confirm('هل تريد طلب إلغاء هذه الوظيفة؟')) cancel.mutate(job.job_id); };
  const retry = () => void history.refetch();
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">الوظائف / 03</span><h2>سجل الوظائف</h2><p>آخر 50 وظيفة متاحة في ذاكرة العملية، مرتبة من الأحدث. لا يستمر السجل بعد إعادة التشغيل.</p></div><span className="count-label">{filtered.length} وظيفة</span></div>
    <div className="filters"><label className="search-wrap"><span className="sr-only">بحث</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="بحث بالمعرّف أو المصدر" /></label><select aria-label="تصفية حالة الوظيفة" value={state} onChange={(e) => setState(e.target.value)}><option value="all">كل الحالات</option>{Object.entries(labels).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
    {history.isLoading && <LoadingState label="جار تحميل سجل الوظائف..." />}{history.isError && (history.error instanceof ApiError && history.error.status === 401 ? <div className="state-panel error-panel" role="alert">انتهت جلسة الدخول.</div> : history.error instanceof TypeError ? <div className="state-panel error-panel" role="alert"><strong>الخدمة المركزية غير متصلة</strong><button className="button button-secondary" onClick={retry}>إعادة المحاولة</button></div> : <ErrorState onRetry={retry} />)}
    {!history.isLoading && !history.isError && jobs.length === 0 && <EmptyState label="لا توجد وظائف متاحة في ذاكرة العملية." />}{jobs.length > 0 && filtered.length === 0 && <EmptyState label="لا توجد نتائج مطابقة." />}
    {filtered.length > 0 && <div className="table-shell"><table><thead><tr><th>الوظيفة</th><th>المصدر</th><th>الحالة</th><th>آخر تحديث</th><th>العدادات</th><th>الإجراء</th></tr></thead><tbody>{filtered.map((j) => <tr key={j.job_id}><td><code>{j.job_id}</code></td><td>{j.source_id || 'عام'}</td><td><StatusBadge status={labels[j.state]} /></td><td>{new Date(j.updated_at).toLocaleString('ar')}</td><td>{Object.values(j.counts).reduce((a, b) => a + (b || 0), 0).toLocaleString('ar')}</td><td><button className="button button-secondary" onClick={() => choose(j)}>متابعة</button>{can('analyst') && active(j.state) && <button className="button button-danger" disabled={cancel.isPending || j.state === 'cancellation_requested'} onClick={() => requestCancel(j)}>إلغاء</button>}</td></tr>)}</tbody></table></div>}
    {selected && <div className="safe-summary" aria-live="polite"><strong>متابعة {selected.job_id}</strong>{detail.isFetching && <span> جار التحديث…</span>}{detail.data && <p>الحالة: {labels[detail.data.state]}</p>}{detail.isError && <p className="job-error">تعذر تحديث الوظيفة. <button className="button button-secondary" onClick={() => { setStarted(Date.now()); void detail.refetch(); }}>إعادة المحاولة</button></p>}{active(selected.state) && Date.now() - started >= JOB_POLL_MAX_MS && <p className="job-error">انتهت مهلة المتابعة التلقائية.</p>}</div>}
  </section>;
}
