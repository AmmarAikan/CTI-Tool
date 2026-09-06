import { type FormEvent, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Navigate } from 'react-router-dom';
import { api, type ExternalJob } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { LoadingState } from '../components/States';
import { JobMonitor, TERMINAL_STATES } from './Sources';
import './Sources.css';
import './Manual.css';

const MANUAL_JOB_KEY = 'manual-url';

function validUrl(value: string) {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && !parsed.username && !parsed.password;
  } catch { return false; }
}

export function Manual() {
  const { can, loading } = useAuth();
  const [url, setUrl] = useState('');
  const [job, setJob] = useState<ExternalJob>();
  const [validationError, setValidationError] = useState('');
  const start = useMutation({
    mutationFn: api.startManualUrlJob,
    onSuccess: (nextJob) => { setJob(nextJob); setUrl(''); },
  });

  if (loading) return <LoadingState label="جار التحقق من الصلاحيات..." />;
  if (!can('analyst')) return <Navigate to="/" replace />;

  const active = Boolean(job && !TERMINAL_STATES.includes(job.state));
  const busy = start.isPending || active;
  function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    const value = url.trim();
    if (!validUrl(value)) { setValidationError('أدخل رابط HTTP أو HTTPS صالحًا دون بيانات اعتماد.'); return; }
    setValidationError('');
    if (!window.confirm('سيؤدي التأكيد إلى تسجيل الرابط ومعالجته، وقد تُصدَّر نتائجه. هذه العملية ليست معاينة. هل تريد المتابعة؟')) return;
    start.mutate(value);
  }
  function updateJob(_key: string, nextJob: ExternalJob) { setJob(nextJob); }

  return <section className="page-section manual-page"><div className="section-heading"><div><span className="eyebrow">المصادر / 03</span><h2>إدخال رابط يدوي</h2><p>إرسال رابط واحد إلى مسار المعالجة الحالي.</p></div></div>
    <div className="manual-warning" role="note"><strong>تنبيه قبل الإرسال</strong><span>التأكيد سيسجّل الرابط ويعالجه، وقد يصدّر النتائج. هذه ليست معاينة ولا تتضمن اعتمادًا أو تجاهلًا لاحقًا.</span></div>
    <form className="manual-form" onSubmit={submit} noValidate>
      <label htmlFor="manual-url">رابط HTTP أو HTTPS</label>
      <input id="manual-url" name="url" type="url" inputMode="url" dir="ltr" autoComplete="url" placeholder="https://example.org/report" value={url} disabled={busy} aria-invalid={Boolean(validationError)} aria-describedby="manual-url-help manual-url-error" onChange={(event) => { setUrl(event.target.value); setValidationError(''); }} />
      <span id="manual-url-help" className="muted-text">يُقبل رابط واحد فقط. تطبّق الخدمة ضوابط التحقق والحماية عند الإرسال.</span>
      {validationError && <span id="manual-url-error" className="field-error" role="alert">{validationError}</span>}
      <button className="button" type="submit" disabled={busy || !url.trim()}>{start.isPending ? 'جار الإرسال...' : active ? 'جار متابعة الوظيفة...' : 'تسجيل الرابط وتشغيله'}</button>
    </form>
    {start.isError && <div className="job-panel error-panel" role="alert"><strong>تعذر إرسال الرابط</strong><span>{start.error instanceof TypeError ? 'الخدمة المركزية غير متصلة.' : 'لم تقبل الخدمة طلب الإرسال.'}</span><button className="button button-secondary" type="button" disabled={busy} onClick={() => start.reset()}>إغلاق الرسالة</button></div>}
    {job && <JobMonitor sourceId={MANUAL_JOB_KEY} job={job} onUpdate={updateJob} />}
  </section>;
}
