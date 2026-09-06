import { type FormEvent, useEffect, useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Navigate } from 'react-router-dom';
import { api, ApiError, type ExternalJob, type ManualPreview } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { LoadingState } from '../components/States';
import { JobMonitor, TERMINAL_STATES } from './Sources';
import './Sources.css';
import './Manual.css';

const REASONS = { not_relevant: 'غير ذي صلة', duplicate: 'مكرر', user_cancelled: 'إلغاء المستخدم' } as const;
const LABELS = { accepted: 'مقبول', review: 'يتطلب مراجعة', rejected: 'مرفوض' } as const;
const COUNT_LABELS = { items: 'العناصر', accepted: 'مقبولة', review: 'للمراجعة', rejected: 'مرفوضة', skipped: 'متخطاة', errors: 'أخطاء' } as const;

function validUrl(value: string) {
  try { const parsed = new URL(value); return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password; }
  catch { return false; }
}
function safeError(error: unknown) {
  if (error instanceof TypeError) return 'الخدمة المركزية غير متصلة.';
  if (error instanceof ApiError) {
    if (error.status === 401) return 'انتهت الجلسة. سجّل الدخول مجددًا.';
    if (error.status === 403) return 'لا تملك صلاحية تنفيذ هذه العملية.';
    if (error.status === 410) return 'انتهت صلاحية المعاينة. أنشئ معاينة جديدة.';
    if (error.status === 409) return error.code.includes('content') ? 'لا تطابق بصمة المعاينة ولا يمكن اعتمادها.' : 'سبق اتخاذ قرار بشأن هذه المعاينة.';
    if (error.status === 502 && error.code === 'invalid_response') return 'أعادت الخدمة استجابة غير صالحة.';
  }
  return 'تعذر تنفيذ العملية بأمان.';
}

export function Manual() {
  const { can, loading } = useAuth();
  const inputRef = useRef<HTMLInputElement>(null);
  const [url, setUrl] = useState('');
  const [preview, setPreview] = useState<ManualPreview>();
  const [job, setJob] = useState<ExternalJob>();
  const [reason, setReason] = useState<keyof typeof REASONS>('not_relevant');
  const [message, setMessage] = useState('');
  const [validationError, setValidationError] = useState('');
  const create = useMutation({ mutationFn: api.createManualPreview, onSuccess: (value) => { setPreview(value); setUrl(''); setMessage(''); } });
  const clearConsumed = (error: unknown) => { if (error instanceof ApiError && [401, 409, 410].includes(error.status)) setPreview(undefined); };
  const approve = useMutation({ mutationFn: api.approveManualPreview, onSuccess: (value) => { setJob(value); setPreview(undefined); setMessage('تم قبول طلب الاعتماد، وجار متابعة الحفظ والتصدير.'); }, onError: clearConsumed });
  const reject = useMutation({ mutationFn: () => preview ? api.rejectManualPreview(preview.preview_id, reason) : Promise.reject(new Error('missing preview')), onSuccess: () => { setPreview(undefined); setMessage('تم تجاهل المعاينة دون تسجيل الرابط أو حفظ محتواه.'); window.setTimeout(() => inputRef.current?.focus(), 0); }, onError: clearConsumed });
  useEffect(() => {
    if (!preview) return;
    const remaining = new Date(preview.expires_at).getTime() - Date.now();
    if (remaining <= 0) { setPreview(undefined); setMessage('انتهت صلاحية المعاينة. أنشئ معاينة جديدة.'); return; }
    const timer = window.setTimeout(
      () => { setPreview(undefined); setMessage('انتهت صلاحية المعاينة. أنشئ معاينة جديدة.'); },
      Math.min(remaining, 2_147_483_647),
    );
    return () => window.clearTimeout(timer);
  }, [preview]);

  if (loading) return <LoadingState label="جار التحقق من الصلاحيات..." />;
  if (!can('analyst')) return <Navigate to="/" replace />;
  const activeJob = Boolean(job && !TERMINAL_STATES.includes(job.state));
  const busy = create.isPending || approve.isPending || reject.isPending || activeJob;
  function submit(event: FormEvent) {
    event.preventDefault(); if (busy) return;
    const value = url.trim();
    if (!validUrl(value)) { setValidationError('أدخل رابط HTTP أو HTTPS صالحًا دون بيانات اعتماد.'); return; }
    setValidationError(''); setMessage(''); setPreview(undefined); setJob(undefined); create.mutate(value);
  }
  function approvePreview() {
    if (preview && !busy && window.confirm('سيُحفظ ويُعالج ويُصدّر المحتوى المجمد الذي راجعته، دون إعادة جلب الرابط. هل تريد الاعتماد؟')) approve.mutate(preview);
  }

  const error = create.error || approve.error || reject.error;
  return <section className="page-section manual-page"><div className="section-heading"><div><span className="eyebrow">المصادر / 03</span><h2>معاينة رابط يدوي</h2><p>راجع نسخة مؤقتة ومنقّاة قبل الحفظ أو التصدير.</p></div></div>
    <form className="manual-form" onSubmit={submit} noValidate><label htmlFor="manual-url">رابط HTTP أو HTTPS</label><input ref={inputRef} id="manual-url" type="url" inputMode="url" dir="ltr" placeholder="https://example.org/report" value={url} disabled={busy} aria-invalid={Boolean(validationError)} aria-describedby="manual-url-help manual-url-error" onChange={(event) => { setUrl(event.target.value); setValidationError(''); }} /><span id="manual-url-help" className="muted-text">لن يُسجّل الرابط أو يُصدّر شيء قبل اعتماد المعاينة صراحة.</span>{validationError && <span id="manual-url-error" className="field-error" role="alert">{validationError}</span>}<button className="button" type="submit" disabled={busy || !url.trim()}>{create.isPending ? 'جار إنشاء المعاينة...' : 'معاينة الرابط'}</button></form>
    {Boolean(error) && <div className="job-panel error-panel" role="alert"><strong>تعذر إكمال العملية</strong><span>{safeError(error)}</span></div>}
    {message && <div className="job-panel" role="status">{message}</div>}
    {preview && <article className="preview-card" aria-labelledby="preview-title"><div className="preview-header"><div><span className="eyebrow">معاينة مؤقتة</span><h3 id="preview-title">{preview.title || 'دون عنوان'}</h3></div><strong>{LABELS[preview.disposition]}</strong></div><code dir="ltr">{preview.display_url}</code><dl className="preview-details"><div><dt>نوع الصفحة</dt><dd>{preview.page_type}</dd></div><div><dt>تنتهي</dt><dd>{new Date(preview.expires_at).toLocaleString('ar')}</dd></div></dl><dl className="job-counts">{Object.entries(preview.counts).map(([key, value]) => <div key={key}><dt>{COUNT_LABELS[key as keyof typeof COUNT_LABELS]}</dt><dd>{value}</dd></div>)}</dl>
      <section aria-labelledby="preview-items-title"><div className="preview-list-heading"><h4 id="preview-items-title">العناصر المعاينة</h4>{preview.items_preview_truncated && <strong>عرض {preview.items_preview.length} من {preview.items_preview_total}</strong>}</div>
        {preview.items_preview.length === 0 ? <p className="muted-text">لا توجد عناصر آمنة للعرض.</p> : <ol className="preview-items">{preview.items_preview.map((item) => <li key={item.item_index} className="preview-item"><div className="preview-header"><h5>العنصر {item.item_index}: {item.title || 'دون عنوان'}</h5><strong>{LABELS[item.disposition]}</strong></div>{item.excerpt && <p className="preview-excerpt">{item.excerpt}</p>}<dl className="preview-details"><div><dt>التصنيف</dt><dd>{item.classification_label || 'غير محدد'}{item.classification_confidence !== undefined && item.classification_confidence !== null ? ` (${Math.round(item.classification_confidence * 100)}٪)` : ''}</dd></div><div><dt>الخصوصية</dt><dd>{item.privacy_status === 'reviewed' ? 'مراجعة مكتملة' : 'تتطلب مراجعة'}</dd></div>{item.published && <div><dt>وقت النشر</dt><dd>{new Date(item.published).toLocaleString('ar')}</dd></div>}</dl></li>)}</ol>}
      </section><p className="manual-warning"><strong>تنبيه</strong><span>«اعتماد وحفظ» يطبّق على كامل المعاينة المجمدة، بما فيها العناصر غير المعروضة عند الاختصار، وليس على عنصر واحد.</span></p><div className="preview-actions"><button className="button" type="button" disabled={busy} onClick={approvePreview}>{approve.isPending ? 'جار الاعتماد...' : 'اعتماد وحفظ'}</button><label>سبب التجاهل<select value={reason} disabled={busy} onChange={(event) => setReason(event.target.value as keyof typeof REASONS)}>{Object.entries(REASONS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><button className="button button-secondary" type="button" disabled={busy} onClick={() => preview && reject.mutate()}>{reject.isPending ? 'جار التجاهل...' : 'تجاهل'}</button></div></article>}
    {job && <JobMonitor sourceId="manual-preview" job={job} onUpdate={(_key, value) => setJob(value)} />}
  </section>;
}
