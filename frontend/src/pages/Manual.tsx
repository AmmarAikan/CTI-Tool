import { type FormEvent, useEffect, useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Navigate } from 'react-router-dom';
import { api, ApiError, type ExternalJob, type ManualPreview } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { LoadingState } from '../components/States';
import { JobMonitor, TERMINAL_STATES } from './Sources';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';
import './Sources.css';
import './Manual.css';

const REASONS = { not_relevant: 'notRelevant', duplicate: 'duplicate', user_cancelled: 'userCancelled' } as const satisfies Record<string,TranslationKey>;
const LABELS = { accepted: 'acceptedState', review: 'reviewState', rejected: 'rejectedState' } as const satisfies Record<string,TranslationKey>;
const COUNT_LABELS = { items: 'items', accepted: 'accepted', review: 'forReview', rejected: 'rejected', skipped: 'skipped', errors: 'errors' } as const satisfies Record<string,TranslationKey>;
type UrlRequest = { value: string; generation: number; signal: AbortSignal };
type PreviewRequest = { preview: ManualPreview; generation: number; signal: AbortSignal };
type RejectRequest = PreviewRequest & { reason: keyof typeof REASONS };

function validUrl(value: string) {
  try { const parsed = new URL(value); return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password; }
  catch { return false; }
}
function safeError(error: unknown,t:(key:TranslationKey)=>string) {
  if (error instanceof TypeError) return t('disconnected');
  if (error instanceof ApiError) {
    if (error.status === 401) return t('sessionExpired');
    if (error.status === 403) return t('forbiddenHint');
    if (error.status === 410) return t('previewExpired');
    if (error.status === 409) return t(error.code.includes('content') ? 'previewHashMismatch' : 'previewAlreadyDecided');
    if (error.status === 502 && error.code === 'invalid_response') return t('malformed');
    if (error.status === 408) return t('requestTimeout');
    if ([502, 503, 504].includes(error.status)) return t('externalControlUnavailable');
  }
  return t('unknownError');
}

export function Manual() {
  const { can, loading } = useAuth();
  const {t,number,dateTime}=useI18n();
  const inputRef = useRef<HTMLInputElement>(null);
  const requestAbort = useRef<AbortController | undefined>(undefined);
  const operationGeneration = useRef(0);
  const [url, setUrl] = useState('');
  const [preview, setPreview] = useState<ManualPreview>();
  const [job, setJob] = useState<ExternalJob>();
  const [reason, setReason] = useState<keyof typeof REASONS>('not_relevant');
  const [message, setMessage] = useState('');
  const [validationError, setValidationError] = useState('');
  const [recheckUrl, setRecheckUrl] = useState('');
  const [recheckValidationError, setRecheckValidationError] = useState('');
  const [recheckJob, setRecheckJob] = useState<ExternalJob>();
  const create = useMutation({ mutationFn: (request: UrlRequest) => api.createManualPreview(request.value, request.signal), onSuccess: (value, request) => { if (request.generation !== operationGeneration.current) return; setPreview(value); setUrl(''); setMessage(''); } });
  const clearConsumed = (error: unknown) => { if (error instanceof ApiError && [401, 409, 410].includes(error.status)) setPreview(undefined); };
  const approve = useMutation({ mutationFn: (request: PreviewRequest) => api.approveManualPreviewAbortable(request.preview, request.signal), onSuccess: (value, request) => { if (request.generation !== operationGeneration.current) return; setJob(value); setPreview(undefined); setMessage(t('approveAccepted')); }, onError: (error, request) => { if (request.generation === operationGeneration.current) clearConsumed(error); } });
  const reject = useMutation({ mutationFn: (request: RejectRequest) => api.rejectManualPreviewAbortable(request.preview.preview_id, request.reason, request.signal), onSuccess: (_value, request) => { if (request.generation !== operationGeneration.current) return; setPreview(undefined); setMessage(t('previewRejected')); window.setTimeout(() => inputRef.current?.focus(), 0); }, onError: (error, request) => { if (request.generation === operationGeneration.current) clearConsumed(error); } });
  const recheck = useMutation({ mutationFn: (request: UrlRequest) => api.recheckManualSource(request.value, request.signal), onSuccess: (value, request) => { if (request.generation !== operationGeneration.current) return; setRecheckJob(value); setRecheckUrl(''); } });
  useEffect(() => {
    if (!preview) return;
    const remaining = new Date(preview.expires_at).getTime() - Date.now();
    if (remaining <= 0) { setPreview(undefined); setMessage(t('previewExpired')); return; }
    const timer = window.setTimeout(
      () => { setPreview(undefined); setMessage(t('previewExpired')); },
      Math.min(remaining, 2_147_483_647),
    );
    return () => window.clearTimeout(timer);
  }, [preview,t]);
  useEffect(() => () => { operationGeneration.current += 1; requestAbort.current?.abort(); }, []);

  function beginRequest() {
    requestAbort.current?.abort();
    const controller = new AbortController(); requestAbort.current = controller;
    const generation = operationGeneration.current + 1; operationGeneration.current = generation;
    return { controller, generation };
  }

  if (loading) return <LoadingState label={t('checkingPermissions')} />;
  if (!can('analyst')) return <Navigate to="/" replace />;
  const activeJob = Boolean(job && !TERMINAL_STATES.includes(job.state));
  const activeRecheck = Boolean(recheckJob && !TERMINAL_STATES.includes(recheckJob.state));
  const busy = create.isPending || approve.isPending || reject.isPending || activeJob;
  const recheckBusy = recheck.isPending || activeRecheck;
  function submit(event: FormEvent) {
    event.preventDefault(); if (busy) return;
    const value = url.trim();
    if (!validUrl(value)) { setValidationError(t('invalidUrl')); return; }
    const request = beginRequest();
    setValidationError(''); setMessage(''); setPreview(undefined); setJob(undefined); create.reset(); create.mutate({ value, generation: request.generation, signal: request.controller.signal });
  }
  function approvePreview() {
    if (!preview || busy || !window.confirm(t('confirmManualApprove'))) return;
    const request = beginRequest(); approve.reset(); approve.mutate({ preview, generation: request.generation, signal: request.controller.signal });
  }
  function submitRecheck(event: FormEvent) {
    event.preventDefault(); if (recheckBusy) return;
    const value = recheckUrl.trim();
    if (!validUrl(value)) { setRecheckValidationError(t('invalidUrl')); return; }
    if (!window.confirm(t('confirmRecheck'))) return;
    const request = beginRequest();
    setRecheckValidationError(''); setRecheckJob(undefined); recheck.reset(); recheck.mutate({ value, generation: request.generation, signal: request.controller.signal });
  }
  function rejectPreview() {
    if (!preview || busy || !window.confirm(t('confirmManualReject'))) return;
    const request = beginRequest(); reject.reset(); reject.mutate({ preview, reason, generation: request.generation, signal: request.controller.signal });
  }

  const error = create.error || approve.error || reject.error;
  return <section className="page-section manual-page"><div className="section-heading"><div><span className="eyebrow">{t('manualEyebrow')}</span><h2>{t('manualPreviewTitle')}</h2><p>{t('manualDescription')}</p></div></div>
    <form className="manual-form" onSubmit={submit} noValidate><label htmlFor="manual-url">{t('urlLabel')}</label><input ref={inputRef} id="manual-url" type="url" inputMode="url" dir="ltr" placeholder="https://example.org/report" value={url} disabled={busy} aria-invalid={Boolean(validationError)} aria-describedby="manual-url-help manual-url-error" onChange={(event) => { setUrl(event.target.value); setValidationError(''); }} /><span id="manual-url-help" className="muted-text">{t('manualPrivacyHint')}</span>{validationError && <span id="manual-url-error" className="field-error" role="alert">{validationError}</span>}<button className="button" type="submit" disabled={busy || !url.trim()}>{create.isPending ? t('creatingPreview') : t('previewLabel')}</button></form>
    <section className="recheck-section" aria-labelledby="recheck-title"><h3 id="recheck-title">{t('recheckTitle')}</h3><p>{t('recheckDescription')}</p><form className="manual-form" onSubmit={submitRecheck} noValidate><label htmlFor="manual-recheck-url">{t('recheckUrl')}</label><input id="manual-recheck-url" type="url" inputMode="url" dir="ltr" placeholder="https://example.org/report" value={recheckUrl} disabled={recheckBusy} aria-invalid={Boolean(recheckValidationError)} aria-describedby="manual-recheck-help manual-recheck-error" onChange={(event) => { setRecheckUrl(event.target.value); setRecheckValidationError(''); }} /><span id="manual-recheck-help" className="muted-text">{t('recheckHint')}</span>{recheckValidationError && <span id="manual-recheck-error" className="field-error" role="alert">{recheckValidationError}</span>}<button className="button" type="submit" disabled={recheckBusy || !recheckUrl.trim()}>{recheck.isPending ? t('rechecking') : t('recheck')}</button></form>{Boolean(recheck.error) && <div className="job-panel error-panel" role="alert"><strong>{t('recheckFailed')}</strong><span>{safeError(recheck.error,t)}</span></div>}{recheckJob && <JobMonitor sourceId="manual-recheck" job={recheckJob} onUpdate={(_key, value) => setRecheckJob(value)} />}</section>
    {Boolean(error) && <div className="job-panel error-panel" role="alert"><strong>{t('operationFailed')}</strong><span>{safeError(error,t)}</span></div>}
    {message && <div className="job-panel" role="status">{message}</div>}
    {preview && <article className="preview-card" aria-labelledby="preview-title"><div className="preview-header"><div><span className="eyebrow">{t('temporaryPreview')}</span><h3 id="preview-title">{preview.title || t('noTitle')}</h3></div><strong>{t(LABELS[preview.disposition])}</strong></div><code dir="ltr">{preview.display_url}</code><dl className="preview-details"><div><dt>{t('pageType')}</dt><dd>{preview.page_type}</dd></div><div><dt>{t('expiresAt')}</dt><dd>{dateTime(preview.expires_at)}</dd></div></dl><dl className="job-counts">{Object.entries(preview.counts).map(([key, value]) => <div key={key}><dt>{t(COUNT_LABELS[key as keyof typeof COUNT_LABELS])}</dt><dd>{number(value)}</dd></div>)}</dl>
      <section aria-labelledby="preview-items-title"><div className="preview-list-heading"><h4 id="preview-items-title">{t('previewItems')}</h4>{preview.items_preview_truncated && <strong>{t('shownOfTotal',{shown:number(preview.items_preview.length),total:number(preview.items_preview_total)})}</strong>}</div>
        {preview.items_preview.length === 0 ? <p className="muted-text">{t('noSafeItems')}</p> : <ol className="preview-items">{preview.items_preview.map((item) => <li key={item.item_index} className="preview-item"><div className="preview-header"><h5>{t('previewItem',{index:number(item.item_index),title:item.title||t('noTitle')})}</h5><strong>{t(LABELS[item.disposition])}</strong></div>{item.excerpt && <p className="preview-excerpt">{item.excerpt}</p>}<dl className="preview-details"><div><dt>{t('classification')}</dt><dd>{item.classification_label || t('unspecified')}{item.classification_confidence !== undefined && item.classification_confidence !== null ? ` (${number(Math.round(item.classification_confidence * 100))}%)` : ''}</dd></div><div><dt>{t('privacy')}</dt><dd>{t(item.privacy_status === 'reviewed' ? 'privacyReviewed' : 'privacyReviewRequired')}</dd></div>{item.published && <div><dt>{t('publishedAt')}</dt><dd>{dateTime(item.published)}</dd></div>}</dl></li>)}</ol>}
      </section><p className="manual-warning"><strong>{t('warning')}</strong><span>{t('wholePreviewWarning')}</span></p><div className="preview-actions"><button className="button" type="button" disabled={busy} onClick={approvePreview}>{approve.isPending ? t('approving') : t('approveSave')}</button><label>{t('rejectReason')}<select value={reason} disabled={busy} onChange={(event) => setReason(event.target.value as keyof typeof REASONS)}>{Object.entries(REASONS).map(([value, label]) => <option key={value} value={value}>{t(label)}</option>)}</select></label><button className="button button-secondary" type="button" disabled={busy} onClick={rejectPreview}>{reject.isPending ? t('rejecting') : t('reject')}</button></div></article>}
    {job && <JobMonitor sourceId="manual-preview" job={job} onUpdate={(_key, value) => setJob(value)} />}
  </section>;
}
