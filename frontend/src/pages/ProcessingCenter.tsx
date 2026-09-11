import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQueries, useQuery } from '@tanstack/react-query';
import { api, ApiError, type ExternalJob, type InternalIntegration, type ManualPreview } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { JobMonitor, TERMINAL_STATES } from './Sources';

type InputKind = 'external' | 'manual' | 'internal' | 'dark';
type PullResult = { run_id: string; status: string };

function validPublicUrl(value: string) {
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password;
  } catch { return false; }
}

export function ProcessingCenter() {
  const { can } = useAuth();
  const { t, number } = useI18n();
  const [kind, setKind] = useState<InputKind>('external');
  const [selection, setSelection] = useState('');
  const [url, setUrl] = useState('');
  const [validation, setValidation] = useState('');
  const [job, setJob] = useState<ExternalJob>();
  const [pullResult, setPullResult] = useState<PullResult>();
  const [preview, setPreview] = useState<ManualPreview>();
  const sources = useQuery({ queryKey: ['center-sources'], queryFn: api.externalSources, retry: false });
  const watches = useQuery({ queryKey: ['center-watches'], queryFn: api.darkWebWatches, retry: false });
  const snapshot = useQueries({ queries: [
    { queryKey: ['center-summary'], queryFn: api.dashboardSummary, retry: false },
    { queryKey: ['center-events'], queryFn: () => api.intelligenceEvents(5), retry: false },
    { queryKey: ['center-indicators'], queryFn: api.intelligenceIndicatorSummary, retry: false },
    { queryKey: ['center-correlations'], queryFn: () => api.intelligenceCorrelations(1), retry: false },
    { queryKey: ['center-outliers'], queryFn: () => api.intelligenceOutliers(1, 0, true), retry: false },
  ] });
  const run = useMutation({
    mutationFn: async () => {
      if (kind === 'external') return api.startExternalSourceJob(selection);
      if (kind === 'dark') return api.scanDarkWebWatch(selection);
      if (kind === 'internal') return api.pullInternal(selection as InternalIntegration);
      return api.createManualPreview(url.trim());
    },
    onSuccess: (value) => {
      if ('job_id' in value) setJob(value as ExternalJob);
      else if ('preview_id' in value) setPreview(value as ManualPreview);
      else setPullResult(value as PullResult);
    },
  });
  const approve = useMutation({ mutationFn: api.approveManualPreview, onSuccess: (value) => { setPreview(undefined); setJob(value); } });
  const reject = useMutation({ mutationFn: () => preview ? api.rejectManualPreview(preview.preview_id, 'user_cancelled') : Promise.reject(), onSuccess: () => setPreview(undefined) });
  const summary = snapshot[0].data;
  const events = snapshot[1].data;
  const indicators = snapshot[2].data;
  const correlations = snapshot[3].data;
  const outliers = snapshot[4].data;
  const state = job?.state || pullResult?.status;
  const confirmed = Boolean(state && TERMINAL_STATES.includes(state as ExternalJob['state']));
  const stages: TranslationKey[] = ['selectInput', 'collectStage', 'privacyStage', 'classifyStage', 'extractStage', 'saveStage', 'correlateStage', 'snapshot'];
  const statusKey = state && ['queued', 'processing', 'completed', 'partial', 'failed', 'cancelled', 'cancellation_requested'].includes(state) ? state as TranslationKey : undefined;
  const safeMutationError = (error: unknown) => error instanceof ApiError && error.status === 403 ? t('forbidden') : error instanceof ApiError && error.status === 408 ? t('timeout') : error instanceof ApiError && error.code === 'invalid_response' ? t('malformed') : error instanceof TypeError ? t('disconnected') : t('unknownError');

  function submit() {
    if (run.isPending || !can('analyst')) return;
    if (kind === 'manual' && !validPublicUrl(url.trim())) { setValidation(t('invalidUrl')); return; }
    if (!window.confirm(t('confirmRun'))) return;
    setValidation(''); setJob(undefined); setPullResult(undefined); setPreview(undefined); run.reset(); run.mutate();
  }
  const choices = kind === 'external'
    ? (sources.data || []).filter((item) => item.status === 'enabled').map((item) => [item.source_id, item.name])
    : kind === 'dark'
      ? (watches.data?.items || []).filter((item) => item.enabled).map((item) => [item.watch_id, item.keyword])
      : kind === 'internal'
        ? [['dionaea', 'Dionaea'], ['host-auth', t('hostAuth')], ['web-access', t('webAccess')]]
        : [];
  const disabled = run.isPending || (kind === 'manual' ? !url.trim() : !selection);

  return <section className="page-section processing-center">
    <div className="section-heading"><div><span className="eyebrow">{t('centerEyebrow')}</span><h2>{t('processingCenter')}</h2><p>{t('centerDescription')}</p></div></div>
    <section className="center-input" aria-labelledby="center-input-title"><h3 id="center-input-title">{t('selectInput')}</h3>
      <label>{t('inputType')}<select value={kind} onChange={(event) => { setKind(event.target.value as InputKind); setSelection(''); setValidation(''); }}><option value="external">{t('externalSource')}</option><option value="manual">{t('manual')}</option><option value="internal">{t('internalSource')}</option><option value="dark">{t('savedWatch')}</option></select></label>
      {kind === 'manual' ? <label>{t('urlLabel')}<input dir="ltr" type="url" value={url} aria-invalid={Boolean(validation)} onChange={(event) => { setUrl(event.target.value); setValidation(''); }} placeholder="https://example.org/report" />{validation && <span className="field-error" role="alert">{validation}</span>}</label> : <label>{t('choose')}<select value={selection} onChange={(event) => setSelection(event.target.value)}><option value="">—</option>{choices.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>}
      {!can('analyst') ? <p className="notice">{t('readonly')}</p> : <button className="button button-primary" disabled={disabled} onClick={submit}>{run.isPending ? t('running') : t('startProcessing')}</button>}
      {kind === 'dark' && watches.data && choices.length === 0 && <p role="status">{t('noConfiguredWatches')}</p>}
      {run.isError && <div className="state-panel error-panel" role="alert"><strong>{safeMutationError(run.error)}</strong><button className="button button-secondary" onClick={submit}>{t('retry')}</button></div>}
    </section>
    <section className="workflow-panel"><div><h3>{t('stages')}</h3><p>{t('confirmedOnly')}</p></div><ol className="stage-strip">{stages.map((key, index) => <li className={index === 0 || confirmed ? 'confirmed' : state ? 'active' : ''} key={key}><span>{index + 1}</span>{t(key)}</li>)}</ol></section>
    <section className="operation-panel"><h3>{t('actualState')}</h3>{!state && !preview && <EmptyState label={t('noOperation')} />}
      {job && <><p><strong>{t('jobId')}:</strong> <code dir="ltr">{job.job_id}</code></p><JobMonitor sourceId="processing-center" job={job} onUpdate={(_id, value) => setJob(value)} /></>}
      {pullResult && <p role="status"><strong>{statusKey ? t(statusKey) : t('operationSucceeded')}</strong> · {t('runId')}: <code dir="ltr">{pullResult.run_id}</code></p>}
      {preview && <article className="preview-card"><h4>{preview.title}</h4><p>{preview.excerpt}</p><button disabled={approve.isPending || reject.isPending} onClick={() => window.confirm(t('confirmApprove')) && approve.mutate(preview)}>{t('approveSave')}</button><button disabled={approve.isPending || reject.isPending} onClick={() => window.confirm(t('confirmRun')) && reject.mutate()}>{t('reject')}</button></article>}
      {(approve.isError || reject.isError) && <div className="state-panel error-panel" role="alert">{safeMutationError(approve.error || reject.error)}</div>}
    </section>
    <section className="snapshot-panel"><h3>{t('snapshot')}</h3><p>{t('snapshotHint')}</p>{snapshot.some((query) => query.isLoading) && <LoadingState />}{snapshot.some((query) => query.isError) && <ErrorState onRetry={() => snapshot.forEach((query) => void query.refetch())} />}
      <div className="metric-grid">{[[t('totalEvents'), summary?.events], [t('totalIndicators'), indicators?.total], [t('totalCorrelations'), correlations?.total], [t('totalOutliers'), outliers?.total]].map(([label, value]) => <article className="metric-card" key={String(label)}><span>{label}</span><strong>{typeof value === 'number' ? number(value) : '—'}</strong></article>)}</div>
      {events?.items.length ? <div className="center-events"><h4>{t('latestEvents')}</h4>{events.items.map((event) => <article key={event.id}><div><strong>{event.title}</strong><small>{event.source_pipeline} · {event.severity || '—'} · {number(Math.round(event.confidence * 100))}%</small></div><Link to={`/intelligence/events/${event.id}`}>{t('viewDetails')}</Link></article>)}</div> : null}
      <nav className="quick-actions" aria-label={t('quickActions')}><Link to="/intelligence/indicators">{t('viewIndicators')}</Link><Link to="/intelligence/correlations">{t('viewCorrelations')}</Link><Link to="/intelligence/outliers">{t('viewOutliers')}</Link><Link to="/analysis">{t('viewRuns')}</Link></nav>
    </section>
  </section>;
}
