import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type ExternalJob, type InternalIntegration, type ManualPreview } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { JobMonitor, TERMINAL_STATES } from './Sources';
import {externalQueryKeys} from '../api/externalQueryKeys';
import { acceptExternalJobUpdate, forgetActiveExternalJob, loadActiveExternalJobs, rememberActiveExternalJob } from '../api/externalJobLifecycle';

type InputKind = 'external' | 'manual' | 'internal' | 'dark';
type PullResult = { run_id: string; status: string };
type OperationRequest = { generation: number; kind: InputKind; selection: string; url: string; signal: AbortSignal };
type PreviewDecisionRequest = { generation: number; preview: ManualPreview; signal: AbortSignal };

export const PROCESSING_CENTER_JOB_POLL_MAX_MS = 15 * 60_000;

function validPublicUrl(value: string) {
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password;
  } catch { return false; }
}

export function ProcessingCenter() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const { t, number } = useI18n();
  const [kind, setKind] = useState<InputKind>('external');
  const [selection, setSelection] = useState('');
  const [url, setUrl] = useState('');
  const [validation, setValidation] = useState('');
  const [job, setJob] = useState<ExternalJob>();
  const [jobInputKey, setJobInputKey] = useState('');
  const [pullResult, setPullResult] = useState<PullResult>();
  const [preview, setPreview] = useState<ManualPreview>();
  const [decisionError, setDecisionError] = useState<unknown>();
  const operationGeneration = useRef(0);
  const submissionController = useRef<AbortController | undefined>(undefined);
  const refreshedTerminalJob = useRef('');
  const importedTerminalJob = useRef('');
  const sources = useQuery({ queryKey: externalQueryKeys.sources(), queryFn: api.externalSources, retry: false });
  const watches = useQuery({ queryKey: ['center-watches'], queryFn: api.darkWebWatches, retry: false });
  const providers = useQuery({ queryKey: ['center-dark-web-providers'], queryFn: api.darkWebDiscoveryProviders, retry: false });
  const snapshot = useQueries({ queries: [
    { queryKey: ['center-summary'], queryFn: api.dashboardSummary, retry: false },
    { queryKey: ['center-events'], queryFn: () => api.intelligenceEvents(5), retry: false },
    { queryKey: ['center-indicators'], queryFn: api.intelligenceIndicatorSummary, retry: false },
    { queryKey: ['center-correlations'], queryFn: () => api.intelligenceCorrelations(1), retry: false },
    { queryKey: ['center-outliers'], queryFn: () => api.intelligenceOutliers(1, 0, true), retry: false },
  ] });
  const analysis=useQuery({queryKey:externalQueryKeys.processingRun(pullResult?.run_id||''),queryFn:({signal})=>api.analysisRunResults(pullResult!.run_id,signal),enabled:Boolean(pullResult?.run_id&&['completed','partial','failed'].includes(pullResult.status)),retry:2});
  const run = useMutation({
    mutationFn: async (request: OperationRequest) => {
      if (request.kind === 'external') return api.startExternalSourceJob(request.selection, request.signal);
      if (request.kind === 'dark') return api.scanDarkWebWatchAbortable(request.selection, request.signal);
      if (request.kind === 'internal') return api.pullInternal(request.selection as InternalIntegration, request.signal);
      return api.createManualPreview(request.url, request.signal);
    },
    onSuccess: (value, request) => {
      if (request.generation !== operationGeneration.current) return;
      if ('job_id' in value) { const external=value as ExternalJob;rememberActiveExternalJob('processing-center',request.selection||'manual',external.job_id);setJob(external); setJobInputKey(`${request.kind}:${request.selection || request.url}`); }
      else if ('preview_id' in value) setPreview(value as ManualPreview);
      else setPullResult(value as PullResult);
    },
  });
  const approve = useMutation({
    mutationFn: (request: PreviewDecisionRequest) => api.approveManualPreviewAbortable(request.preview, request.signal),
    onSuccess: (value, request) => {
      if (request.generation !== operationGeneration.current) return;
      rememberActiveExternalJob('processing-center','manual',value.job_id);setPreview(undefined); setDecisionError(undefined); setJob(value); setJobInputKey(`manual:${url.trim()}`);
    },
    onError: (error, request) => { if (request.generation === operationGeneration.current) setDecisionError(error); },
  });
  const reject = useMutation({
    mutationFn: (request: PreviewDecisionRequest) => api.rejectManualPreviewAbortable(request.preview.preview_id, 'user_cancelled', request.signal),
    onSuccess: (_value, request) => { if (request.generation === operationGeneration.current) { setPreview(undefined); setDecisionError(undefined); } },
    onError: (error, request) => { if (request.generation === operationGeneration.current) setDecisionError(error); },
  });
  const summary = snapshot[0].data;
  const events = snapshot[1].data;
  const indicators = snapshot[2].data;
  const correlations = snapshot[3].data;
  const outliers = snapshot[4].data;
  const state = job?.state || pullResult?.status;
  const stages: TranslationKey[] = ['selectInput', 'collectStage', 'privacyStage', 'classifyStage', 'extractStage', 'saveStage', 'correlateStage', 'snapshot'];
  const statusKey = state && ['queued', 'processing', 'completed', 'partial', 'failed', 'cancelled', 'cancellation_requested'].includes(state) ? state as TranslationKey : undefined;
  const safeMutationError = (error: unknown) => error instanceof ApiError && error.status === 401 ? t('sessionExpired') : error instanceof ApiError && error.status === 403 ? t('forbidden') : error instanceof ApiError && error.status === 404 ? t('jobNotFound') : error instanceof ApiError && error.status === 408 ? t('timeout') : error instanceof ApiError && error.status === 409 ? t('previewConflict') : error instanceof ApiError && error.status === 410 ? t('previewExpired') : error instanceof ApiError && error.status === 503 ? t('externalControlUnavailable') : error instanceof ApiError && error.code === 'invalid_response' ? t('malformed') : error instanceof TypeError ? t('disconnected') : t('unknownError');

  useEffect(() => () => {
    operationGeneration.current += 1;
    submissionController.current?.abort();
  }, []);
  useEffect(()=>{const stored=loadActiveExternalJobs().find(item=>item.context==='processing-center');if(!stored)return;let cancelled=false;void api.externalJob(stored.jobId).then(value=>{if(cancelled)return;setJob(value);setJobInputKey(`external:${stored.sourceId}`);if(stored.sourceId!=='manual'){setKind('external');setSelection(stored.sourceId);}}).catch(()=>undefined);return()=>{cancelled=true};},[]);
  useEffect(()=>{
    if(!job||!['completed','partial'].includes(job.state)||importedTerminalJob.current===job.job_id)return;
    importedTerminalJob.current=job.job_id;const generation=operationGeneration.current;const controller=new AbortController();submissionController.current=controller;
    void api.importExternalJob(job.job_id,controller.signal).then(value=>{if(generation===operationGeneration.current){setPullResult(value);void queryClient.invalidateQueries({queryKey:['external','accepted-records']});void queryClient.invalidateQueries({queryKey:externalQueryKeys.reviews()});void queryClient.invalidateQueries({queryKey:externalQueryKeys.processingRun(value.run_id)})}}).catch(error=>{if(generation===operationGeneration.current)setDecisionError(error)});
    return()=>controller.abort();
  },[job,kind,queryClient]);

  function submit() {
    if (run.isPending || !can('analyst')) return;
    if (kind === 'manual' && !validPublicUrl(url.trim())) { setValidation(t('invalidUrl')); return; }
    const inputKey = `${kind}:${kind === 'manual' ? url.trim() : selection}`;
    if (job && !TERMINAL_STATES.includes(job.state) && jobInputKey === inputKey) return;
    if (!window.confirm(t('confirmRun'))) return;
    submissionController.current?.abort();
    const controller = new AbortController();
    submissionController.current = controller;
    const generation = operationGeneration.current + 1;
    operationGeneration.current = generation;
    setValidation(''); setDecisionError(undefined); setJob(undefined); setJobInputKey(''); setPullResult(undefined); setPreview(undefined); run.reset(); approve.reset(); reject.reset();
    run.mutate({ generation, kind, selection, url: url.trim(), signal: controller.signal });
  }
  function decidePreview(action: 'approve' | 'reject') {
    if (!preview || approve.isPending || reject.isPending || !can('analyst')) return;
    const confirmation = action === 'approve' ? t('confirmApprove') : t('confirmRun');
    if (!window.confirm(confirmation)) return;
    submissionController.current?.abort();
    const controller = new AbortController();
    submissionController.current = controller;
    const generation = operationGeneration.current + 1;
    operationGeneration.current = generation;
    setDecisionError(undefined); approve.reset(); reject.reset();
    const request = { generation, preview, signal: controller.signal };
    if (action === 'approve') approve.mutate(request); else reject.mutate(request);
  }
  const readyProviderIds = new Set((providers.data || []).filter((item) => item.enabled && item.ready).map((item) => item.provider_id));
  const choices = kind === 'external'
    ? (sources.data || []).filter((item) => ['enabled','ready'].includes(item.status)).map((item) => [item.source_id, item.name])
    : kind === 'dark'
      ? (watches.data?.items || []).filter((item) => item.enabled && Boolean(item.provider_id) && readyProviderIds.has(item.provider_id!)).map((item) => [item.watch_id, item.keyword])
      : kind === 'internal'
        ? [['dionaea', 'Dionaea'], ['host-auth', t('hostAuth')], ['web-access', t('webAccess')]]
        : [];
  const currentInputKey = `${kind}:${kind === 'manual' ? url.trim() : selection}`;
  const duplicateActiveJob = Boolean(job && !TERMINAL_STATES.includes(job.state) && jobInputKey === currentInputKey);
  const disabled = run.isPending || duplicateActiveJob || (kind === 'manual' ? !url.trim() : !selection);
  const selectedLabel = choices.find(([id]) => id === selection)?.[1] || t('processingCenter');

  return <section className="page-section processing-center">
    <div className="section-heading"><div><span className="eyebrow">{t('centerEyebrow')}</span><h2>{t('processingCenter')}</h2><p>{t('centerDescription')}</p></div></div>
    <section className="center-input" aria-labelledby="center-input-title"><h3 id="center-input-title">{t('selectInput')}</h3>
      <label>{t('inputType')}<select value={kind} onChange={(event) => { setKind(event.target.value as InputKind); setSelection(''); setValidation(''); }}><option value="external">{t('externalSource')}</option><option value="manual">{t('manual')}</option><option value="internal">{t('internalSource')}</option><option value="dark">{t('savedWatch')}</option></select></label>
      {kind === 'manual' ? <label>{t('urlLabel')}<input dir="ltr" type="url" value={url} aria-invalid={Boolean(validation)} onChange={(event) => { setUrl(event.target.value); setValidation(''); }} placeholder="https://example.org/report" />{validation && <span className="field-error" role="alert">{validation}</span>}</label> : <label>{t('choose')}<select value={selection} onChange={(event) => setSelection(event.target.value)}><option value="">—</option>{choices.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>}
      {!can('analyst') ? <p className="notice">{t('readonly')}</p> : <button className="button button-primary" disabled={disabled} onClick={submit}>{run.isPending ? t('running') : t('startProcessing')}</button>}
      {kind === 'dark' && watches.data && choices.length === 0 && <p role="status">{t('noConfiguredWatches')}</p>}
      {run.isError && <div className="state-panel error-panel" role="alert"><strong>{safeMutationError(run.error)}</strong><button className="button button-secondary" onClick={submit}>{t('retry')}</button></div>}
    </section>
    <section className="workflow-panel"><div><h3>{t('stages')}</h3><p>{t('confirmedOnly')}</p></div><ol className="stage-strip">{stages.map((key, index) => {const confirmed=index===0||(index===1&&Boolean(job&&['completed','partial'].includes(job.state)))||(index>1&&Boolean(analysis.data&&['completed','partial'].includes(analysis.data.status)));return <li className={confirmed?'confirmed':''} key={key}><span>{index + 1}</span>{t(key)}</li>})}</ol></section>
    <section className="operation-panel"><h3>{t('actualState')}</h3>{!state && !preview && <EmptyState label={t('noOperation')} />}
      {job && <JobMonitor key={job.job_id} sourceId="processing-center" label={selectedLabel} job={job} maxPollingMs={PROCESSING_CENTER_JOB_POLL_MAX_MS} onUpdate={(_id, value) => { setJob((current) => current?.job_id === value.job_id ? acceptExternalJobUpdate(current,value) : current); if (TERMINAL_STATES.includes(value.state) && refreshedTerminalJob.current !== value.job_id) { forgetActiveExternalJob('processing-center',value.job_id);refreshedTerminalJob.current = value.job_id;void queryClient.invalidateQueries({queryKey:externalQueryKeys.reviews()});snapshot.forEach((query) => void query.refetch()); } }} />}
      {pullResult && <div className="job-panel" role="status"><strong>{statusKey ? t(statusKey) : t('operationSucceeded')}</strong>{can('analyst')&&<details><summary>{t('technicalDetails')}</summary><code dir="ltr">{pullResult.run_id}</code></details>}</div>}
      {job&&TERMINAL_STATES.includes(job.state)&&<p role="status">{t('collectionCompleted')}</p>}
      {job&&['completed','partial'].includes(job.state)&&!pullResult&&!decisionError&&<p role="status">{t('centralImportRunning')}</p>}
      {analysis.isLoading&&<LoadingState label={t('loadingRunDetails')}/>} {analysis.isError&&<ErrorState onRetry={()=>void analysis.refetch()}/>} {analysis.data&&<section className="snapshot-panel"><h4>{analysis.data.status==='partial'?t('analysisPartial'):t('analysisCompleted')}</h4><div className="metric-grid">{[[t('processed'),analysis.data.processed_documents],[t('entities'),analysis.data.entity_count],[t('indicators'),analysis.data.indicator_count],[t('correlations'),analysis.data.correlation_count],[t('skipped'),analysis.data.skipped_count],[t('errors'),analysis.data.error_count]].map(([label,value])=><article className="metric-card" key={String(label)}><span>{label}</span><strong>{number(value as number)}</strong></article>)}</div><h4>{t('entities')}</h4>{analysis.data.entities.length?<ul>{analysis.data.entities.map((item,index)=><li key={`${item.event_id}-${index}`}>{item.type}: {item.value} · {item.record_title}</li>)}</ul>:<EmptyState label={t('noEntitiesIdentified')}/>}<h4>{t('indicators')}</h4>{analysis.data.indicators.length?<ul>{analysis.data.indicators.map((item,index)=><li key={`${item.event_id}-${index}`}>{item.type}: {item.value} · {item.record_title}</li>)}</ul>:<EmptyState label={t('noIndicatorsExtracted')}/>}<h4>{t('correlations')}</h4>{analysis.data.correlations.length?<ul>{analysis.data.correlations.map((item,index)=><li key={`${item.type}-${index}`}>{item.type}: {item.explanation}</li>)}</ul>:<EmptyState label={t('noCorrelationsFound')}/>}</section>}
      {preview && <article className="preview-card"><h4>{preview.title}</h4><p>{preview.excerpt}</p><button disabled={approve.isPending || reject.isPending} onClick={() => decidePreview('approve')}>{t('approveSave')}</button><button disabled={approve.isPending || reject.isPending} onClick={() => decidePreview('reject')}>{t('reject')}</button></article>}
      {decisionError !== undefined && <div className="state-panel error-panel" role="alert">{safeMutationError(decisionError)}{job&&['completed','partial'].includes(job.state)&&<button className="button button-secondary" onClick={()=>{importedTerminalJob.current='';setDecisionError(undefined);setJob({...job});}}>{t('retry')}</button>}</div>}
    </section>
    {!job&&!pullResult&&<section className="snapshot-panel"><h3>{t('snapshot')}</h3><p>{t('snapshotHint')}</p>{snapshot.some((query) => query.isLoading) && <LoadingState />}{snapshot.some((query) => query.isError) && <ErrorState onRetry={() => snapshot.forEach((query) => void query.refetch())} />}
      <div className="metric-grid">{[[t('totalEvents'), summary?.events], [t('totalIndicators'), indicators?.total], [t('totalCorrelations'), correlations?.total], [t('totalOutliers'), outliers?.total]].map(([label, value]) => <article className="metric-card" key={String(label)}><span>{label}</span><strong>{typeof value === 'number' ? number(value) : '—'}</strong></article>)}</div>
      {events?.items.length ? <div className="center-events"><h4>{t('latestEvents')}</h4>{events.items.map((event) => <article key={event.id}><div><strong>{event.title}</strong><small>{event.source_pipeline} · {event.severity || '—'} · {number(Math.round(event.confidence * 100))}%</small></div><Link to={`/intelligence/events/${event.id}`}>{t('viewDetails')}</Link></article>)}</div> : null}
      <nav className="quick-actions" aria-label={t('quickActions')}><Link to="/intelligence/indicators">{t('viewIndicators')}</Link><Link to="/intelligence/correlations">{t('viewCorrelations')}</Link><Link to="/intelligence/outliers">{t('viewOutliers')}</Link><Link to="/analysis">{t('viewRuns')}</Link></nav>
    </section>}
  </section>;
}
