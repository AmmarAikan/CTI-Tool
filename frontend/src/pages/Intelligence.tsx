import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { api, type CTICorrelationEndpoint, type CTICorrelationFactor, type Page } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { useI18n,type TranslationKey } from '../i18n/I18nContext';

function PageState({ query, empty, children }: { query: { isLoading: boolean; isError: boolean; refetch: () => unknown; data?: Page<unknown> }; empty: string; children: React.ReactNode }) { if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState onRetry={() => void query.refetch()} />; if (query.data?.items.length === 0) return <EmptyState label={empty} />; return <>{children}</>; }
function Pager({ total, offset, limit, setOffset }: { total: number; offset: number; limit: number; setOffset: (value: number) => void }) { const {t,number}=useI18n();return <div className="pagination"><button className="button button-secondary" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - limit))}>{t('previous')}</button><span>{total?t('pageRange',{start:number(offset+1),end:number(Math.min(total,offset+limit)),total:number(total)}):number(0)}</span><button className="button button-secondary" disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}>{t('next')}</button></div>; }
function Heading({ eyebrow, title, text }: { eyebrow: string; title: string; text: string }) { return <div className="section-heading"><div><span className="eyebrow">{eyebrow}</span><h2>{title}</h2><p>{text}</p></div></div>; }

export function IntelligenceOverview() {
  const {t,number}=useI18n();
  const summary = useQuery({ queryKey: ['dashboard-summary'], queryFn: api.dashboardSummary, retry: false });
  return <section className="page-section intelligence-module"><Heading eyebrow={t('intelligenceEyebrow')} title={t('overview')} text={t('intelligenceSnapshot')} />{summary.isLoading && <LoadingState />}{summary.isError && <ErrorState onRetry={() => void summary.refetch()} />}{summary.data && <><div className="metric-grid">{[[t('events'), summary.data.events], [t('allObservables'), summary.data.observables], [t('verifiedIndicators'), summary.data.indicators], [t('correlations'), summary.data.correlations], [t('outliers'), summary.data.outliers]].map(([label, value]) => <article className="metric-card intel-accent" key={label}><span>{label}</span><strong>{number(Number(value))}</strong></article>)}</div><div className="distribution-grid"><Distribution title={t('severity')} values={summary.data.by_severity} /><Distribution title={t('pipeline')} values={summary.data.by_pipeline} /></div></>}</section>;
}
function Distribution({ title, values }: { title: string; values: Record<string, number> }) { const {t,number}=useI18n(),entries=Object.entries(values),max=Math.max(0,...entries.map(([,value])=>value));return <article className="distribution-card"><h3>{title}</h3>{!entries.length?<p>{t('noData')}</p>:entries.map(([label,value])=><div className="bar-row" key={label}><div><span>{label}</span><strong>{t('recordCount',{count:number(value)})}</strong></div><span className="bar-track" role="img" aria-label={`${label}: ${number(value)}`}><span className="bar-fill intel-fill" style={{width:`${max?value/max*100:0}%`}}/></span></div>)}</article>}

export function EventsPage() {
  const {t}=useI18n();
  const [offset, setOffset] = useState(0); const [severity, setSeverity] = useState(''); const [pipeline, setPipeline] = useState(''); const [search, setSearch] = useState(''); const limit = 20;
  const query = useQuery({ queryKey: ['intel-events', offset, severity, pipeline, search], queryFn: () => api.intelligenceEvents(limit, offset, { severity, source_pipeline: pipeline, search: search.length >= 2 ? search : '' }), retry: false });
  return <section className="page-section intelligence-module"><Heading eyebrow={t('intelligence')} title={t('events')} text={t('eventsDescription')} /><div className="filters"><input aria-label={t('searchEvents')} placeholder={t('searchTitle')} value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} /><select aria-label={t('pipeline')} value={pipeline} onChange={(e) => { setPipeline(e.target.value); setOffset(0); }}><option value="">{t('allPipelines')}</option><option value="external">{t('externalPipeline')}</option><option value="internal">{t('internalPipeline')}</option></select><select aria-label={t('severity')} value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0); }}><option value="">{t('allSeverityLevels')}</option><option value="critical">{t('critical')}</option><option value="high">{t('high')}</option><option value="medium">{t('medium')}</option><option value="low">{t('low')}</option></select></div><PageState query={query} empty={t('noEvents')}><EventTable items={query.data?.items || []} /></PageState>{query.data && <Pager total={query.data.total} offset={offset} limit={limit} setOffset={setOffset} />}</section>;
}
function EventTable({ items }: { items: Awaited<ReturnType<typeof api.intelligenceEvents>>['items'] }) { const {t,dateTime}=useI18n();return <div className="table-shell"><table><thead><tr><th>{t('event')}</th><th>{t('source')}</th><th>{t('severity')}</th><th>{t('status')}</th><th>{t('time')}</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td><Link to={`/intelligence/events/${item.id}`}><strong>{item.title}</strong></Link><small>{item.summary}</small></td><td>{item.source_type}<small>{item.source_pipeline}</small></td><td><StatusBadge status={item.severity || 'unknown'} /></td><td>{localizedProcessingState(item.processing_status,t)}</td><td>{dateTime(item.first_seen || item.created_at)}</td></tr>)}</tbody></table></div>; }

function downloadJson(filename: string, value: unknown) { const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })); const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url); }

export function EventDetailPage() { const {t,number}=useI18n();const { eventId = '' } = useParams(); const query = useQuery({ queryKey: ['intel-event', eventId], queryFn: () => api.intelligenceEvent(eventId), retry: false }); const attack = useQuery({ queryKey: ['attack-event', eventId], queryFn: () => api.attackMapping(eventId), enabled: Boolean(eventId), retry: false }); const stix = useMutation({ mutationFn: () => api.stixBundle(eventId), onSuccess: (bundle) => downloadJson(`cti-${eventId}.stix.json`, bundle) }); return <section className="page-section intelligence-module"><Heading eyebrow={t('eventDetails')} title={query.data?.title || t('eventFallback')} text={t('eventDetailsDescription')} />{query.isLoading && <LoadingState />}{query.isError && <ErrorState onRetry={() => void query.refetch()} />}{query.data && <><article className="detail-panel"><p>{query.data.summary}</p><div className="integration-facts"><span>{t('severity')}: <strong>{localizedSeverity(query.data.severity,t)}</strong></span><span>{t('risk')}: <strong>{number(query.data.risk_score)}</strong></span><span>{t('confidence')}: <strong>{number(Math.round(query.data.confidence * 100))}%</strong></span></div><button className="button button-secondary" disabled={stix.isPending} onClick={() => stix.mutate()}>{stix.isPending ? t('preparingStix') : t('downloadStix')}</button>{stix.isSuccess && <span role="status" className="copy-feedback">{t('stixReady')}</span>}{stix.isError && <div className="form-error" role="alert">{t('stixFailed')}</div>}</article><DetailList title={t('observableAssessment')} items={query.data.indicators.map((item) => `${localizedRoleLabel(item.semantic_role,t)} · ${localizedAssessmentLabel(item.assessment,t)} · ${item.type}: ${item.value}`)} /><DetailList title={t('entities')} items={query.data.entities.map((item) => `${item.type}: ${item.value}`)} /><DetailList title={t('relationships')} items={query.data.relationships.map((item) => `${item.subject} — ${item.relation} — ${item.object}`)} />{attack.data && <AttackResults data={attack.data} eventId={eventId} />}{attack.isError && <div className="notice"><span className="notice-mark">i</span><div><strong>{t('attackAnalysisFailed')}</strong><p>{t('attackFailureNonBlocking')}</p></div></div>}</>}</section>; }
function DetailList({ title, items }: { title: string; items: string[] }) { const {t}=useI18n();return <section className="detail-list"><h3>{title}</h3>{items.length ? <ul>{items.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul> : <p>{t('noData')}</p>}</section>; }

type Translate = (key: TranslationKey, values?: Record<string, string | number>) => string;
const localizedSeverity = (value: string | null | undefined, t: Translate) => value && ['critical','high','medium','low'].includes(value) ? t(value as TranslationKey) : value || t('unspecifiedState');
const localizedProcessingState = (value: string, t: Translate) => value === 'transformed' ? t('transformed') : value;
const localizedRoleLabel = (value: string, t: Translate) => { const keys: Record<string, TranslationKey> = { external_reference: 'externalReference', vulnerability: 'vulnerability', observable: 'observable', indicator: 'threatIndicator' }; return keys[value] ? t(keys[value]) : value; };
const localizedAssessmentLabel = (value: string, t: Translate) => { const keys: Record<string, TranslationKey> = { reference: 'referenceOnly', non_actionable: 'nonActionable', unknown: 'unknownAssessment', suspicious: 'suspicious', malicious: 'malicious' }; return keys[value] ? t(keys[value]) : value; };

const roleLabel = localizedRoleLabel;
const assessmentLabel = localizedAssessmentLabel;
const reasonLabel = (value: string, t: Translate) => { const keys: Record<string, TranslationKey> = { embedded_in_url: 'embeddedInUrl', reference_host: 'referenceHost', vulnerability_id: 'vulnerabilityId', non_global_ip: 'nonGlobalIp', non_global_url_host: 'nonGlobalUrlHost', reserved_domain: 'reservedDomain', locally_administered_mac: 'locallyAdministeredMac', needs_enrichment: 'needsEnrichment', enrichment_verdict: 'enrichmentVerdict', unsupported_type: 'unsupportedType' }; return keys[value] ? t(keys[value]) : value; };

export function IndicatorsPage() {
  const {t,number}=useI18n();
  const [offset, setOffset] = useState(0); const [type, setType] = useState(''); const [role, setRole] = useState(''); const [assessment, setAssessment] = useState(''); const [validation, setValidation] = useState(''); const [search, setSearch] = useState(''); const [copied, setCopied] = useState(''); const limit = 20;
  const summary = useQuery({ queryKey: ['indicator-summary'], queryFn: api.intelligenceIndicatorSummary, retry: false });
  const filters = { type, semantic_role: role, assessment, validation_status: validation, search: search.length >= 2 ? search : '' };
  const query = useQuery({ queryKey: ['indicators', offset, filters], queryFn: () => api.intelligenceIndicators(limit, offset, filters), retry: false });
  async function copy(id: string, value: string) { await navigator.clipboard.writeText(value); setCopied(id); }
  return <section className="page-section intelligence-module"><Heading eyebrow={t('intelligence')} title={t('indicators')} text={t('indicatorsDescription')} />
    {summary.data && <div className="metric-grid compact-metrics">{[[t('allValues'), summary.data.total], [t('observableValues'), summary.data.by_role.observable || 0], [t('externalReferences'), summary.data.by_role.external_reference || 0], [t('vulnerabilities'), summary.data.by_role.vulnerability || 0], [t('verifiedIndicators'), summary.data.by_role.indicator || 0]].map(([label, value]) => <article className="metric-card intel-accent" key={label}><span>{label}</span><strong>{number(Number(value))}</strong></article>)}</div>}
    <div className="notice indicator-notice"><span className="notice-mark">i</span><div><strong>{t('extractionConfidenceNotice')}</strong><p>{t('indicatorPromotionNotice')}</p></div></div>
    <div className="filters"><input aria-label={t('searchIndicators')} value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} placeholder={t('searchValue')} /><input aria-label={t('indicatorType')} value={type} onChange={(e) => { setType(e.target.value); setOffset(0); }} placeholder={t('indicatorTypeHint')} /><select aria-label={t('semanticRole')} value={role} onChange={(e) => { setRole(e.target.value); setOffset(0); }}><option value="">{t('allRoles')}</option><option value="observable">{t('observable')}</option><option value="external_reference">{t('externalReference')}</option><option value="vulnerability">{t('vulnerability')}</option><option value="indicator">{t('threatIndicator')}</option></select><select aria-label={t('assessment')} value={assessment} onChange={(e) => { setAssessment(e.target.value); setOffset(0); }}><option value="">{t('allAssessments')}</option><option value="unknown">{t('unknownAssessment')}</option><option value="reference">{t('referenceOnly')}</option><option value="non_actionable">{t('nonActionable')}</option><option value="suspicious">{t('suspicious')}</option><option value="malicious">{t('malicious')}</option></select><select aria-label={t('valueValidity')} value={validation} onChange={(e) => { setValidation(e.target.value); setOffset(0); }}><option value="">{t('allFormats')}</option><option value="valid">{t('valid')}</option><option value="invalid">{t('invalid')}</option></select></div>
    <PageState query={query} empty={t('noMatchingValues')}><div className="table-shell"><table className="indicator-table"><thead><tr><th>{t('type')}</th><th>{t('value')}</th><th>{t('roleAndAssessment')}</th><th>{t('extractionConfidence')}</th><th>{t('evidence')}</th><th>{t('source')}</th><th>{t('action')}</th></tr></thead><tbody>{query.data?.items.map((item) => <tr key={item.id}><td>{item.type}</td><td><Link to={`/intelligence/events/${item.event_id}`}><code className="indicator-value" dir="ltr">{item.value}</code></Link></td><td><StatusBadge status={item.actionable ? 'warning' : item.validation_status === 'invalid' ? 'unavailable' : 'healthy'} /><strong className="assessment-title">{roleLabel(item.semantic_role,t)}</strong><small>{assessmentLabel(item.assessment,t)} · {reasonLabel(item.reason_code,t)}</small></td><td>{number(Math.round(item.confidence * 100))}%<small>{t('extractionOnly')}</small></td><td>{item.evidence_count ? item.evidence_providers.join(', ') : t('noneRecorded')}<small>{number(Math.round(item.assessment_confidence * 100))}% {t('assessmentConfidence')}</small></td><td>{item.source_pipeline}</td><td><button className="button button-quiet" onClick={() => void copy(item.id, item.value)}>{t('copy')}</button>{copied === item.id && <span role="status">{t('copied')}</span>}</td></tr>)}</tbody></table></div></PageState>{query.data && <Pager total={query.data.total} offset={offset} limit={limit} setOffset={setOffset} />}</section>;
}

function AttackResults({ data, eventId }: { data: Awaited<ReturnType<typeof api.attackMapping>>; eventId: string }) { const {t,number}=useI18n(); const navigator = useMutation({ mutationFn: () => api.attackNavigator(eventId), onSuccess: (layer) => downloadJson(`cti-${eventId}.attack-navigator.json`, layer) }); return <section className="detail-list attack-results"><div className="attack-heading"><h3>MITRE ATT&amp;CK</h3><div className="action-row"><a href={data.official_dataset_url} target="_blank" rel="noreferrer">{data.catalog_version}</a><button className="button button-secondary" disabled={navigator.isPending} onClick={() => navigator.mutate()}>{navigator.isPending ? t('navigatorPreparing') : t('downloadNavigator')}</button></div></div>{navigator.isError && <div className="form-error" role="alert">{t('navigatorFailed')}</div>}{data.techniques.length ? <div className="attack-grid">{data.techniques.map((item) => <article key={item.technique_id}><a href={item.url} target="_blank" rel="noreferrer"><strong dir="ltr">{item.technique_id}</strong> · {item.name}</a><span>{item.tactic} · {item.mapping_source === 'explicit_id' ? t('explicitIdentifier') : t('automatedReviewCandidate')} · {number(Math.round(item.confidence * 100))}%</span><p>{item.evidence}</p></article>)}</div> : <p>{t('noSupportedTechnique')}</p>}</section>; }

export function AttackPage() { const {t}=useI18n();const [eventOffset, setEventOffset] = useState(0); const [eventSearch, setEventSearch] = useState(''); const [eventId, setEventId] = useState(''); const eventLimit = 20; const events = useQuery({ queryKey: ['attack-events', eventOffset, eventSearch], queryFn: () => api.intelligenceEvents(eventLimit, eventOffset, { search: eventSearch.length >= 2 ? eventSearch : '' }), retry: false }); const mapping = useQuery({ queryKey: ['attack-mapping', eventId], queryFn: () => api.attackMapping(eventId), enabled: Boolean(eventId), retry: false }); return <section className="page-section intelligence-module"><Heading eyebrow={t('attackEyebrow')} title="MITRE ATT&CK" text={t('attackDescription')} /><nav className="integration-links" aria-label="MITRE ATT&CK resources"><a href="https://attack.mitre.org/matrices/enterprise/" target="_blank" rel="noreferrer">Matrix</a><a href="https://attack.mitre.org/campaigns/" target="_blank" rel="noreferrer">Campaigns</a><a href="https://attack.mitre.org/groups/" target="_blank" rel="noreferrer">Groups</a><a href="https://attack.mitre.org/software/" target="_blank" rel="noreferrer">Software</a><a href="https://mitre-attack.github.io/attack-navigator/v3/enterprise/" target="_blank" rel="noreferrer">Navigator</a></nav><div className="select-block"><label htmlFor="attack-event-search">{t('searchEvents')}</label><input id="attack-event-search" value={eventSearch} onChange={(e) => { setEventSearch(e.target.value); setEventOffset(0); setEventId(''); }} placeholder={t('minimumTwoCharacters')} /><label htmlFor="attack-event-select">{t('event')}</label><select id="attack-event-select" value={eventId} onChange={(e) => setEventId(e.target.value)}><option value="">{t('chooseEventForAnalysis')}</option>{events.data?.items.map((event) => <option value={event.id} key={event.id}>{event.title}</option>)}</select></div>{events.isLoading && <LoadingState label={t('loadingEvents')} />}{events.isError && <ErrorState onRetry={() => void events.refetch()} />}{events.data?.items.length === 0 && <EmptyState label={t('noEvents')} />}{events.data && <Pager total={events.data.total} offset={eventOffset} limit={eventLimit} setOffset={(value) => { setEventOffset(value); setEventId(''); }} />}{mapping.isLoading && <LoadingState label={t('mappingAttack')} />}{mapping.isError && <ErrorState onRetry={() => void mapping.refetch()} />}{mapping.data && <AttackResults data={mapping.data} eventId={eventId} />}</section>; }

const correlationBasisLabel = (value: string, t: Translate) => ({ exact_observable_match: t('exactObservableMatch'), normalized_text_similarity: t('normalizedTextSimilarity'), recorded_correlation: t('recordedCorrelation') }[value] || value);
const correlationFactorLabel = (factor: CTICorrelationFactor, t: Translate) => ({ shared_observable: t('sharedObservable'), algorithm: t('algorithm'), threshold: t('minimumScore'), method: t('correlationMethod') }[factor.kind]);
function CorrelationEndpoint({ label, endpoint }: { label: string; endpoint: CTICorrelationEndpoint }) { const {t,number}=useI18n(); return <section className="correlation-endpoint"><span>{label}</span><Link to={`/intelligence/events/${encodeURIComponent(endpoint.event_id)}`}>{endpoint.title}</Link><div><span className={`pipeline-chip pipeline-${endpoint.source_pipeline}`}>{endpoint.source_pipeline}</span><span>{endpoint.source_name || endpoint.source_type}</span><span>{t('risk')}: {number(endpoint.risk_score)}</span></div></section>; }

export function CorrelationsPage() {
  const {t,number,dateTime}=useI18n();
  const [offset, setOffset] = useState(0);
  const limit = 20;
  const query = useQuery({ queryKey: ['correlations', offset], queryFn: () => api.intelligenceCorrelations(limit, offset), retry: false });
  return <section className="page-section intelligence-module correlation-evidence-page">
    <Heading eyebrow={t('intelligence')} title={t('correlations')} text={t('correlationsDescription')} />
    <div className="notice"><span className="notice-mark">i</span><div><strong>{t('evidenceFirst')}</strong><p>{t('correlationEvidenceNotice')}</p></div></div>
    <PageState query={query} empty={t('noData')}>
      <div className="correlation-list">
        {query.data?.items.map((item) => <article className={`correlation-card ${item.cross_source ? 'cross-source' : ''}`} key={item.id}>
          <header>
            <div>
              <span className={`correlation-scope ${item.cross_source ? 'cross-source' : ''}`}>{item.cross_source ? t('crossSourceCorrelation') : t('withinPipelineCorrelation')}</span>
              <h3>{correlationBasisLabel(item.score_basis,t)}</h3>
              <p>{item.reason}</p>
            </div>
            <div className="correlation-score"><strong>{number(Math.round(item.score * 100))}%</strong><span>{t('correlationStrength')}</span></div>
          </header>
          <div className="correlation-path">
            <CorrelationEndpoint label={t('sourceEvent')} endpoint={item.source_event} />
            <span className="correlation-arrow" aria-hidden="true">&harr;</span>
            <CorrelationEndpoint label={t('targetEvent')} endpoint={item.target_event} />
          </div>
          <section className="correlation-factors">
            <div><h4>{t('evidenceFactors')}</h4><span>{t(`evidence${item.evidence_status[0].toUpperCase()}${item.evidence_status.slice(1)}` as TranslationKey)}</span></div>
            {item.factors.length ? <ul>{item.factors.map((factor, index) => <li key={`${factor.kind}-${factor.label}-${index}`}><span>{correlationFactorLabel(factor,t)} &middot; {factor.label}</span><code dir="auto">{factor.value}</code></li>)}</ul> : <p>{t('noEvidenceFactors')}</p>}
          </section>
          <time dateTime={item.created_at}>{dateTime(item.created_at)}</time>
        </article>)}
      </div>
    </PageState>
    {query.data && <Pager total={query.data.total} offset={offset} limit={limit} setOffset={setOffset} />}
  </section>;
}
export function OutliersPage() { const {t,number,dateTime}=useI18n();const [offset, setOffset] = useState(0); const limit = 20; const query = useQuery({ queryKey: ['outliers', offset], queryFn: () => api.intelligenceOutliers(limit, offset), retry: false }); return <SimpleListPage title={t('outliers')} text={t('outliersDescription')} query={query} offset={offset} limit={limit} setOffset={setOffset} headers={[t('start'), t('end'), t('alerts'), t('score'), t('status')]} rows={query.data?.items.map((item) => [dateTime(item.started_at), dateTime(item.ended_at), number(item.alert_count), number(item.anomaly_score), item.is_outlier ? t('outlier') : t('normal')]) || []} />; }
function SimpleListPage({ title, text, query, offset, limit, setOffset, headers, rows }: { title: string; text: string; query: ReturnType<typeof useQuery<Page<unknown>>>; offset: number; limit: number; setOffset: (v: number) => void; headers: string[]; rows: string[][] }) { const {t}=useI18n();return <section className="page-section intelligence-module"><Heading eyebrow={t('intelligence')} title={title} text={text} /><PageState query={query} empty={t('noData')}><div className="table-shell"><table><thead><tr>{headers.map((item) => <th key={item}>{item}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>)}</tbody></table></div></PageState>{query.data && <Pager total={query.data.total} offset={offset} limit={limit} setOffset={setOffset} />}</section>; }

const mlRuntimeLabels: Record<string, TranslationKey> = {
  primary_active: 'primaryActive',
  secondary_fallback_active: 'fallbackActive',
  unavailable: 'modelUnavailable',
};
const mlGateLabels: Record<string, TranslationKey> = {
  bert_artifact_present: 'bertArtifactPresent',
  secondary_artifact_present: 'secondaryArtifactPresent',
  bert_test_f1_at_least_0_75: 'bertTestF1Gate',
  bert_test_accuracy_at_least_0_90: 'bertTestAccuracyGate',
  primary_outperforms_secondary_entity_f1: 'primaryOutperformsSecondaryGate',
  bert_unique_unseen_f1_at_least_0_73: 'bertUniqueUnseenGate',
  dataset_cross_split_overlap_zero: 'datasetOverlapGate',
  dataset_label_conflicts_zero: 'datasetConflictGate',
  dataset_malformed_lines_zero: 'datasetMalformedGate',
};
const mlLimitationLabels: Record<string, TranslationKey> = {
  saved_metrics_not_live_accuracy: 'savedMetricsNotLiveAccuracy',
  quality_gates_incomplete: 'qualityGatesIncomplete',
  primary_unavailable: 'primaryUnavailable',
  fallback_unavailable: 'fallbackUnavailable',
};

function ModelEvidence({ data }: { data: Awaited<ReturnType<typeof api.mlStatus>> }) {
  const { t, number } = useI18n();
  const percentage = (value: number | undefined) => value === undefined ? t('noneRecorded') : `${number(Math.round(value * 100))}%`;
  return <>
    <div className="metric-grid">
      <article className="metric-card analysis-accent"><span>{t('analysisBackend')}</span><strong>{data.backend}</strong><small>{data.primary_model}</small></article>
      <article className="metric-card"><span>{t('runtimeState')}</span><strong>{t(mlRuntimeLabels[data.runtime_state])}</strong><small>{t('inferenceScope')}: {t('namedEntityRecognition')}</small></article>
      <article className="metric-card"><span>{t('modelReadiness')}</span><StatusBadge status={data.readiness} /><small>{data.quality_gates_passed ? t('successful') : t('incomplete')}</small></article>
    </div>
    <article className="detail-panel ml-evidence-panel">
      <h3>{t('modelEvidence')}</h3>
      <p>{t('offlineEvaluationScope')}</p>
      <div className="ml-model-grid">
        <div><span>{t('primaryModel')}</span><strong>{data.primary_model}</strong><small>{data.primary_loaded ? t('available') : t('unavailableAccess')}</small></div>
        <div><span>{t('secondaryModel')}</span><strong>{data.secondary_model}</strong><small>{data.secondary_loaded ? t('available') : t('unavailableAccess')}</small></div>
        <div><span>{t('heldOutF1')}</span><strong>{percentage(data.held_out_f1)}</strong></div>
        <div><span>{t('uniqueUnseenF1')}</span><strong>{percentage(data.unique_unseen_f1)}</strong></div>
        <div><span>{t('inferenceEvidence')}</span><strong>{data.inference_evidence.observed ? t('inferenceObserved') : t('noInferenceObserved')}</strong><small>{t('inferenceCounts',{inputs:number(data.inference_evidence.input_count),chunks:number(data.inference_evidence.chunk_count)})}</small></div>
      </div>
      <h4>{t('qualityGates')}</h4>
      <ul className="ml-gate-list">{data.quality_gates.map((gate) => <li key={gate.key}><span>{t(mlGateLabels[gate.key])}</span><strong className={gate.passed ? 'ml-gate-passed' : 'ml-gate-failed'}>{gate.passed ? t('successful') : t('incomplete')}</strong></li>)}</ul>
      <h4>{t('modelLimitations')}</h4>
      <ul className="ml-limitations">{data.limitations.map((limitation) => <li key={limitation}>{t(mlLimitationLabels[limitation])}</li>)}</ul>
    </article>
  </>;
}

export function AnalysisPage() {
  const {t,number}=useI18n();
  const ml = useQuery({ queryKey: ['ml-status'], queryFn: api.mlStatus, retry: false });
  const [offset, setOffset] = useState(0);
  const limit = 20;
  const runs = useQuery({ queryKey: ['analysis-runs', offset], queryFn: () => api.analysisRuns(limit, offset), retry: false });
  const [selected, setSelected] = useState('');
  const detail = useQuery({ queryKey: ['analysis-run', selected], queryFn: () => api.analysisRun(selected), enabled: Boolean(selected), retry: false });
  return <section className="page-section analysis-module">
    <Heading eyebrow={t('analysisEyebrow')} title={t('analysisOperations')} text={t('analysisExecutionModel')} />
    {ml.isLoading && <LoadingState />}
    {ml.isError && <ErrorState onRetry={() => void ml.refetch()} />}
    {ml.data && <ModelEvidence data={ml.data} />}
    <h3 className="subheading">{t('runHistory')}</h3>
    {runs.isLoading && <LoadingState />}
    {runs.isError && <ErrorState onRetry={() => void runs.refetch()} />}
    {runs.data?.items.length === 0 && <EmptyState label={t('noAnalysisRuns')} />}
    {runs.data && runs.data.items.length > 0 && <>
      <div className="table-shell"><table><thead><tr><th>{t('analysisRun')}</th><th>{t('pipeline')}</th><th>{t('status')}</th><th>{t('processed')}</th><th>{t('duration')}</th></tr></thead><tbody>{runs.data.items.map((run) => <tr key={run.id}><td><button className="button button-quiet" onClick={() => setSelected(run.id)}>{run.id.slice(0, 8)}</button></td><td>{run.pipeline}</td><td><StatusBadge status={run.status} /></td><td>{number(run.processed)} / {number(run.failed)}</td><td>{run.duration_seconds === undefined ? t('inProgress') : t('secondsShort',{value:number(run.duration_seconds)})}</td></tr>)}</tbody></table></div>
      <Pager total={runs.data.total} offset={offset} limit={limit} setOffset={setOffset} />
    </>}
    {detail.isLoading && <LoadingState label={t('loadingRunDetails')} />}
    {detail.isError && <ErrorState onRetry={() => void detail.refetch()} />}
    {detail.data && <article className="detail-panel"><h3>{t('selectedRunDetails')}</h3><p>{t('runCounters',{collected:number(detail.data.collected),processed:number(detail.data.processed),stored:number(detail.data.stored),failed:number(detail.data.failed)})}</p>{detail.data.error_category && <p>{t('errorCategory')}: {detail.data.error_category}</p>}</article>}
  </section>;
}

export { MISPPage } from './MISP';
