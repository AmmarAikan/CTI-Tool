import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, type StorylineLimitation, type StorylineMilestone, type StorylineResponse, type StorylineRiskFactorKey } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';
const milestoneLabels: Record<StorylineMilestone['kind'], TranslationKey> = {
  observed: 'storyObserved',
  last_observed: 'storyLastObserved',
  processed: 'storyProcessed',
  correlated: 'storyCorrelated',
  attack_mapping: 'storyAttackMapping',
};
const evidenceStatusLabels: Record<StorylineMilestone['evidence_status'], TranslationKey> = {
  recorded: 'storyRecorded',
  derived: 'storyDerived',
  candidate: 'storyCandidate',
};
const limitationLabels: Record<StorylineLimitation, TranslationKey> = {
  chronology_not_causality: 'storyChronologyLimitation',
  attack_candidates_require_review: 'storyAttackLimitation',
  internal_raw_telemetry_hidden: 'storyInternalPrivacyLimitation',
  bounded_evidence: 'storyBoundedLimitation',
};
const riskFactorLabels: Record<StorylineRiskFactorKey, TranslationKey> = {
  base_severity_or_cvss: 'riskBase',
  indicators: 'riskIndicators',
  confidence: 'riskConfidence',
  source_diversity: 'riskSourceDiversity',
  correlations: 'riskCorrelations',
  internal_outlier: 'riskOutlier',
};
const assessmentLabels: Record<string, TranslationKey> = {
  reference: 'referenceOnly',
  non_actionable: 'nonActionable',
  unknown: 'unknownAssessment',
  suspicious: 'suspicious',
  malicious: 'malicious',
};

function StoryMilestone({ item }: { item: StorylineMilestone }) {
  const { t, number, dateTime } = useI18n();
  return (
    <li className={`story-milestone story-${item.kind}`}>
      <span className="story-node" aria-hidden="true" />
      <article>
        <header>
          <div>
            <span className="eyebrow">{t(milestoneLabels[item.kind])}</span>
            <h3>
              {item.related_event_id
                ? <Link to={`/intelligence/events/${encodeURIComponent(item.related_event_id)}`}>{item.title}</Link>
                : item.title}
            </h3>
          </div>
          <time dateTime={item.occurred_at}>{item.occurred_at ? dateTime(item.occurred_at) : t('timeNotRecorded')}</time>
        </header>
        <p>{item.detail}</p>
        <footer>
          <span className={`pipeline-chip pipeline-${item.source_pipeline}`}>{item.source_pipeline}</span>
          <span>{t(evidenceStatusLabels[item.evidence_status])}</span>
          {item.confidence !== undefined && <span>{t('confidence')}: {number(Math.round(item.confidence * 100))}%</span>}
          {item.score !== undefined && <span>{t('correlationStrength')}: {number(Math.round(item.score * 100))}%</span>}
        </footer>
      </article>
    </li>
  );
}

function EvidenceList({ data }: { data: StorylineResponse }) {
  const { t, number } = useI18n();
  return (
    <div className="story-evidence-grid">
      <section className="story-evidence-card">
        <h3>{t('observableAssessment')}</h3>
        {data.observables.length ? (
          <ul>
            {data.observables.map((item) => (
              <li key={item.id}>
                <code dir="auto">{item.type}: {item.value}</code>
                <span>{t(assessmentLabels[item.assessment] || 'unknownAssessment')} &middot; {number(Math.round(item.confidence * 100))}%</span>
              </li>
            ))}
          </ul>
        ) : <p>{t('noData')}</p>}
      </section>
      <section className="story-evidence-card">
        <h3>{t('entitiesAndRelationships')}</h3>
        {!data.entities.length && !data.relationships.length && <p>{t('noData')}</p>}
        <ul>
          {data.entities.map((item, index) => <li key={`entity-${index}`}><strong>{item.type}</strong><span>{item.value}</span></li>)}
          {data.relationships.map((item, index) => <li key={`relationship-${index}`}><strong>{item.relation}</strong><span>{item.subject} &rarr; {item.object}</span></li>)}
        </ul>
      </section>
      <section className="story-evidence-card">
        <h3>{t('explainableRisk')}</h3>
        <p>{t('deterministicRiskNotice')}</p>
        {data.risk_factors.length ? (
          <ul>
            {data.risk_factors.map((item) => <li key={item.key}><span>{t(riskFactorLabels[item.key])}</span><strong>+{number(item.value)}</strong></li>)}
          </ul>
        ) : <p>{t('riskFactorsUnavailable')}</p>}
        <div className="story-risk-context">
          <span>{t('sourceCount')}: {data.risk_context.source_count === undefined ? t('notRecorded') : number(data.risk_context.source_count)}</span>
          <span>{t('correlationCount')}: {data.risk_context.correlation_count === undefined ? t('notRecorded') : number(data.risk_context.correlation_count)}</span>
        </div>
      </section>
    </div>
  );
}

function RelatedEvidence({ data }: { data: StorylineResponse }) {
  const { t, number } = useI18n();
  return (
    <div className="story-related-grid">
      <section className="story-evidence-card">
        <h3>{t('relatedCorrelations')}</h3>
        {data.correlations.length ? data.correlations.map((item) => {
          const related = item.source_event_id === data.event.id ? item.target_event : item.source_event;
          return (
            <article className="story-related-item" key={item.id}>
              <div>
                <span className={`correlation-scope ${item.cross_source ? 'cross-source' : ''}`}>{item.cross_source ? t('crossSourceCorrelation') : t('withinPipelineCorrelation')}</span>
                <Link to={`/intelligence/events/${encodeURIComponent(related.event_id)}`}>{related.title}</Link>
              </div>
              <strong>{number(Math.round(item.score * 100))}%</strong>
              {item.factors.map((factor, index) => <code dir="auto" key={`${factor.kind}-${index}`}>{factor.label}: {factor.value}</code>)}
            </article>
          );
        }) : <p>{t('noRelatedCorrelations')}</p>}
      </section>
      <section className="story-evidence-card">
        <h3>MITRE ATT&amp;CK</h3>
        {data.attack.techniques.length ? data.attack.techniques.map((item) => (
          <article className="story-related-item" key={item.technique_id}>
            <div>
              <span>{item.tactic}</span>
              <a href={item.url} target="_blank" rel="noreferrer">{item.technique_id} &middot; {item.name}</a>
            </div>
            <strong>{number(Math.round(item.confidence * 100))}%</strong>
            <p>{item.mapping_source === 'explicit_id' ? t('explicitIdentifier') : t('automatedReviewCandidate')}</p>
          </article>
        )) : <p>{t('noSupportedTechnique')}</p>}
      </section>
    </div>
  );
}

function StorylineView({ data }: { data: StorylineResponse }) {
  const { t, number, dateTime } = useI18n();
  const counts: Array<[TranslationKey, number]> = [
    ['allObservables', data.evidence_counts.observables],
    ['entities', data.evidence_counts.entities],
    ['relationships', data.evidence_counts.relationships],
    ['correlations', data.evidence_counts.correlations],
    ['attackMappings', data.evidence_counts.attack_mappings],
  ];
  return (
    <>
      <article className="story-hero">
        <div>
          <span className="eyebrow">{t('storyEvidenceOverview')}</span>
          <h2>{data.event.title}</h2>
          <p>{data.event.summary}</p>
          <div className="story-provenance">
            <span className={`pipeline-chip pipeline-${data.event.source_pipeline}`}>{data.event.source_pipeline}</span>
            <span>{data.source_name || data.event.source_type}</span>
            <span>{t('observedAt')}: {dateTime(data.event.first_seen || data.event.created_at)}</span>
          </div>
        </div>
        <div className="story-risk-score">
          <span>{t('risk')}</span>
          <strong>{number(Math.round(data.event.risk_score))}</strong>
          <small>{data.event.severity || t('unspecifiedState')}</small>
        </div>
      </article>
      <div className="metric-grid compact-metrics story-counts">
        {counts.map(([label, value]) => <article className="metric-card intel-accent" key={label}><span>{t(label)}</span><strong>{number(value)}</strong></article>)}
      </div>
      <section className="story-limitations" aria-label={t('analysisLimits')}>
        {data.limitations.map((item) => <p key={item}>{t(limitationLabels[item])}</p>)}
      </section>
      <section className="story-timeline-section">
        <div className="section-heading compact-heading"><div><span className="eyebrow">{t('chronology')}</span><h2>{t('evidenceTimeline')}</h2><p>{t('timelineDescription')}</p></div></div>
        <ol className="story-timeline">{data.milestones.map((item) => <StoryMilestone item={item} key={item.id} />)}</ol>
      </section>
      <EvidenceList data={data} />
      <RelatedEvidence data={data} />
      {data.evidence_truncated && <p className="notice">{t('storyBoundedLimitation')}</p>}
    </>
  );
}

export function ThreatStorylinePage() {
  const { t } = useI18n();
  const { eventId = '' } = useParams();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const events = useQuery({
    queryKey: ['storyline-events', search],
    queryFn: () => api.intelligenceEvents(20, 0, { search: search.length >= 2 ? search : '' }),
    retry: false,
  });
  const storyline = useQuery({
    queryKey: ['threat-storyline', eventId],
    queryFn: () => api.intelligenceStoryline(eventId),
    enabled: Boolean(eventId),
    retry: false,
  });
  const selectedListed = events.data?.items.some((item) => item.id === eventId);
  const selectEvent = (value: string) => navigate(value ? `/intelligence/storyline/${encodeURIComponent(value)}` : '/intelligence/storyline');

  return (
    <section className="page-section intelligence-module storyline-page">
      <div className="section-heading">
        <div><span className="eyebrow">{t('storylineEyebrow')}</span><h2>{t('storyline')}</h2><p>{t('storylineDescription')}</p></div>
      </div>
      <div className="notice"><span className="notice-mark">i</span><div><strong>{t('evidenceNotAssumption')}</strong><p>{t('storyChronologyLimitation')}</p></div></div>
      <div className="story-selector">
        <label htmlFor="storyline-search">{t('searchEvents')}</label>
        <input id="storyline-search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t('minimumTwoCharacters')} />
        <label htmlFor="storyline-event">{t('selectedEventForStoryline')}</label>
        <select id="storyline-event" value={eventId} onChange={(event) => selectEvent(event.target.value)}>
          <option value="">{t('chooseEventForStoryline')}</option>
          {eventId && storyline.data && !selectedListed && <option value={eventId}>{storyline.data.event.title}</option>}
          {events.data?.items.map((item) => <option value={item.id} key={item.id}>{item.title}</option>)}
        </select>
      </div>
      {events.isLoading && !eventId && <LoadingState label={t('loadingEvents')} />}
      {events.isError && <ErrorState onRetry={() => void events.refetch()} />}
      {!eventId && events.data?.items.length === 0 && <EmptyState label={t('noEvents')} />}
      {!eventId && events.data && events.data.items.length > 0 && <EmptyState label={t('chooseEventForStoryline')} />}
      {storyline.isLoading && <LoadingState label={t('buildingStoryline')} />}
      {storyline.isError && <ErrorState onRetry={() => void storyline.refetch()} />}
      {storyline.data && <StorylineView data={storyline.data} />}
    </section>
  );
}
