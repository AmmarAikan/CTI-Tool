import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type CVEEnrichmentItem, type StorylineRiskFactorKey } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';
import { ErrorState, LoadingState } from './States';
import { StatusBadge } from './StatusBadge';

const riskFactorLabels: Record<StorylineRiskFactorKey, TranslationKey> = {
  base_severity_or_cvss: 'riskBase',
  indicators: 'riskIndicators',
  confidence: 'riskConfidence',
  source_diversity: 'riskSourceDiversity',
  correlations: 'riskCorrelations',
  internal_outlier: 'riskOutlier',
};

function EnrichmentItem({ item }: { item: CVEEnrichmentItem }) {
  const { t, number, dateTime } = useI18n();
  return <article className="enrichment-item">
    <header>
      <a href={item.nvd_url} target="_blank" rel="noreferrer"><strong dir="ltr">{item.cve_id}</strong></a>
      <StatusBadge status={item.status} />
    </header>
    {item.found && <div className="enrichment-item-facts">
      <span>{t('cvss')}: <strong>{item.cvss_score === undefined ? t('notRecorded') : number(item.cvss_score)}</strong></span>
      <span>{t('severity')}: <strong>{item.severity ? t(item.severity) : t('notRecorded')}</strong></span>
      <span>{t('version')}: <strong>{item.cvss_version || t('notRecorded')}</strong></span>
    </div>}
    {item.description && <p>{item.description}</p>}
    {item.cwes.length > 0 && <p className="enrichment-cwes"><strong>{t('weaknesses')}:</strong> <span dir="ltr">{item.cwes.join(', ')}</span></p>}
    <footer>
      <span>{item.enriched_at ? t('lastEnrichedValue', { value: dateTime(item.enriched_at) }) : t('neverEnriched')}</span>
      <a href={item.nvd_url} target="_blank" rel="noreferrer">{t('openNvd')}</a>
    </footer>
  </article>;
}

export function CVEEnrichmentPanel({ eventId }: { eventId: string }) {
  const { can } = useAuth();
  const { t, number, dateTime } = useI18n();
  const queryClient = useQueryClient();
  const enrichment = useQuery({
    queryKey: ['event-enrichment', eventId],
    queryFn: () => api.intelligenceEnrichment(eventId),
    enabled: Boolean(eventId),
    retry: false,
  });
  const run = useMutation({
    mutationFn: (refresh: boolean) => api.runNVDEnrichment(eventId, refresh),
    onSuccess: (result) => {
      queryClient.setQueryData(['event-enrichment', eventId], result);
      void queryClient.invalidateQueries({ queryKey: ['intel-event', eventId] });
    },
  });
  const data = enrichment.data;
  const refresh = Boolean(data && data.eligible_count > 0 && data.pending_count === 0 && data.failed_count === 0);

  function confirmAndRun() {
    if (window.confirm(t(refresh ? 'confirmNvdRefresh' : 'confirmNvdEnrichment'))) run.mutate(refresh);
  }

  return <section className="detail-list enrichment-panel" aria-labelledby="cve-enrichment-title">
    <div className="enrichment-heading">
      <div><h3 id="cve-enrichment-title">{t('cveEnrichment')}</h3><p>{t('enrichmentDescription')}</p></div>
      <span className="enrichment-provider">{t('nvdEvidenceSource')}</span>
    </div>
    {enrichment.isLoading && <LoadingState label={t('loadingEnrichment')} />}
    {enrichment.isError && <ErrorState onRetry={() => void enrichment.refetch()} />}
    {data && <>
      <div className="enrichment-counts">
        <span>{t('eligibleCves')} <strong>{number(data.eligible_count)}</strong></span>
        <span>{t('storedResults')} <strong>{number(data.completed_count + data.not_found_count)}</strong></span>
        <span>{t('pendingLookups')} <strong>{number(data.pending_count)}</strong></span>
        <span>{t('failedLookups')} <strong>{number(data.failed_count)}</strong></span>
      </div>
      <div className="enrichment-risk">
        <div><span>{t('enrichmentRiskTitle')}</span><strong>{number(data.risk.score)} / 100</strong><small>{t('deterministicEnrichmentRisk')}</small></div>
        <ul>{data.risk.factors.map((factor) => <li key={factor.key}><span>{t(riskFactorLabels[factor.key])}</span><strong>+{number(factor.value)}</strong></li>)}</ul>
      </div>
      {data.last_enriched_at && <p className="enrichment-last">{t('lastEnrichedValue', { value: dateTime(data.last_enriched_at) })}</p>}
      {data.eligible_count === 0 ? <p>{t('noCvesForEnrichment')}</p> : <div className="enrichment-grid">{data.items.map((item) => <EnrichmentItem key={item.indicator_id} item={item} />)}</div>}
      {data.items_truncated && <p className="enrichment-last">{t('enrichmentItemsTruncated')}</p>}
      {can('analyst') && data.eligible_count > 0 && <div className="enrichment-actions"><button className="button button-secondary" disabled={run.isPending} onClick={confirmAndRun}>{run.isPending ? t('enrichingCves') : t(refresh ? 'refreshNvdEnrichment' : 'runNvdEnrichment')}</button><small>{t('enrichmentLookupLimit')}</small></div>}
      {!can('analyst') && data.eligible_count > 0 && <p className="role-note">{t('viewerEnrichmentHint')}</p>}
      {run.isSuccess && <div className="notice" role="status"><span className="notice-mark">✓</span><div><strong>{t('enrichmentRunSummary', { count: number(run.data.attempted_count) })}</strong><p>{run.data.risk_changed ? t('riskChanged', { before: number(run.data.previous_risk_score), after: number(run.data.risk.score) }) : t('riskUnchanged', { score: number(run.data.risk.score) })}</p></div></div>}
      {run.isError && <div className="form-error" role="alert">{t('enrichmentSafeFailure')}</div>}
    </>}
  </section>;
}
