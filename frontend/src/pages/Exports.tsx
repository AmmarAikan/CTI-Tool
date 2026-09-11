import { useQuery } from '@tanstack/react-query';
import { api, ApiError } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import './ExternalFeatures.css';
import { useI18n } from '../i18n/I18nContext';

function Failure({ error, retry }: { error: Error; retry: () => void }) {
  const {t}=useI18n();
  if (error instanceof ApiError && error.status === 404 && error.code === 'export_not_found') return <EmptyState label={t('noExport')} />;
  if (error instanceof ApiError && error.status === 401) return <div className="state-panel error-panel" role="alert">{t('sessionExpired')}</div>;
  if (error instanceof TypeError || (error instanceof ApiError && (error.status === 408 || error.status === 503))) return <div className="state-panel error-panel" role="alert"><strong>{t('exportUnavailable')}</strong><button className="button button-secondary" onClick={retry}>{t('retry')}</button></div>;
  return <ErrorState onRetry={retry} />;
}

export function Exports() {
  const {t,number,dateTime}=useI18n();
  const query = useQuery({ queryKey: ['external-export-latest'], queryFn: api.latestExternalExport, retry: false });
  const value = query.data;
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">{t('exports')} / 05</span><h2>{t('latestExport')}</h2><p>{t('exportDescription')}</p></div>{value && <StatusBadge status={value.status} />}</div>
    {query.isLoading && <LoadingState label={t('loadingExport')} />}{query.isError && <Failure error={query.error} retry={() => void query.refetch()} />}
    {value && <div className="metric-grid"><article className="metric-card"><span>{t('acceptedRecords')}</span><strong>{number(value.accepted_records)}</strong></article><article className="metric-card"><span>{t('reviewRecords')}</span><strong>{number(value.review_records)}</strong></article><article className="metric-card"><span>{t('completedAt')}</span><strong className="compact-value">{value.completed_at ? dateTime(value.completed_at) : t('notAvailable')}</strong></article></div>}
    {value && <div className="safe-summary"><dl><div><dt>{t('runId')}</dt><dd><code>{value.run_id}</code></dd></div><div><dt>{t('sha256')}</dt><dd><code>{value.dataset_sha256 ? `${value.dataset_sha256.slice(0, 12)}…${value.dataset_sha256.slice(-8)}` : t('notAvailable')}</code></dd></div></dl><p className="muted-text">{t('downloadUnavailable')}</p></div>}
  </section>;
}
