import './SystemReadiness.css';
import { useQueries, useQuery } from '@tanstack/react-query';
import { api, type HealthResponse, type InternalIntegration } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { useI18n } from '../i18n/I18nContext';

type CheckState = 'healthy' | 'degraded' | 'unconfigured' | 'unavailable';
type Check = { id: string; title: string; state: CheckState; detail: string };

function integrationState(value: HealthResponse): CheckState {
  if (!value.configured) return 'unconfigured';
  if (!value.reachable) return 'unavailable';
  return value.contract_valid === false ? 'degraded' : 'healthy';
}

export function SystemReadiness() {
  const { t, number, dateTime } = useI18n();
  const system = useQuery({ queryKey: ['system-health'], queryFn: api.systemHealth, retry: false });
  const external = useQuery({ queryKey: ['external-health'], queryFn: api.externalHealth, retry: false });
  const internalNames: Array<[InternalIntegration, string]> = [
    ['dionaea', 'Dionaea'], ['host-auth', t('hostAuth')], ['web-access', t('webAccess')],
  ];
  const internal = useQueries({ queries: internalNames.map(([id]) => ({
    queryKey: ['internal-health', id], queryFn: () => api.internalHealth(id), retry: false,
  })) });
  const misp = useQuery({ queryKey: ['misp-health'], queryFn: api.mispHealth, retry: false });
  const ml = useQuery({ queryKey: ['ml-status'], queryFn: api.mlStatus, retry: false });
  const summary = useQuery({ queryKey: ['dashboard-summary'], queryFn: api.dashboardSummary, retry: false });

  const checks: Check[] = [];
  if (system.data) checks.push({
    id: 'backend', title: t('readinessBackend'),
    state: system.data.database && system.data.status === 'ok' ? 'healthy' : 'degraded',
    detail: t(system.data.database ? 'readinessDatabaseAvailable' : 'readinessDatabaseUnavailable'),
  });
  if (external.data) checks.push({
    id: 'external', title: t('external'), state: integrationState(external.data),
    detail: t('readinessExternalDetail'),
  });
  internal.forEach((query, index) => {
    if (query.data) checks.push({
      id: internalNames[index][0], title: internalNames[index][1],
      state: integrationState(query.data), detail: t('readinessInternalDetail'),
    });
  });
  if (misp.data) checks.push({
    id: 'misp', title: 'MISP',
    state: !misp.data.configured ? 'unconfigured' : misp.data.reachable ? 'healthy' : 'unavailable',
    detail: t('readinessMispDetail'),
  });
  if (ml.data) checks.push({
    id: 'ml', title: t('readinessModel'),
    state: !ml.data.primary_loaded && !ml.data.secondary_loaded ? 'unavailable' : ml.data.quality_gates_passed ? 'healthy' : 'degraded',
    detail: t('readinessModelDetail', {
      backend: ml.data.backend,
      quality: t(ml.data.quality_gates_passed ? 'successful' : 'degraded'),
    }),
  });
  if (summary.data) {
    const externalCount = summary.data.by_pipeline.external || 0;
    const internalCount = summary.data.by_pipeline.internal || 0;
    checks.push({
      id: 'data', title: t('readinessEvidence'),
      state: externalCount > 0 && internalCount > 0 ? 'healthy' : 'degraded',
      detail: t('readinessDataDetail', {
        external: number(externalCount), internal: number(internalCount),
        correlations: number(summary.data.correlations),
      }),
    });
  }

  const loading = [system, external, misp, ml, summary, ...internal].some((query) => query.isLoading);
  const failed = [system, external, misp, ml, summary, ...internal].some((query) => query.isError);
  const refresh = () => {
    void system.refetch(); void external.refetch(); void misp.refetch();
    void ml.refetch(); void summary.refetch();
    internal.forEach((query) => void query.refetch());
  };

  return <section className="page-section">
    <div className="section-heading">
      <div>
        <span className="eyebrow">{t('readinessEyebrow')}</span>
        <h2>{t('systemReadiness')}</h2>
        <p>{t('readinessDescription')}</p>
      </div>
      <div className="refresh-block">
        <small>{t('lastRefresh', { time: dateTime(new Date()) })}</small>
        <button className="button button-secondary" onClick={refresh}>{t('recheckHealth')}</button>
      </div>
    </div>
    <div className="notice"><span className="notice-mark">i</span><div>
      <strong>{t('readinessScopeTitle')}</strong><p>{t('readinessScopeDescription')}</p>
    </div></div>
    {loading && <LoadingState />}
    {failed && <ErrorState onRetry={refresh} />}
    {!loading && checks.length === 0 && <EmptyState label={t('readinessNoEvidence')} />}
    {checks.length > 0 && <div className="readiness-grid">
      {checks.map((check) => <article className="readiness-card" key={check.id}>
        <div className="readiness-card-heading"><h3>{check.title}</h3><StatusBadge status={check.state} /></div>
        <p>{check.detail}</p>
      </article>)}
    </div>}
    <p className="safe-explanation">{t('readinessNoSyntheticData')}</p>
  </section>;
}
