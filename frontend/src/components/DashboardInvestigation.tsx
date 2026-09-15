import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { useI18n } from '../i18n/I18nContext';
import { EmptyState, ErrorState, LoadingState } from './States';
import { StatusBadge } from './StatusBadge';

const drilldowns = [
  { to: '/intelligence/events', key: 'events' },
  { to: '/intelligence/indicators', key: 'indicators' },
  { to: '/external-sources', key: 'sources' },
  { to: '/analysis', key: 'analysisRuns' },
] as const;

export function DashboardInvestigation() {
  const { t, number, dateTime } = useI18n();
  const latest = useQuery({
    queryKey: ['dashboard-latest-events'],
    queryFn: () => api.intelligenceEvents(5, 0),
    retry: false,
  });

  return (
    <section className="dashboard-investigation" aria-labelledby="dashboard-latest-events">
      <nav className="dashboard-drilldowns" aria-label={t('quickActions')}>
        {drilldowns.map((item) => (
          <Link className="button button-secondary" key={item.to} to={item.to}>
            {t(item.key)}
          </Link>
        ))}
      </nav>

      <div className="section-heading compact-heading">
        <div>
          <span className="eyebrow">{t('intelligence')}</span>
          <h2 id="dashboard-latest-events">{t('latestEvents')}</h2>
          <p>{t('eventsDescription')}</p>
        </div>
        <Link className="button button-secondary" to="/intelligence/events">{t('viewDetails')}</Link>
      </div>

      {latest.isLoading && <LoadingState label={t('loadingStatistics')} />}
      {latest.isError && <ErrorState onRetry={() => void latest.refetch()} />}
      {latest.data && latest.data.items.length === 0 && <EmptyState label={t('noEvents')} />}
      {latest.data && latest.data.items.length > 0 && (
        <div className="dashboard-event-list">
          {latest.data.items.map((event) => (
            <Link className="dashboard-event-row" key={event.id} to={`/intelligence/events/${encodeURIComponent(event.id)}`}>
              <div className="dashboard-event-copy">
                <strong>{event.title}</strong>
                <small>{event.source_type} · {dateTime(event.first_seen || event.created_at)}</small>
              </div>
              <div className="dashboard-event-facts">
                <StatusBadge status={event.severity || 'unknown'} />
                <span>{t('risk')}: <strong>{number(Math.round(event.risk_score))}</strong></span>
                <span className={`pipeline-chip pipeline-${event.source_pipeline}`}>{event.source_pipeline}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </section>
  );
}
