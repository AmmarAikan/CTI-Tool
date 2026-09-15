import { useState, type FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { api, type IntelligenceSearchKind, type IntelligenceSearchResult } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';

const kindLabels: Record<IntelligenceSearchKind, TranslationKey> = {
  event: 'resultEvent',
  indicator: 'resultIndicator',
  entity: 'resultEntity',
  source: 'resultSource',
  correlation: 'resultCorrelation',
};

const matchLabels: Record<IntelligenceSearchResult['match_quality'], TranslationKey> = {
  exact: 'exactMatch',
  prefix: 'prefixMatch',
  contains: 'containsMatch',
};

function resultTarget(result: IntelligenceSearchResult): string {
  if (result.kind === 'source') return result.source_pipeline === 'internal' ? '/internal-sources' : '/external-sources';
  if (result.event_id) return `/intelligence/events/${encodeURIComponent(result.event_id)}`;
  return '/intelligence/correlations';
}

export function IntelligenceSearchPage() {
  const { t, number, dateTime } = useI18n();
  const [params, setParams] = useSearchParams();
  const submitted = (params.get('q') || '').trim();
  const [input, setInput] = useState(submitted);
  const [invalid, setInvalid] = useState(false);
  const isValid = submitted.length >= 2 && submitted.length <= 100;
  const search = useQuery({
    queryKey: ['intelligence-search', submitted],
    queryFn: () => api.intelligenceSearch(submitted, 5),
    enabled: isValid,
    retry: false,
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = input.trim();
    if (query.length < 2 || query.length > 100) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    setParams({ q: query });
  }

  return (
    <section className="page-section intelligence-module investigation-search">
      <div className="section-heading">
        <div>
          <span className="eyebrow">{t('investigationSearchEyebrow')}</span>
          <h2>{t('investigationSearchTitle')}</h2>
          <p>{t('investigationSearchDescription')}</p>
        </div>
      </div>

      <form className="investigation-search-form" onSubmit={submit} noValidate>
        <label htmlFor="global-intelligence-search">{t('searchAllIntelligence')}</label>
        <div>
          <input
            id="global-intelligence-search"
            value={input}
            onChange={(event) => { setInput(event.target.value); setInvalid(false); }}
            placeholder={t('searchIntelligencePlaceholder')}
            minLength={2}
            maxLength={100}
          />
          <button className="button button-primary" type="submit">{t('runSearch')}</button>
        </div>
        {invalid && <span className="form-error" role="alert">{t('minimumTwoCharacters')}</span>}
      </form>

      {!isValid && !invalid && (
        <div className="notice search-scope-notice">
          <span className="notice-mark">i</span>
          <div><strong>{t('searchCoverage')}</strong><p>{t('searchCoverageDescription')}</p></div>
        </div>
      )}
      {search.isLoading && <LoadingState label={t('searchingIntelligence')} />}
      {search.isError && <ErrorState onRetry={() => void search.refetch()} />}
      {search.data && (
        <section className="search-results" aria-live="polite" aria-labelledby="search-results-heading">
          <div className="section-heading compact-heading">
            <div>
              <span className="eyebrow">{t('searchResultsCount', { count: number(search.data.returned) })}</span>
              <h2 id="search-results-heading">{t('searchResultsFor', { query: search.data.query })}</h2>
            </div>
          </div>
          {search.data.truncated && <div className="notice"><span className="notice-mark">i</span><p>{t('searchTruncated')}</p></div>}
          {search.data.items.length === 0 ? <EmptyState label={t('noIntelligenceMatches')} /> : (
            <div className="search-result-list">
              {search.data.items.map((result) => (
                <article className="search-result-card" key={`${result.kind}-${result.id}`}>
                  <div className="search-result-main">
                    <div className="search-result-meta">
                      <span className={`search-kind search-kind-${result.kind}`}>{t(kindLabels[result.kind])}</span>
                      <span>{t(matchLabels[result.match_quality])}</span>
                      {result.severity && <StatusBadge status={result.severity} />}
                    </div>
                    <Link className="search-result-label" to={resultTarget(result)} dir="auto">{result.label}</Link>
                    <p>{result.context}</p>
                    <div className="search-provenance">
                      <span>{t('provenance')}: <strong>{result.source_name || result.source_type || t('notAvailable')}</strong></span>
                      {result.source_pipeline && <span className={`pipeline-chip pipeline-${result.source_pipeline}`}>{result.source_pipeline}</span>}
                      {result.confidence !== undefined && <span>{t('confidence')}: {number(Math.round(result.confidence * 100))}%</span>}
                      {result.created_at && <time dateTime={result.created_at}>{dateTime(result.created_at)}</time>}
                    </div>
                  </div>
                  <div className="search-result-actions">
                    <Link className="button button-secondary" to={resultTarget(result)}>{t('openRecord')}</Link>
                    {result.related_event_id && <Link className="button button-quiet" to={`/intelligence/events/${encodeURIComponent(result.related_event_id)}`}>{t('relatedEvent')}</Link>}
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </section>
  );
}
