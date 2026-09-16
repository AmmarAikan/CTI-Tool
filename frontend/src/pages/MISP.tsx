import { useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import {
  api,
  ApiError,
  type MISPCandidate,
  type MISPDeliveryStatus,
  type MISPReadinessReason,
} from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';

const MISP_PUBLIC_URL = 'https://cti-gateway-vps.tailf2792f.ts.net:8443';

function Heading({ eyebrow, title, text }: { eyebrow: string; title: string; text: string }) {
  return <div className="section-heading"><div><span className="eyebrow">{eyebrow}</span><h2>{title}</h2><p>{text}</p></div></div>;
}

function Pager({ total, offset, limit, onChange }: { total: number; offset: number; limit: number; onChange: (value: number) => void }) {
  const { t, number } = useI18n();
  return <div className="pagination">
    <button className="button button-secondary" disabled={!offset} onClick={() => onChange(Math.max(0, offset - limit))}>{t('previous')}</button>
    <span>{total ? t('pageRange', { start: number(offset + 1), end: number(Math.min(total, offset + limit)), total: number(total) }) : number(0)}</span>
    <button className="button button-secondary" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>{t('next')}</button>
  </div>;
}

const readinessKeys: Record<MISPReadinessReason, TranslationKey> = {
  ready: 'mispReady',
  misp_unconfigured: 'mispUnconfiguredReason',
  no_transferable_attributes: 'noTransferableAttributes',
};

const statusKeys: Record<MISPDeliveryStatus, TranslationKey> = {
  delivered: 'mispDelivered',
  skipped: 'mispSkipped',
  failed: 'mispFailed',
};

const reasonKeys: Record<string, TranslationKey> = {
  event_not_found: 'mispEventNotFound',
  misp_unconfigured: 'mispUnconfiguredReason',
  no_transferable_attributes: 'noTransferableAttributes',
  preview_failed: 'mispPreviewFailed',
  delivery_failed: 'mispDeliveryFailed',
};

function CandidateCard({
  candidate,
  checked,
  canSend,
  onToggle,
  onReview,
}: {
  candidate: MISPCandidate;
  checked: boolean;
  canSend: boolean;
  onToggle: () => void;
  onReview: () => void;
}) {
  const { t, number, dateTime } = useI18n();
  return <article className={`misp-candidate-card ${candidate.ready ? 'ready' : 'blocked'}`}>
    <header>
      <div className="misp-candidate-title">
        {canSend && <input
          type="checkbox"
          checked={checked}
          disabled={!candidate.ready}
          onChange={onToggle}
          aria-label={t('selectEventForSharing', { title: candidate.title })}
        />}
        <div>
          <Link to={`/intelligence/events/${encodeURIComponent(candidate.event_id)}`}>{candidate.title}</Link>
          <div className="candidate-meta">
            <span className={`pipeline-chip pipeline-${candidate.source_pipeline}`}>{candidate.source_pipeline}</span>
            <StatusBadge status={candidate.severity || 'unknown'} />
            <span>{t('risk')}: {number(candidate.risk_score)}</span>
          </div>
        </div>
      </div>
      <span className={`readiness-badge ${candidate.ready ? 'ready' : 'blocked'}`}>
        {t(readinessKeys[candidate.readiness_reason])}
      </span>
    </header>
    <div className="candidate-counts">
      <span>{t('willSend')} <strong>{number(candidate.included)}</strong></span>
      <span>{t('safelyOmitted')} <strong>{number(candidate.omitted)}</strong></span>
      <span>{t('deliveryAttempts')} <strong>{number(candidate.delivery_count)}</strong></span>
    </div>
    {candidate.last_delivered_at && <p className="candidate-last-delivery">{t('lastDelivered')}: {dateTime(candidate.last_delivered_at)}</p>}
    <div className="action-row">
      <button className="button button-secondary" onClick={onReview}>{t('reviewPreview')}</button>
      {candidate.last_misp_event_id && <a href={`${MISP_PUBLIC_URL}/events/view/${encodeURIComponent(candidate.last_misp_event_id)}`} target="_blank" rel="noreferrer">{t('openMispEvent')}</a>}
    </div>
  </article>;
}

export function MISPPage() {
  const { t, number, dateTime } = useI18n();
  const { user } = useAuth();
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [pipeline, setPipeline] = useState('');
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [reviewId, setReviewId] = useState('');
  const limit = 20;
  const canSend = user?.role === 'admin';

  const health = useQuery({ queryKey: ['misp-health'], queryFn: api.mispHealth, retry: false });
  const candidates = useQuery({
    queryKey: ['misp-candidates', offset, search, pipeline],
    queryFn: () => api.mispCandidates(limit, offset, {
      search: search.length >= 2 ? search : '',
      source_pipeline: pipeline,
    }),
    retry: false,
  });
  const history = useQuery({ queryKey: ['misp-deliveries'], queryFn: () => api.mispDeliveries(), retry: false });
  const preview = useQuery({
    queryKey: ['misp-preview', reviewId],
    queryFn: () => api.mispPreview(reviewId),
    enabled: Boolean(reviewId),
    retry: false,
  });
  const batch = useMutation({
    mutationFn: (eventIds: string[]) => api.mispBatch(eventIds),
    onSuccess: () => {
      setSelected(new Set());
      void candidates.refetch();
      void history.refetch();
    },
  });

  const readyOnPage = useMemo(
    () => candidates.data?.items.filter((item) => item.ready).map((item) => item.event_id) || [],
    [candidates.data],
  );

  function toggle(eventId: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(eventId)) next.delete(eventId);
      else if (next.size < 20) next.add(eventId);
      return next;
    });
  }

  function selectReadyPage() {
    setSelected((current) => {
      const next = new Set(current);
      for (const eventId of readyOnPage) {
        if (next.size >= 20) break;
        next.add(eventId);
      }
      return next;
    });
  }

  function confirmBatch() {
    if (!batch.isPending && selected.size > 0 && window.confirm(t('confirmMispBatch', { count: number(selected.size) }))) {
      batch.mutate([...selected]);
    }
  }

  return <section className="page-section misp-module">
    <Heading eyebrow={t('mispEyebrow')} title="MISP" text={t('mispDescription')} />

    {health.isLoading && <LoadingState />}
    {health.isError && <ErrorState onRetry={() => void health.refetch()} />}
    {health.data && <article className="health-card misp-accent">
      <span>{t('mispHealth')}</span>
      <strong>{!health.data.configured ? t('mispUnconfigured') : health.data.reachable ? t('connected') : t('mispDisconnected')}</strong>
      <StatusBadge status={health.data.reachable ? 'healthy' : health.data.configured ? 'unavailable' : 'disabled'} />
    </article>}

    <article className="detail-panel sharing-guide">
      <h3>{t('peopleToolAccess')}</h3>
      <p>{t('peopleToolAccessDescription')}</p>
      <div className="action-row">
        <a className="button button-secondary" href={MISP_PUBLIC_URL + '/'} target="_blank" rel="noreferrer">{t('openMisp')}</a>
        <a href="https://www.misp-project.org/openapi/" target="_blank" rel="noreferrer">MISP API</a>
      </div>
    </article>

    <div className="notice">
      <span className="notice-mark">i</span>
      <div><strong>{t('mispIdempotencyTitle')}</strong><p>{t('mispIdempotencyDescription')}</p></div>
    </div>

    <section className="misp-candidate-section">
      <div className="section-heading compact">
        <div><h3>{t('mispCandidateQueue')}</h3><p>{t('mispCandidateDescription')}</p></div>
      </div>
      <div className="filters">
        <input
          aria-label={t('searchEvents')}
          value={search}
          onChange={(event) => { setSearch(event.target.value); setOffset(0); }}
          placeholder={t('minimumTwoCharacters')}
        />
        <select aria-label={t('pipeline')} value={pipeline} onChange={(event) => { setPipeline(event.target.value); setOffset(0); }}>
          <option value="">{t('allPipelines')}</option>
          <option value="external">{t('externalPipeline')}</option>
          <option value="internal">{t('internalPipeline')}</option>
        </select>
      </div>

      {canSend && <div className="misp-selection-bar">
        <span>{t('selectedEvents', { count: number(selected.size) })}</span>
        <div className="action-row">
          <button className="button button-secondary" disabled={!readyOnPage.length || selected.size >= 20} onClick={selectReadyPage}>{t('selectReadyPage')}</button>
          <button className="button button-quiet" disabled={!selected.size} onClick={() => setSelected(new Set())}>{t('clearSelection')}</button>
          <button className="button button-primary" disabled={!selected.size || batch.isPending || health.data?.reachable !== true} onClick={confirmBatch}>
            {batch.isPending ? t('sendingAndVerifying') : t('sendSelectedEvents')}
          </button>
        </div>
      </div>}
      {!canSend && <p className="role-note">{t('mispAdminOnly')}</p>}

      {candidates.isLoading && <LoadingState label={t('loadingEvents')} />}
      {candidates.isError && <ErrorState onRetry={() => void candidates.refetch()} />}
      {candidates.data?.items.length === 0 && <EmptyState label={t('noPreviewEvents')} />}
      {candidates.data && candidates.data.items.length > 0 && <div className="misp-candidate-grid">
        {candidates.data.items.map((candidate) => <CandidateCard
          key={candidate.event_id}
          candidate={candidate}
          checked={selected.has(candidate.event_id)}
          canSend={canSend}
          onToggle={() => toggle(candidate.event_id)}
          onReview={() => setReviewId(candidate.event_id)}
        />)}
      </div>}
      {candidates.data && <Pager total={candidates.data.total} offset={offset} limit={limit} onChange={setOffset} />}
    </section>

    {preview.isLoading && <LoadingState label={t('preparingPreview')} />}
    {preview.isError && <ErrorState onRetry={() => void preview.refetch()} />}
    {preview.data && <article className="detail-panel misp-preview-panel">
      <h3>{preview.data.title}</h3>
      <div className="integration-facts">
        <span>{t('willSend')}: <strong>{number(preview.data.included)}</strong></span>
        <span>{t('safelyOmitted')}: <strong>{number(preview.data.omitted)}</strong></span>
        <span>{t('publishing')}: <strong>{t('no')}</strong></span>
      </div>
      {preview.data.tags.length > 0 && <div className="tag-list">{preview.data.tags.map((tag) => <code key={tag} dir="ltr">{tag}</code>)}</div>}
      {preview.data.omitted > 0 && <p>{t('omittedBreakdown', {
        references: number(preview.data.omitted_by_reason.external_reference || 0),
        invalid: number(preview.data.omitted_by_reason.invalid || 0),
        nonActionable: number(preview.data.omitted_by_reason.non_actionable || 0),
        unsupported: number(preview.data.omitted_by_reason.unsupported || 0),
      })}</p>}
      {preview.data.attributes.length ? <ul className="misp-attributes">{preview.data.attributes.map((item, index) => <li key={`${item.type}-${index}`}>
        <strong>{item.type}</strong>: <code dir="ltr">{item.value}</code> <small>({item.category} · {t('idsLabel')}: {item.to_ids ? t('yes') : t('no')})</small>
      </li>)}</ul> : <p>{t('noTransferableAttributes')}</p>}
    </article>}

    {batch.isSuccess && <section className="detail-panel misp-batch-result" role="status">
      <h3>{t('mispBatchResult')}</h3>
      <p>{t('mispBatchSummary', {
        delivered: number(batch.data.delivered),
        skipped: number(batch.data.skipped),
        failed: number(batch.data.failed),
        published: number(batch.data.published),
      })}</p>
      <ul>{batch.data.items.map((item) => <li key={item.event_id}>
        <Link to={`/intelligence/events/${encodeURIComponent(item.event_id)}`}>{item.event_id}</Link>
        <span>{t(statusKeys[item.status])}</span>
        {item.reason && <small>{t(reasonKeys[item.reason] || 'mispSafeFailure')}</small>}
        {item.misp_event_id && <a href={`${MISP_PUBLIC_URL}/events/view/${encodeURIComponent(item.misp_event_id)}`} target="_blank" rel="noreferrer">{t('openMispEvent')}</a>}
      </li>)}</ul>
    </section>}
    {batch.isError && <div className="form-error" role="alert">{batch.error instanceof ApiError && batch.error.status === 403 ? t('mispAdminOnly') : t('mispSafeFailure')}</div>}

    <section className="detail-list">
      <h3>{t('mispDeliveryHistory')}</h3>
      {history.isLoading && <LoadingState label={t('loadingHistory')} />}
      {history.isError && <ErrorState onRetry={() => void history.refetch()} />}
      {history.data?.items.length === 0 && <p>{t('noMispDeliveries')}</p>}
      {history.data && history.data.items.length > 0 && <div className="table-shell"><table>
        <thead><tr><th>{t('time')}</th><th>{t('event')}</th><th>{t('status')}</th><th>{t('user')}</th><th>{t('verified')}</th><th>MISP</th></tr></thead>
        <tbody>{history.data.items.map((item) => <tr key={item.id}>
          <td>{dateTime(item.created_at)}</td>
          <td>{item.event_id ? <Link to={`/intelligence/events/${encodeURIComponent(item.event_id)}`}>{item.event_id.slice(0, 18)}</Link> : t('notAvailable')}</td>
          <td><strong>{t(statusKeys[item.status])}</strong>{item.reason && <small>{t(reasonKeys[item.reason] || 'mispSafeFailure')}</small>}</td>
          <td>{item.username || t('notAvailable')}</td>
          <td>{item.attributes_verified === undefined ? t('legacy') : number(item.attributes_verified)}</td>
          <td>{item.misp_event_id ? <a href={`${MISP_PUBLIC_URL}/events/view/${encodeURIComponent(item.misp_event_id)}`} target="_blank" rel="noreferrer">{t('openMispEvent')}</a> : t('notRecorded')}</td>
        </tr>)}</tbody>
      </table></div>}
    </section>
  </section>;
}
