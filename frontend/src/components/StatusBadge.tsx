import { useI18n, type TranslationKey } from '../i18n/I18nContext';

const translatedStatuses: Record<string, TranslationKey> = { queued: 'queued', running: 'processing', completed: 'completed', partial: 'partial', failed: 'failed', cancelled: 'cancelled', cancellation_requested: 'cancellation_requested' };

export function StatusBadge({ status }: { status: string }) {
  const { t } = useI18n();
  const normalized = status.toLowerCase();
  const tone = normalized === 'ok' || normalized === 'enabled' || normalized === 'healthy' ? 'success' : normalized === 'disabled' ? 'muted' : 'warning';
  const label = translatedStatuses[normalized] ? t(translatedStatuses[normalized]) : status;
  return <span className={`status-badge status-${tone}`} aria-label={`${t('status')}: ${label}`}><span aria-hidden="true" className="status-dot" />{label}</span>;
}
