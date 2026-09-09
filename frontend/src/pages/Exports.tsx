import { useQuery } from '@tanstack/react-query';
import { api, ApiError } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';
import './ExternalFeatures.css';

function Failure({ error, retry }: { error: Error; retry: () => void }) {
  if (error instanceof ApiError && error.status === 404 && error.code === 'export_not_found') return <EmptyState label="لا يوجد تصدير متاح حتى الآن" />;
  if (error instanceof ApiError && error.status === 401) return <div className="state-panel error-panel" role="alert">انتهت جلسة الدخول.</div>;
  if (error instanceof TypeError || (error instanceof ApiError && (error.status === 408 || error.status === 503))) return <div className="state-panel error-panel" role="alert"><strong>خدمة التصدير غير متاحة حاليًا</strong><button className="button button-secondary" onClick={retry}>إعادة المحاولة</button></div>;
  return <ErrorState onRetry={retry} />;
}

export function Exports() {
  const query = useQuery({ queryKey: ['external-export-latest'], queryFn: api.latestExternalExport, retry: false });
  const value = query.data;
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">التصديرات / 05</span><h2>أحدث تصدير</h2><p>ملخص آمن لآخر مجموعة بيانات متحقق منها.</p></div>{value && <StatusBadge status={value.status} />}</div>
    {query.isLoading && <LoadingState label="جار تحميل ملخص التصدير..." />}{query.isError && <Failure error={query.error} retry={() => void query.refetch()} />}
    {value && <div className="metric-grid"><article className="metric-card"><span>السجلات المقبولة</span><strong>{value.accepted_records.toLocaleString('ar')}</strong></article><article className="metric-card"><span>سجلات المراجعة</span><strong>{value.review_records.toLocaleString('ar')}</strong></article><article className="metric-card"><span>وقت الاكتمال</span><strong className="compact-value">{value.completed_at ? new Date(value.completed_at).toLocaleString('ar') : 'غير متاح'}</strong></article></div>}
    {value && <div className="safe-summary"><dl><div><dt>معرّف التشغيل</dt><dd><code>{value.run_id}</code></dd></div><div><dt>بصمة SHA-256</dt><dd><code>{value.dataset_sha256 ? `${value.dataset_sha256.slice(0, 12)}…${value.dataset_sha256.slice(-8)}` : 'غير متاحة'}</code></dd></div></dl><p className="muted-text">لا تتوفر نقطة تنزيل آمنة عبر Backend المركزي، لذلك لا يظهر تنزيل للبيانات الخام.</p></div>}
  </section>;
}
