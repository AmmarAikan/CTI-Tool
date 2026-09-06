import { useQuery } from '@tanstack/react-query';
import { api, ApiError } from '../api/client';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState, ErrorState, LoadingState } from '../components/States';

function SummaryError({ error, onRetry }: { error: Error; onRetry: () => void }) {
  if (error instanceof ApiError && error.status === 401) return <div className="state-panel error-panel" role="alert"><strong>انتهت جلسة الدخول</strong><span>سجّل الدخول مجددًا للوصول إلى إحصاءات المنصة.</span></div>;
  if (error instanceof TypeError) return <div className="state-panel error-panel" role="alert"><strong>الخدمة المركزية غير متصلة</strong><span>تعذر الوصول إلى Backend المركزي.</span><button className="button button-secondary" onClick={onRetry}>إعادة المحاولة</button></div>;
  return <ErrorState onRetry={onRetry} />;
}

export function Dashboard() {
  const health = useQuery({ queryKey: ['external-health'], queryFn: api.externalHealth, retry: false });
  const summary = useQuery({ queryKey: ['dashboard-summary'], queryFn: api.dashboardSummary, retry: false });
  const healthValue = health.data;
  const healthState = healthValue?.reachable ? 'متاحة' : healthValue?.configured ? 'غير متاحة' : 'غير مهيأة';
  const statistics = summary.data ? [['أحداث التهديدات', summary.data.events], ['المؤشرات', summary.data.indicators], ['الارتباطات', summary.data.correlations], ['جلسات الرصد', summary.data.sessions], ['القيم الشاذة', summary.data.outliers]] as const : [];
  const isEmpty = statistics.length > 0 && statistics.every(([, amount]) => amount === 0);
  return <section className="page-section">
    <div className="section-heading"><div><span className="eyebrow">نظرة عامة / 01</span><h2>لوحة المتابعة</h2><p>ملخص آمن لبيانات استخبارات التهديدات وحالة المصادر الخارجية.</p></div>{healthValue && <StatusBadge status={healthValue.reachable ? 'healthy' : 'unavailable'} />}</div>
    <div className="metric-grid"><article className="metric-card accent"><span>خدمة المصادر الخارجية</span>{health.isLoading ? <LoadingState label="جار فحص الخدمة..." /> : health.isError || !healthValue ? <><strong>تعذر الفحص</strong><button className="button button-secondary" onClick={() => void health.refetch()}>إعادة المحاولة</button></> : <><strong>{healthState}</strong><small>{healthValue.service || 'External Sources'} · {healthValue.api_version || 'v1'}</small></>}</article></div>
    <div className="section-heading"><div><span className="eyebrow">الإحصاءات الحية</span><h2>بيانات المنصة</h2></div></div>
    {summary.isLoading && <LoadingState label="جار تحميل إحصاءات المنصة..." />}
    {summary.isError && <SummaryError error={summary.error} onRetry={() => void summary.refetch()} />}
    {!summary.isLoading && !summary.isError && summary.data && <><div className="metric-grid">{statistics.map(([label, amount]) => <article className="metric-card" key={label}><span>{label}</span><strong>{amount.toLocaleString('ar')}</strong><small>إجمالي مسجل</small></article>)}</div>{isEmpty && <EmptyState label="لا توجد بيانات إحصائية مسجلة حاليًا." />}</>}
    <div className="notice"><span className="notice-mark">i</span><div><strong>تشغيل مركزي</strong><p>المتصفح يتصل بالـ Backend المركزي فقط. تبقى بيانات الخدمة والاتصالات الداخلية خارج المتصفح.</p></div></div>
  </section>;
}
