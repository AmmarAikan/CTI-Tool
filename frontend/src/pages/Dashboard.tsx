import { useQueries, useQuery } from '@tanstack/react-query';
import { api, ApiError, type HealthResponse, type InternalIntegration } from '../api/client';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState, ErrorState, LoadingState } from '../components/States';

function SummaryError({ error, onRetry }: { error: Error; onRetry: () => void }) {
  if (error instanceof ApiError && error.status === 401) return <div className="state-panel error-panel" role="alert"><strong>انتهت جلسة الدخول</strong><span>سجّل الدخول مجددًا للوصول إلى إحصاءات المنصة.</span></div>;
  if (error instanceof ApiError && error.status === 403) return <div className="state-panel error-panel" role="alert"><strong>الوصول غير مسموح</strong><span>لا تملك صلاحية عرض هذه البيانات.</span></div>;
  if (error instanceof ApiError && error.status === 408) return <div className="state-panel error-panel" role="alert"><strong>انتهت مهلة الطلب</strong><button className="button button-secondary" onClick={onRetry}>إعادة المحاولة</button></div>;
  if (error instanceof TypeError) return <div className="state-panel error-panel" role="alert"><strong>الخدمة المركزية غير متصلة</strong><span>تعذر الوصول إلى Backend المركزي.</span><button className="button button-secondary" onClick={onRetry}>إعادة المحاولة</button></div>;
  return <ErrorState onRetry={onRetry} />;
}

function state(health?: HealthResponse) {
  if (!health?.configured) return { label: 'غير مهيأة', badge: 'disabled' };
  if (!health.reachable) return { label: 'غير متصلة', badge: 'unavailable' };
  if (health.contract_valid === false) return { label: 'متدهورة', badge: 'degraded' };
  return { label: 'متاحة', badge: 'healthy' };
}

function internalState(health?: HealthResponse) {
  const value = state(health);
  return { ...value, label: value.label === 'متاحة' ? 'متصلة' : value.label };
}

function Distribution({ title, values }: { title: string; values: Record<string, number> }) {
  const entries = Object.entries(values);
  const max = Math.max(0, ...entries.map(([, value]) => value));
  return <article className="distribution-card"><h3>{title}</h3>{entries.length === 0 ? <p className="muted-text">لا توجد بيانات</p> : <div className="bar-list">{entries.map(([label, value]) => <div className="bar-row" key={label}><div><span>{label}</span><strong>{value.toLocaleString('ar')} سجل</strong></div><span className="bar-track" aria-label={`${label}: ${value}`}><span className="bar-fill" style={{ width: `${max ? (value / max) * 100 : 0}%` }} /></span></div>)}</div>}</article>;
}

export function Dashboard() {
  const system = useQuery({ queryKey: ['system-health'], queryFn: api.systemHealth, retry: false });
  const external = useQuery({ queryKey: ['external-health'], queryFn: api.externalHealth, retry: false });
  const configuration = useQuery({ queryKey: ['integration-status'], queryFn: api.integrationStatus, retry: false });
  const integrations: InternalIntegration[] = ['dionaea', 'host-auth', 'web-access'];
  const internal = useQueries({ queries: integrations.map((integration) => ({ queryKey: ['internal-health', integration], queryFn: () => api.internalHealth(integration), retry: false })) });
  const summary = useQuery({ queryKey: ['dashboard-summary'], queryFn: api.dashboardSummary, retry: false });
  const statistics = summary.data ? [['أحداث التهديدات', summary.data.events], ['المؤشرات', summary.data.indicators], ['الارتباطات', summary.data.correlations], ['جلسات الرصد', summary.data.sessions], ['القيم الشاذة', summary.data.outliers]] as const : [];
  const isEmpty = statistics.length > 0 && statistics.every(([, amount]) => amount === 0);
  const names = ['Dionaea', 'سجلات الدخول', 'الوصول إلى الويب'];
  const refreshedAt = new Intl.DateTimeFormat('ar', { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date());
  const retryHealth = () => { void system.refetch(); void external.refetch(); void configuration.refetch(); internal.forEach((query) => void query.refetch()); };
  return <section className="page-section">
    <div className="section-heading"><div><span className="eyebrow">نظرة عامة / 01</span><h2>لوحة المتابعة</h2><p>الحالة التشغيلية الحالية من عقود المنصة المركزية المؤكدة فقط.</p></div><div className="refresh-block"><small>آخر تحديث: {refreshedAt}</small><button className="button button-secondary" onClick={retryHealth}>إعادة فحص الحالة</button></div></div>
    <div className="health-grid">
      <article className="health-card"><span>Backend / قاعدة البيانات</span>{system.isLoading ? <LoadingState label="جار الفحص..." /> : system.data ? <><strong>{system.data.database ? 'سليمة' : 'متدهورة'}</strong><StatusBadge status={system.data.status === 'ok' ? 'healthy' : 'degraded'} /></> : <button className="button button-secondary" onClick={() => void system.refetch()}>إعادة فحص Backend</button>}</article>
      <article className="health-card external-accent"><span>المصادر الخارجية</span>{external.isLoading ? <LoadingState label="جار الفحص..." /> : external.data ? <><strong>{state(external.data).label}</strong><StatusBadge status={state(external.data).badge} /></> : <button className="button button-secondary" onClick={() => void external.refetch()}>إعادة المحاولة</button>}</article>
      {internal.map((query, index) => <article className="health-card internal-accent" key={integrations[index]}><span>{names[index]}</span>{query.isLoading ? <LoadingState label="جار الفحص..." /> : query.data ? <><strong>{internalState(query.data).label}</strong><StatusBadge status={internalState(query.data).badge} /></> : <button className="button button-secondary" onClick={() => void query.refetch()}>إعادة فحص {names[index]}</button>}</article>)}
    </div>
    {configuration.data && !configuration.data.external_control_api.configured && <div className="notice"><span className="notice-mark">i</span><div><strong>المصادر الخارجية غير مهيأة</strong><p>يتطلب الاتصال إعدادًا مركزيًا؛ لا توجد معلومات اتصال معروضة في المتصفح.</p></div></div>}
    <div className="section-heading compact-heading"><div><span className="eyebrow">الإحصاءات الحية</span><h2>بيانات المنصة</h2></div></div>
    {summary.isLoading && <LoadingState label="جار تحميل إحصاءات المنصة..." />}
    {summary.isError && <SummaryError error={summary.error} onRetry={() => void summary.refetch()} />}
    {summary.data && <><div className="metric-grid">{statistics.map(([label, amount]) => <article className="metric-card" key={label}><span>{label}</span><strong>{amount.toLocaleString('ar')}</strong><small>إجمالي مسجل</small></article>)}</div>{isEmpty && <EmptyState label="لا توجد بيانات إحصائية مسجلة حاليًا." />}<div className="distribution-grid"><Distribution title="توزيع الشدة" values={summary.data.by_severity} /><Distribution title="توزيع خطوط المعالجة" values={summary.data.by_pipeline} /></div></>}
    <div className="notice"><span className="notice-mark">i</span><div><strong>لقطة تشغيلية حالية</strong><p>لا تعرض اللوحة اتجاهات تاريخية لعدم وجود عقد سلسلة زمنية. المتصفح يتصل بالـ Backend المركزي فقط.</p></div></div>
  </section>;
}
