import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type HealthResponse, type InternalIntegration } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { StatusBadge } from '../components/StatusBadge';

const PROFILES: Record<InternalIntegration, { name: string; description: string; type: string }> = {
  dionaea: { name: 'Dionaea', description: 'جلسات مصيدة الخدمات الوهمية بعد المعالجة المركزية الآمنة.', type: 'dionaea_session' },
  'host-auth': { name: 'سجلات الدخول', description: 'أحداث مصادقة المضيف بعد التنقية والمعالجة.', type: 'linux_auth_session' },
  'web-access': { name: 'الوصول إلى الويب', description: 'أحداث الوصول إلى الويب دون عرض السجلات الخام.', type: 'web_access_session' },
};

function healthLabel(health?: HealthResponse) {
  if (!health) return 'تعذر الفحص';
  if (!health.configured) return 'غير مهيأة';
  if (!health.reachable) return 'غير متصلة';
  if (health.contract_valid === false) return 'متدهورة';
  return 'متصلة';
}

function IntegrationCard({ integration, showLink = true }: { integration: InternalIntegration; showLink?: boolean }) {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const profile = PROFILES[integration];
  const health = useQuery({ queryKey: ['internal-health', integration], queryFn: () => api.internalHealth(integration), retry: false });
  const pull = useMutation({
    mutationFn: () => api.pullInternal(integration),
    onSuccess: () => { void health.refetch(); void queryClient.invalidateQueries({ queryKey: ['internal-events', integration] }); },
  });
  const startPull = () => {
    if (pull.isPending || !window.confirm(`هل تريد بدء سحب ${profile.name} الآن؟`)) return;
    pull.mutate();
  };
  const value = health.data;
  return <article className="integration-card">
    <div className="integration-card-head"><div className="internal-icon" aria-hidden="true">◆</div><div><h3>{profile.name}</h3><p>{profile.description}</p></div><StatusBadge status={healthLabel(value)} /></div>
    {health.isLoading && <LoadingState label="جار فحص الاتصال..." />}
    {health.isError && <ErrorState onRetry={() => void health.refetch()} />}
    {value && <div className="integration-facts"><span>الإعداد: <strong>{value.configured ? 'مكتمل' : 'غير مكتمل'}</strong></span><span>الوصول: <strong>{value.reachable ? 'متاح' : 'غير متاح'}</strong></span></div>}
    {value && !value.configured && <p className="safe-explanation">يتطلب هذا المصدر إعدادًا مركزيًا. لا تُعرض عناوين الخدمات أو بيانات الاعتماد في المتصفح.</p>}
    {value?.configured && !value.reachable && <p className="safe-explanation">المصدر مهيأ لكنه غير متصل حاليًا. أعد فحص الصحة قبل السحب.</p>}
    <div className="card-actions">
      <button className="button button-secondary" onClick={() => void health.refetch()} disabled={health.isFetching}>إعادة فحص الصحة</button>
      {can('analyst') && <button className="button button-primary" onClick={startPull} disabled={pull.isPending || !value?.configured}>{pull.isPending ? 'جار السحب...' : 'سحب الآن'}</button>}
      {showLink && <a className="button button-quiet" href={`/internal-sources/${integration}`}>عرض السجلات الآمنة</a>}
    </div>
    {pull.isSuccess && <div className="pull-result" role="status">اكتمل التشغيل: جُمعت {pull.data.collected_count}، وخُزنت {pull.data.stored_count}.</div>}
    {pull.isError && <div className="form-error" role="alert">{pull.error instanceof ApiError && pull.error.status === 403 ? 'لا تملك صلاحية تشغيل السحب.' : pull.error instanceof ApiError && pull.error.status === 408 ? 'انتهت مهلة السحب. تحقق من حالة المصدر قبل المحاولة.' : 'تعذر إتمام السحب عبر الخدمة المركزية.'}</div>}
  </article>;
}

export function InternalOverview() {
  return <section className="page-section internal-module"><div className="section-heading"><div><span className="eyebrow">المصادر الداخلية / 01</span><h2>نظرة عامة</h2><p>مراقبة موحدة وآمنة لتكاملات الرصد الداخلية.</p></div></div><div className="integration-grid">{(Object.keys(PROFILES) as InternalIntegration[]).map((key) => <IntegrationCard key={key} integration={key} />)}</div></section>;
}

export function InternalSourcePage({ integration }: { integration: InternalIntegration }) {
  const profile = PROFILES[integration];
  const [severity, setSeverity] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 10;
  const events = useQuery({ queryKey: ['internal-events', integration, severity, offset], queryFn: () => api.internalEvents(integration, limit, offset, severity), retry: false });
  const page = events.data;
  const formatTime = (value?: string) => value ? new Intl.DateTimeFormat('ar', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'غير متوفر';
  return <section className="page-section internal-module">
    <div className="section-heading"><div><span className="eyebrow">المصادر الداخلية</span><h2>{profile.name}</h2><p>{profile.description}</p></div></div>
    <IntegrationCard integration={integration} showLink={false} />
    <div className="records-heading"><h3>السجلات المعالجة الآمنة</h3><div className="filters"><label><span className="sr-only">تصفية حسب الشدة</span><select value={severity} onChange={(event) => { setSeverity(event.target.value); setOffset(0); }}><option value="">كل درجات الشدة</option><option value="critical">حرجة</option><option value="high">عالية</option><option value="medium">متوسطة</option><option value="low">منخفضة</option></select></label></div></div>
    {events.isLoading && <LoadingState label="جار تحميل السجلات الآمنة..." />}
    {events.isError && <ErrorState onRetry={() => void events.refetch()} />}
    {page && page.items.length === 0 && <EmptyState label="لا توجد بيانات" />}
    {page && page.items.length > 0 && <><div className="table-shell"><table><thead><tr><th>الوقت</th><th>الملخص</th><th>النوع / الفئة</th><th>الشدة</th><th>المصدر</th></tr></thead><tbody>{page.items.map((item) => <tr key={item.id}><td>{formatTime(item.first_seen || item.created_at)}</td><td>{item.summary}</td><td><span className="type-label">{item.event_type}</span><small>{item.category || 'غير مصنف'}</small></td><td><StatusBadge status={item.severity || 'unknown'} /></td><td>{item.source}</td></tr>)}</tbody></table></div><div className="pagination"><button className="button button-secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>السابق</button><span>{offset + 1}–{Math.min(offset + limit, page.total)} من {page.total}</span><button className="button button-secondary" disabled={offset + limit >= page.total} onClick={() => setOffset(offset + limit)}>التالي</button></div></>}
  </section>;
}
