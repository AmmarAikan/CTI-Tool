import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError } from '../api/client';
import { EmptyState, ErrorState, LoadingState } from '../components/States';

export function Reviews() {
  const [search, setSearch] = useState(''); const [type, setType] = useState('all');
  const query = useQuery({ queryKey: ['external-reviews-latest'], queryFn: api.latestExternalReviews, retry: false });
  const records = query.data?.records || []; const types = [...new Set(records.map((r) => r.source_type).filter(Boolean))] as string[];
  const filtered = useMemo(() => records.filter((r) => (type === 'all' || r.source_type === type) && [r.record_id, r.title, r.source_type, r.review_reason, ...r.review_reasons].some((v) => v?.toLocaleLowerCase().includes(search.toLocaleLowerCase()))), [records, search, type]);
  const retry = () => void query.refetch();
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">المراجعات / 06</span><h2>أحدث المراجعات</h2><p>قائمة آمنة للقراءة فقط؛ لا يدعم العقد الحالي قرارات المراجعة.</p></div><span className="count-label">{filtered.length} سجل</span></div>
    <div className="filters"><label className="search-wrap"><span className="sr-only">بحث</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="بحث في البيانات الآمنة" /></label><select aria-label="تصفية نوع المصدر" value={type} onChange={(e) => setType(e.target.value)}><option value="all">كل الأنواع</option>{types.map((v) => <option key={v}>{v}</option>)}</select></div>
    {query.isLoading && <LoadingState label="جار تحميل المراجعات..." />}{query.isError && (query.error instanceof ApiError && query.error.status === 404 && query.error.code === 'review_not_found' ? <EmptyState label="لا توجد مراجعات حتى الآن" /> : query.error instanceof ApiError && query.error.status === 401 ? <div className="state-panel error-panel" role="alert">انتهت جلسة الدخول.</div> : query.error instanceof TypeError || query.error instanceof ApiError && (query.error.status === 408 || query.error.status === 503) ? <div className="state-panel error-panel" role="alert"><strong>خدمة المراجعات غير متاحة حاليًا</strong><button className="button button-secondary" onClick={retry}>إعادة المحاولة</button></div> : <ErrorState onRetry={retry} />)}
    {!query.isLoading && !query.isError && records.length === 0 && <EmptyState label="لا توجد مراجعات حتى الآن" />}{records.length > 0 && filtered.length === 0 && <EmptyState label="لا توجد نتائج مطابقة." />}
    {filtered.length > 0 && <div className="card-list">{filtered.map((r) => <article className="review-card" key={r.record_id}><div><strong>{r.title || 'بلا عنوان'}</strong><code>{r.record_id}</code></div><dl><div><dt>نوع المصدر</dt><dd>{r.source_type || 'غير متاح'}</dd></div><div><dt>سبب المراجعة</dt><dd>{r.review_reasons.join('، ') || r.review_reason}</dd></div><div><dt>التصنيف</dt><dd>{r.classification_label || 'غير متاح'}</dd></div><div><dt>الخصوصية</dt><dd>{r.privacy_status || 'غير متاح'}</dd></div><div><dt>وقت الجمع</dt><dd>{r.collected_at ? new Date(r.collected_at).toLocaleString('ar') : 'غير متاح'}</dd></div>{r.published && <div><dt>وقت النشر</dt><dd>{new Date(r.published).toLocaleString('ar')}</dd></div>}</dl></article>)}</div>}
  </section>;
}
