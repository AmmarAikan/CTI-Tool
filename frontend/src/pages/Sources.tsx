import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState, ErrorState, LoadingState } from '../components/States';

export function Sources() {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [type, setType] = useState('all');
  const query = useQuery({ queryKey: ['external-sources'], queryFn: api.externalSources, retry: false });
  const sources = query.data || [];
  const types = [...new Set(sources.map((source) => source.source_type))];
  const filtered = useMemo(() => sources.filter((source) => `${source.name} ${source.source_id}`.toLowerCase().includes(search.toLowerCase()) && (status === 'all' || source.status === status) && (type === 'all' || source.source_type === type)), [sources, search, status, type]);
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">المصادر / 02</span><h2>المصادر الخارجية</h2><p>المصادر المسجلة وحالتها التشغيلية الآمنة.</p></div><span className="count-label">{filtered.length} مصدر</span></div><div className="filters"><label className="search-wrap"><span className="sr-only">بحث</span><input placeholder="بحث بالاسم أو المعرّف" value={search} onChange={(event) => setSearch(event.target.value)} /></label><select aria-label="تصفية الحالة" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">كل الحالات</option><option value="enabled">مفعّل</option><option value="disabled">معطّل</option><option value="pending_review">قيد المراجعة</option></select><select aria-label="تصفية النوع" value={type} onChange={(event) => setType(event.target.value)}><option value="all">كل الأنواع</option>{types.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>{query.isLoading && <LoadingState label="جار تحميل المصادر..." />}{query.isError && <ErrorState onRetry={() => void query.refetch()} />}{!query.isLoading && !query.isError && sources.length === 0 && <EmptyState label="لا توجد مصادر مسجلة حاليًا." />}{!query.isLoading && !query.isError && sources.length > 0 && filtered.length === 0 && <EmptyState label="لا توجد نتائج مطابقة للفلاتر الحالية." />}{filtered.length > 0 && <div className="table-shell"><table><thead><tr><th>المصدر</th><th>النوع</th><th>الحالة</th><th>بيانات آمنة</th></tr></thead><tbody>{filtered.map((source) => <tr key={source.source_id}><td><strong>{source.name}</strong><code dir="ltr">{source.source_id}</code></td><td><span className="type-label">{source.source_type}</span></td><td><StatusBadge status={source.status} /></td><td>{Object.keys(source.metadata || {}).length > 0 ? <span className="safe-label">متاحة</span> : <span className="muted-text">لا توجد</span>}</td></tr>)}</tbody></table></div>}</section>;
}
