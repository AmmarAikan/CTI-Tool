import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { StatusBadge } from '../components/StatusBadge';
import { ErrorState, LoadingState } from '../components/States';

export function Dashboard() {
  const health = useQuery({ queryKey: ['external-health'], queryFn: api.externalHealth, retry: false });
  if (health.isLoading) return <section className="page-section"><LoadingState label="جار فحص خدمة المصادر الخارجية..." /></section>;
  if (health.isError) return <section className="page-section"><ErrorState onRetry={() => void health.refetch()} /></section>;
  const value = health.data;
  if (!value) return <section className="page-section"><ErrorState onRetry={() => void health.refetch()} /></section>;
  const state = value.reachable ? 'متاحة' : value.configured ? 'غير متاحة' : 'غير مهيأة';
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">نظرة عامة / 01</span><h2>لوحة المتابعة</h2><p>حالة منظومة جمع المصادر الخارجية عبر الواجهة المركزية.</p></div><StatusBadge status={value.reachable ? 'healthy' : 'unavailable'} /></div><div className="metric-grid"><article className="metric-card accent"><span>خدمة المصادر الخارجية</span><strong>{state}</strong><small>{value.service || 'External Sources'} · {value.api_version || 'v1'}</small></article><article className="metric-card"><span>قناة الاتصال</span><strong>{value.configured ? 'مهيأة' : 'غير مهيأة'}</strong><small>Central Backend API</small></article><article className="metric-card"><span>آخر فحص</span><strong>الآن</strong><small>قراءة آمنة من الخدمة</small></article></div><div className="notice"><span className="notice-mark">i</span><div><strong>تشغيل مركزي</strong><p>المتصفح يتصل بالـ Backend المركزي فقط. تبقى بيانات الخدمة والاتصالات الداخلية خارج المتصفح.</p></div></div></section>;
}
