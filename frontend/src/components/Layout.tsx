import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

const groups = [
  { label: 'لوحة المتابعة', accent: 'dashboard', links: [['/', 'لوحة المتابعة']] },
  { label: 'المصادر الخارجية', accent: 'external', links: [['/external-sources', 'المصادر'], ['/manual', 'رابط يدوي'], ['/jobs', 'الوظائف'], ['/reviews', 'المراجعات'], ['/exports', 'التصديرات']] },
  { label: 'المصادر الداخلية', accent: 'internal', links: [['/internal-sources', 'نظرة عامة'], ['/internal-sources/dionaea', 'Dionaea'], ['/internal-sources/host-auth', 'سجلات الدخول'], ['/internal-sources/web-access', 'الوصول إلى الويب']] },
  { label: 'الاستخبارات والتحليل', accent: 'analysis', links: [['/intelligence', 'نظرة عامة'], ['/intelligence/events', 'الأحداث'], ['/intelligence/indicators', 'المؤشرات'], ['/intelligence/correlations', 'الارتباطات'], ['/intelligence/outliers', 'القيم الشاذة'], ['/analysis', 'عمليات التحليل'], ['/misp', 'MISP']] },
  { label: 'الإدارة', accent: 'admin', adminOnly: true, links: [['/admin', 'قريبًا']] },
];

export function Layout() {
  const { user, logout, can } = useAuth();
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">CTI</span><div><strong>مركز التهديدات</strong><small>عمليات استخباراتية</small></div></div>
      <nav aria-label="التنقل الرئيسي">{groups.filter((group) => !group.adminOnly || user?.role === 'admin').map((group) => <section className={`nav-group nav-${group.accent}`} key={group.label} aria-label={group.label}><h2>{group.label}</h2>{group.links.filter(([to]) => to !== '/manual' || can('analyst')).map(([to, label]) => <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>{label}</NavLink>)}</section>)}</nav>
      <div className="sidebar-foot"><span className="online-dot" />اتصال مركزي آمن</div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><span className="eyebrow">منصة CTI</span><h1>مساحة العمليات</h1></div><div className="user-menu"><div className="avatar" aria-hidden="true">{user?.username.slice(0, 1).toUpperCase()}</div><div><strong>{user?.username}</strong><small>{user?.role}</small></div><button className="button button-quiet" onClick={logout}>تسجيل الخروج</button></div></header>
      <Outlet />
    </main>
  </div>;
}
