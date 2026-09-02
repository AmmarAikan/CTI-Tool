import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

const links = [
  ['/', 'لوحة المتابعة'],
  ['/external-sources', 'المصادر الخارجية'],
  ['/jobs', 'الوظائف'],
  ['/manual', 'رابط يدوي'],
  ['/exports', 'التصديرات'],
  ['/reviews', 'المراجعات'],
];

export function Layout() {
  const { user, logout, can } = useAuth();
  const visibleLinks = links.filter(([to]) => to !== '/manual' || can('analyst'));
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">CTI</span><div><strong>مركز التهديدات</strong><small>عمليات استخباراتية</small></div></div>
      <nav aria-label="التنقل الرئيسي">{visibleLinks.map(([to, label]) => <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>{label}</NavLink>)}</nav>
      <div className="sidebar-foot"><span className="online-dot" />اتصال مركزي آمن</div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><span className="eyebrow">منصة CTI</span><h1>مساحة العمليات</h1></div><div className="user-menu"><div className="avatar" aria-hidden="true">{user?.username.slice(0, 1).toUpperCase()}</div><div><strong>{user?.username}</strong><small>{user?.role}</small></div><button className="button button-quiet" onClick={logout}>تسجيل الخروج</button></div></header>
      <Outlet />
    </main>
  </div>;
}
