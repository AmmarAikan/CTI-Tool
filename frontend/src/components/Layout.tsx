import { useEffect, useState, type ReactNode } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { ThemeToggle } from './ThemeToggle';

type NavItem = { to: string; label: string; icon: ReactNode; analystOnly?: boolean };
type NavGroup = { label: string; accent: string; adminOnly?: boolean; links: NavItem[] };
function Icon({ children }: { children: ReactNode }) { return <svg className="nav-icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{children}</svg>; }
const icons = {
  dashboard: <Icon><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></Icon>,
  source: <Icon><circle cx="12" cy="12" r="2" /><path d="M5.6 5.6a9 9 0 0 0 0 12.8M18.4 5.6a9 9 0 0 1 0 12.8M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7" /></Icon>,
  link: <Icon><path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.1 1.1M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.1-1.1" /></Icon>,
  jobs: <Icon><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></Icon>,
  review: <Icon><path d="M8 4h8M9 3h6v3H9zM6 5H5v16h14V5h-1M8 11h8M8 15h5" /></Icon>,
  export: <Icon><path d="M12 3v12m-4-4 4 4 4-4M5 19h14" /></Icon>,
  shield: <Icon><path d="M12 3 5 6v5c0 4.7 2.9 8 7 10 4.1-2 7-5.3 7-10V6z" /><path d="m9 12 2 2 4-4" /></Icon>,
  intel: <Icon><circle cx="11" cy="11" r="7" /><path d="m16 16 5 5M11 8v6M8 11h6" /></Icon>,
  analysis: <Icon><path d="M4 19V9m5 10V5m5 14v-7m5 7V3" /></Icon>,
  misp: <Icon><path d="M12 3 4 7v5c0 5 3.4 8 8 9 4.6-1 8-4 8-9V7z" /><path d="M8 12h8" /></Icon>,
  admin: <Icon><circle cx="12" cy="8" r="4" /><path d="M4 21c.6-4 3.2-6 8-6s7.4 2 8 6" /></Icon>,
};
const groups: NavGroup[] = [
  { label: 'العمليات', accent: 'dashboard', links: [{ to: '/', label: 'لوحة المتابعة', icon: icons.dashboard }] },
  { label: 'المصادر الخارجية', accent: 'external', links: [{ to: '/external-sources', label: 'المصادر', icon: icons.source }, { to: '/manual', label: 'رابط يدوي', icon: icons.link, analystOnly: true }, { to: '/jobs', label: 'الوظائف', icon: icons.jobs }, { to: '/reviews', label: 'المراجعات', icon: icons.review }, { to: '/exports', label: 'التصديرات', icon: icons.export }] },
  { label: 'المصادر الداخلية', accent: 'internal', links: [{ to: '/internal-sources', label: 'نظرة عامة', icon: icons.shield }, { to: '/internal-sources/dionaea', label: 'Dionaea', icon: icons.source }, { to: '/internal-sources/host-auth', label: 'سجلات الدخول', icon: icons.review }, { to: '/internal-sources/web-access', label: 'الوصول إلى الويب', icon: icons.link }] },
  { label: 'الاستخبارات والتحليل', accent: 'analysis', links: [{ to: '/intelligence', label: 'نظرة عامة', icon: icons.intel }, { to: '/intelligence/events', label: 'الأحداث', icon: icons.review }, { to: '/intelligence/indicators', label: 'القيم والمؤشرات', icon: icons.source }, { to: '/intelligence/attack', label: 'MITRE ATT&CK', icon: icons.link }, { to: '/intelligence/correlations', label: 'الارتباطات', icon: icons.link }, { to: '/intelligence/outliers', label: 'القيم الشاذة', icon: icons.analysis }, { to: '/analysis', label: 'عمليات التحليل', icon: icons.analysis }, { to: '/misp', label: 'MISP', icon: icons.misp }] },
  { label: 'الإدارة', accent: 'admin', adminOnly: true, links: [{ to: '/admin', label: 'المستخدمون والتدقيق', icon: icons.admin }] },
];
const pageTitles = Object.fromEntries(groups.flatMap((group) => group.links.map((link) => [link.to, { title: link.label, group: group.label }])));

export function Layout() {
  const { user, logout, can } = useAuth();
  const { pathname } = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => setMenuOpen(false), [pathname]);
  useEffect(() => { if (!menuOpen) return; const close = (event: KeyboardEvent) => { if (event.key === 'Escape') setMenuOpen(false); }; document.addEventListener('keydown', close); return () => document.removeEventListener('keydown', close); }, [menuOpen]);
  const context = pageTitles[pathname] || (pathname.startsWith('/intelligence/events/') ? { title: 'تفاصيل الحدث', group: 'الاستخبارات والتحليل' } : { title: 'مساحة العمليات', group: 'منصة CTI' });
  const role = user?.role === 'admin' ? 'مسؤول النظام' : user?.role === 'analyst' ? 'محلل تهديدات' : 'مشاهد';
  return <div className="app-shell">
    <button className={`sidebar-backdrop ${menuOpen ? 'visible' : ''}`} aria-label="إغلاق قائمة التنقل" onClick={() => setMenuOpen(false)} tabIndex={menuOpen ? 0 : -1} />
    <aside id="primary-navigation" className={`sidebar ${menuOpen ? 'open' : ''}`} aria-label="القائمة الجانبية">
      <div className="brand"><span className="brand-mark" aria-hidden="true">CTI</span><div><strong>مركز التهديدات</strong><small>Cyber Intelligence Center</small></div></div>
      <nav aria-label="التنقل الرئيسي">{groups.filter((group) => !group.adminOnly || user?.role === 'admin').map((group) => <section className={`nav-group nav-${group.accent}`} key={group.label} aria-label={group.label}><h2>{group.label}</h2>{group.links.filter((link) => !link.analystOnly || can('analyst')).map(({ to, label, icon }) => <NavLink key={to} to={to} end={to === '/' || to === '/intelligence/events'} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>{icon}<span>{label}</span></NavLink>)}</section>)}</nav>
      <div className="sidebar-foot"><span className="online-dot" aria-hidden="true" /><span><strong>جلسة محمية</strong><small>اتصال مركزي آمن</small></span></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div className="topbar-context"><button className="menu-toggle" type="button" aria-label="فتح قائمة التنقل" aria-controls="primary-navigation" aria-expanded={menuOpen} onClick={() => setMenuOpen(true)}><span /><span /><span /></button><div><span className="breadcrumb">{context.group} <b aria-hidden="true">/</b> منصة CTI</span><h1>{context.title}</h1></div></div><div className="user-menu"><span className="session-status"><span className="online-dot" aria-hidden="true" />جلسة نشطة</span><ThemeToggle /><div className="avatar" aria-hidden="true">{user?.username.slice(0, 1).toUpperCase()}</div><div className="user-copy"><strong>{user?.username}</strong><small>{role}</small></div><button className="button button-quiet logout-button" onClick={logout} aria-label="تسجيل الخروج">تسجيل الخروج</button></div></header>
      <Outlet />
    </main>
  </div>;
}
