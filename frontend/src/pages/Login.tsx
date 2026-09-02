import { FormEvent, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setError('');
    if (!username.trim() || !password) { setError('أدخل اسم المستخدم وكلمة المرور.'); return; }
    setBusy(true);
    try { await login(username.trim(), password); const from = (location.state as { from?: unknown } | null)?.from; navigate(typeof from === 'string' && from.startsWith('/') && !from.startsWith('//') ? from : '/', { replace: true }); }
    catch (reason) { setError(reason instanceof ApiError && reason.status === 401 ? 'بيانات الدخول غير صحيحة.' : 'تعذر تسجيل الدخول. حاول مرة أخرى.'); }
    finally { setBusy(false); }
  }
  return <main className="login-page"><section className="login-panel"><div className="brand"><span className="brand-mark">CTI</span><div><strong>مركز التهديدات</strong><small>عمليات استخباراتية</small></div></div><div className="login-copy"><span className="eyebrow">وصول آمن</span><h1>أهلًا بك في مساحة العمليات</h1><p>سجّل الدخول للوصول إلى مصادر استخبارات التهديدات.</p></div><form onSubmit={submit} noValidate><label htmlFor="username">اسم المستخدم</label><input id="username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} /><label htmlFor="password">كلمة المرور</label><input id="password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />{error && <div className="form-error" role="alert">{error}</div>}<button className="button button-primary full-width" disabled={busy}>{busy ? 'جار التحقق...' : 'تسجيل الدخول'}</button></form></section><aside className="login-aside"><span className="aside-kicker">01 / CENTRAL INTELLIGENCE</span><h2>رؤية أوضح.<br /><em>استجابة أسرع.</em></h2><p>واجهة تشغيل موحدة للبيانات الخارجية والإشارات الأمنية.</p></aside></main>;
}
