import { FormEvent, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { useI18n } from '../i18n/I18nContext';

export function Login() {
  const { login } = useAuth();
  const { t } = useI18n();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setError('');
    if (!username.trim() || !password) { setError(t('loginRequired')); return; }
    setBusy(true);
    try { await login(username.trim(), password); const from = (location.state as { from?: unknown } | null)?.from; navigate(typeof from === 'string' && from.startsWith('/') && !from.startsWith('//') ? from : '/', { replace: true }); }
    catch (reason) { setError(reason instanceof ApiError && reason.status === 401 ? t('invalidCredentials') : t('loginFailed')); }
    finally { setBusy(false); }
  }
  return <main className="login-page"><section className="login-panel"><div className="brand"><span className="brand-mark">CTI</span><div><strong>{t('brand')}</strong><small>{t('intelligenceOperations')}</small></div></div><div className="login-copy"><span className="eyebrow">{t('secureAccess')}</span><h1>{t('welcome')}</h1><p>{t('loginIntro')}</p></div><form onSubmit={submit} noValidate><label htmlFor="username">{t('username')}</label><input id="username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} /><label htmlFor="password">{t('password')}</label><input id="password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />{error && <div className="form-error" role="alert">{error}</div>}<button className="button button-primary full-width" disabled={busy}>{busy ? t('signingIn') : t('signIn')}</button></form></section><aside className="login-aside"><span className="aside-kicker">01 / CENTRAL INTELLIGENCE</span><h2>{t('clearerVision')}<br /><em>{t('fasterResponse')}</em></h2><p>{t('unifiedInterface')}</p></aside></main>;
}
