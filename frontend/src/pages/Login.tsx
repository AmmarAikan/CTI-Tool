import { FormEvent, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { useI18n } from '../i18n/I18nContext';
import { AuthFrame } from '../components/PublicFrame';

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
    try { await login(username.trim(), password); const from = (location.state as { from?: unknown } | null)?.from; navigate(typeof from === 'string' && from.startsWith('/') && !from.startsWith('//') ? from : '/dashboard', { replace: true }); }
    catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) setError(t('invalidCredentials'));
      else if (reason instanceof ApiError && reason.status === 429) setError(t('loginLimited'));
      else setError(t('loginFailed'));
    }
    finally { setBusy(false); }
  }
  return (
    <AuthFrame
      eyebrow={t('secureAccess')}
      title={t('welcome')}
      description={t('loginIntro')}
      asideEyebrow={t('loginAsideEyebrow')}
      asideTitle={t('loginAsideTitle')}
      asideDescription={t('loginAsideDescription')}
      signals={[
        { label: t('authAccessLabel'), value: t('authRoleBasedValue') },
        { label: t('authSessionLabel'), value: t('authTimeLimitedValue') },
        { label: t('authActionsLabel'), value: t('authAuditedValue') },
      ]}
    >
      <form className="auth-form" onSubmit={submit} noValidate>
        <label htmlFor="username">{t('username')}</label>
        <input id="username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} />
        <label htmlFor="password">{t('password')}</label>
        <input id="password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />
        {error && <div className="form-error" role="alert">{error}</div>}
        <button className="button button-primary full-width" disabled={busy}>
          {busy ? t('signingIn') : t('signIn')}
        </button>
        <p className="auth-switch">
          {t('loginRegisterPrompt')} <Link to="/register">{t('loginRegister')}</Link>
        </p>
      </form>
    </AuthFrame>
  );
}
