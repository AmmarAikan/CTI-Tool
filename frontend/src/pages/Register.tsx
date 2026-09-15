import { FormEvent, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import { AuthFrame } from '../components/PublicFrame';
import { useI18n } from '../i18n/I18nContext';

export function Register() {
  const { t } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState('');
  const [created, setCreated] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError('');
    const normalized = username.trim();
    if (!normalized || !password || !confirmation) {
      setError(t('registerRequired'));
      return;
    }
    if (!/^[A-Za-z0-9_.-]{3,100}$/.test(normalized)) {
      setError(t('registerUsernameInvalid'));
      return;
    }
    if (password.length < 12) {
      setError(t('registerPasswordShort'));
      return;
    }
    if (password !== confirmation) {
      setError(t('registerPasswordMismatch'));
      return;
    }
    setBusy(true);
    try {
      const user = await api.register(normalized, password);
      setCreated(user.username);
      setPassword('');
      setConfirmation('');
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 409) setError(t('registerConflict'));
      else if (reason instanceof ApiError && reason.status === 429) setError(t('registerLimited'));
      else setError(t('registerFailed'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthFrame
      eyebrow={t('registerEyebrow')}
      title={t('registerTitle')}
      description={t('registerDescription')}
      asideEyebrow={t('registerAsideEyebrow')}
      asideTitle={t('registerAsideTitle')}
      asideDescription={t('registerAsideDescription')}
      signals={[
        { label: t('authRoleLabel'), value: t('authViewerValue') },
        { label: t('authWriteLabel'), value: t('authDisabledValue') },
        { label: t('authApprovalLabel'), value: t('authApprovalValue') },
      ]}
    >
      {created ? (
        <div className="auth-success" role="status">
          <span aria-hidden="true">✓</span>
          <strong>{t('registerSuccess')}</strong>
          <code>{created}</code>
          <Link className="button button-primary full-width" to="/login">{t('registerLogin')}</Link>
        </div>
      ) : (
        <form className="auth-form" onSubmit={submit} noValidate>
          <label htmlFor="register-username">{t('username')}</label>
          <input id="register-username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} aria-describedby="username-hint" />
          <small id="username-hint" className="field-hint">{t('registerUsernameHint')}</small>
          <label htmlFor="register-password">{t('password')}</label>
          <input id="register-password" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} aria-describedby="password-hint" />
          <small id="password-hint" className="field-hint">{t('registerPasswordHint')}</small>
          <label htmlFor="register-confirm">{t('registerConfirm')}</label>
          <input id="register-confirm" type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
          {error && <div className="form-error" role="alert">{error}</div>}
          <button className="button button-primary full-width" disabled={busy}>{busy ? t('registerSubmitting') : t('registerSubmit')}</button>
          <p className="auth-switch">{t('registerHasAccount')} <Link to="/login">{t('registerLogin')}</Link></p>
        </form>
      )}
    </AuthFrame>
  );
}
