import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { LanguageToggle } from './LanguageToggle';
import { ThemeToggle } from './ThemeToggle';
import { useI18n } from '../i18n/I18nContext';

export function PublicHeader() {
  const { t } = useI18n();
  return (
    <header className="public-header">
      <Link className="brand public-brand" to="/" aria-label={t('platform')}>
        <span className="brand-mark">CTI</span>
        <span>
          <strong>ACTIT</strong>
          <small>{t('brandSub')}</small>
        </span>
      </Link>
      <div className="public-tools">
        <span className="public-secure-state">
          <span className="online-dot" />
          {t('secureConnection')}
        </span>
        <LanguageToggle />
        <ThemeToggle />
      </div>
    </header>
  );
}

interface AuthFrameProps {
  eyebrow: string;
  title: string;
  description: string;
  asideEyebrow: string;
  asideTitle: string;
  asideDescription: string;
  signals: Array<{ label: string; value: string }>;
  children: ReactNode;
}

export function AuthFrame({
  eyebrow,
  title,
  description,
  asideEyebrow,
  asideTitle,
  asideDescription,
  signals,
  children,
}: AuthFrameProps) {
  return (
    <main className="public-page auth-page">
      <PublicHeader />
      <div className="auth-grid">
        <section className="auth-panel" aria-labelledby="auth-title">
          <div className="auth-heading">
            <span className="eyebrow">{eyebrow}</span>
            <h1 id="auth-title">{title}</h1>
            <p>{description}</p>
          </div>
          {children}
        </section>
        <aside className="auth-aside">
          <div className="auth-aside-copy">
            <span className="aside-kicker">{asideEyebrow}</span>
            <h2>{asideTitle}</h2>
            <p>{asideDescription}</p>
          </div>
          <dl className="auth-signals">
            {signals.map((signal) => (
              <div key={signal.label}>
                <dt>{signal.label}</dt>
                <dd>{signal.value}</dd>
              </div>
            ))}
          </dl>
        </aside>
      </div>
    </main>
  );
}
