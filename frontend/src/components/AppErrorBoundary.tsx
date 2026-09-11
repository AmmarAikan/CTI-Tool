import { Component, type ErrorInfo, type ReactNode } from 'react';
import { useI18n } from '../i18n/I18nContext';

function FatalState() { const { t } = useI18n(); return <main className="fatal-state" role="alert"><strong>{t('fatalTitle')}</strong><p>{t('fatalHint')}</p><a className="button button-primary" href="/">{t('backDashboard')}</a></main>; }

export class AppErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(_error: Error, _info: ErrorInfo) { /* Never render or forward runtime details. */ }
  render() {
    if (this.state.failed) return <FatalState />;
    return this.props.children;
  }
}

export function NotFound() { const { t } = useI18n(); return <section className="page-section"><div className="state-panel"><strong>{t('notFound')}</strong><p>{t('notFoundHint')}</p><a className="button button-secondary" href="/">{t('dashboard')}</a></div></section>; }
