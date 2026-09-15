import { Link } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { PublicHeader } from '../components/PublicFrame';
import { useI18n, type TranslationKey } from '../i18n/I18nContext';

const steps: Array<[string, TranslationKey, TranslationKey]> = [
  ['01', 'landingCollect', 'landingCollectDetail'],
  ['02', 'landingExtract', 'landingExtractDetail'],
  ['03', 'landingCorrelate', 'landingCorrelateDetail'],
  ['04', 'landingShare', 'landingShareDetail'],
];
const cards: Array<[TranslationKey, TranslationKey]> = [
  ['landingEvidenceTitle', 'landingEvidenceDescription'],
  ['landingCorrelationTitle', 'landingCorrelationDescription'],
  ['landingBehaviorTitle', 'landingBehaviorDescription'],
  ['landingSharingTitle', 'landingSharingDescription'],
];
const trust: TranslationKey[] = [
  'landingTrustViewer',
  'landingTrustWrite',
  'landingTrustAudit',
];

export function Landing() {
  const { t } = useI18n();
  const { user } = useAuth();

  return (
    <main className="public-page landing-page">
      <PublicHeader />
      <section className="landing-hero">
        <div className="landing-copy">
          <span className="eyebrow">{t('landingEyebrow')}</span>
          <h1>{t('landingTitle')}</h1>
          <p>{t('landingDescription')}</p>
          <div className="landing-actions">
            <Link className="button button-primary" to={user ? '/dashboard' : '/login'}>
              {user ? t('landingResume') : t('landingEnter')}
            </Link>
            {!user && <Link className="button button-secondary" to="/register">{t('landingRegister')}</Link>}
          </div>
          <ul className="trust-list" aria-label={t('landingAccessControls')}>
            {trust.map((key) => <li key={key}><span aria-hidden="true">✓</span>{t(key)}</li>)}
          </ul>
        </div>
        <div className="landing-terminal" aria-label={t('landingLifecycle')}>
          <div className="terminal-head">
            <span>{t('landingPipeline')}</span>
            <span className="terminal-live"><i /> {t('landingEvidenceReady')}</span>
          </div>
          <ol>
            {steps.map(([index, title, detail]) => (
              <li key={index}>
                <span>{index}</span>
                <div><strong>{t(title)}</strong><p>{t(detail)}</p></div>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="landing-section" aria-labelledby="lifecycle-title">
        <div className="section-heading compact">
          <div>
            <span className="eyebrow">{t('landingKnowledgeAction')}</span>
            <h2 id="lifecycle-title">{t('landingCapabilities')}</h2>
            <p>{t('landingCapabilitiesHint')}</p>
          </div>
        </div>
        <div className="capability-grid">
          {cards.map(([title, detail], index) => (
            <article key={title}>
              <span>0{index + 1}</span>
              <h3>{t(title)}</h3>
              <p>{t(detail)}</p>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
