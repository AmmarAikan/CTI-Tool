import { useI18n } from '../i18n/I18nContext';
export function LanguageToggle(){const {language,t,toggle}=useI18n();return <button type="button" className="utility-toggle language-toggle" onClick={toggle} aria-label={t('languageToggle')} aria-pressed={language==='en'}><span aria-hidden="true">文</span><span>{language==='ar'?'EN':'AR'}</span></button>}
