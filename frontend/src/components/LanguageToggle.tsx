import { useI18n } from '../i18n/I18nContext';
export function LanguageToggle(){const {language,t,toggle}=useI18n();const label=t('languageToggle');return <button type="button" className="utility-toggle language-toggle" onClick={toggle} aria-label={label} title={label} aria-pressed={language==='en'}><span aria-hidden="true">{t('languageActionSymbol')}</span></button>}
