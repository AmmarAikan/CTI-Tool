import { useEffect, useState } from 'react';

type Theme = 'dark' | 'light';
const THEME_KEY = 'cti_theme';

function readTheme(): Theme {
  try { return sessionStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark'; }
  catch { return 'dark'; }
}

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme);
  useEffect(() => applyTheme(theme), [theme]);
  const isLight = theme === 'light';
  const toggle = () => {
    const next: Theme = isLight ? 'dark' : 'light';
    setTheme(next); applyTheme(next);
    try { sessionStorage.setItem(THEME_KEY, next); } catch { /* preference storage is optional */ }
  };
  return <button className="theme-toggle" type="button" onClick={toggle} aria-pressed={isLight} aria-label={isLight ? 'تفعيل المظهر الداكن' : 'تفعيل المظهر الفاتح'} title={isLight ? 'المظهر الداكن' : 'المظهر الفاتح'}>
    <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{isLight ? <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></> : <path d="M20 15.2A8.5 8.5 0 0 1 8.8 4a8.5 8.5 0 1 0 11.2 11.2Z" />}</svg>
    <span>{isLight ? 'فاتح' : 'داكن'}</span>
  </button>;
}

export { THEME_KEY };
