import { describe, expect, it } from 'vitest';
import { ar, en } from '../i18n/I18nContext';

const productionSources = import.meta.glob(['../components/**/*.tsx', '../pages/**/*.tsx', '../auth/**/*.tsx', '../main.tsx'], { eager: true, query: '?raw', import: 'default' }) as Record<string, string>;
const productionEntries = Object.entries(productionSources);
const sourceLabel = (path: string) => path.replace(/^\.\.\//, '').replace(/^\.\//, '');

function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('static localization contract', () => {
  it('keeps Arabic and English catalogs identical', () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(ar).sort());
  });

  it('contains no hardcoded Arabic in production TSX outside the Arabic catalog', () => {
    const violations = productionEntries.flatMap(([path, contents]) => {
      const source = withoutComments(contents);
      return source.split('\n').flatMap((line, index) => /[\u0600-\u06ff]/u.test(line)
        ? [`${sourceLabel(path)}:${index + 1}`]
        : []);
    });
    expect(violations, 'Move rendered Arabic into i18n/I18nContext.tsx').toEqual([]);
  });

  it('does not branch page rendering on the active language', () => {
    const violations = productionEntries.filter(([path]) => path.includes('/pages/')).flatMap(([path, contents]) => {
      const source = withoutComments(contents);
      return /\b(language|locale)\s*(?:===|!==|\?|&&|\|\|)/u.test(source)
        ? [sourceLabel(path)]
        : [];
    });
    expect(violations, 'Use typed catalog keys instead of page-local language branches').toEqual([]);
  });
});
