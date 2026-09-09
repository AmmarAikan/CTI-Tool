import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ThemeToggle, THEME_KEY } from '../components/ThemeToggle';

beforeEach(() => { sessionStorage.clear(); document.documentElement.removeAttribute('data-theme'); vi.restoreAllMocks(); });
afterEach(() => { cleanup(); document.documentElement.removeAttribute('data-theme'); vi.restoreAllMocks(); });

describe('theme preference', () => {
  it('defaults to dark and toggles accessibly to persisted light', async () => {
    render(<ThemeToggle />);
    const toggle = screen.getByRole('button', { name: 'تفعيل المظهر الفاتح' });
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark'); expect(toggle).toHaveAttribute('aria-pressed', 'false');
    await userEvent.setup().click(toggle);
    expect(document.documentElement).toHaveAttribute('data-theme', 'light'); expect(toggle).toHaveAttribute('aria-pressed', 'true'); expect(sessionStorage.getItem(THEME_KEY)).toBe('light');
  });

  it('restores valid light preference and ignores corrupted values', () => {
    sessionStorage.setItem(THEME_KEY, 'light'); render(<ThemeToggle />); expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    cleanup(); sessionStorage.setItem(THEME_KEY, 'unexpected'); render(<ThemeToggle />); expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
  });

  it('keeps working when preference storage is unavailable', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('blocked'); });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('blocked'); });
    render(<ThemeToggle />); expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
    await userEvent.setup().click(screen.getByRole('button')); expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  });
});
