import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider } from '../auth/AuthContext';
import { ReactNode } from 'react';
import { I18nProvider } from '../i18n/I18nContext';

export function renderWithProviders(ui: ReactNode, entries = ['/']) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<I18nProvider><QueryClientProvider client={client}><AuthProvider><MemoryRouter initialEntries={entries}>{ui}</MemoryRouter></AuthProvider></QueryClientProvider></I18nProvider>);
}
