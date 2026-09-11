import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/AuthContext';
import { Layout } from '../components/Layout';
import { ProtectedRoute } from '../components/ProtectedRoute';
import { Dashboard } from './Dashboard';
import { Login } from './Login';
import { Manual } from './Manual';
import { Sources } from './Sources';
import { Exports } from './Exports';
import { Reviews } from './Reviews';
import { Jobs } from './Jobs';
import { InternalOverview, InternalSourcePage } from './InternalSources';
import { AnalysisPage, AttackPage, CorrelationsPage, EventDetailPage, EventsPage, IndicatorsPage, IntelligenceOverview, MISPPage, OutliersPage } from './Intelligence';
import { AdminGuard, AdminPage } from './Admin';
import { AppErrorBoundary, NotFound } from '../components/AppErrorBoundary';
import { DarkWebWatches } from './DarkWebWatches';
import { ProcessingCenter } from './ProcessingCenter';

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 30_000, refetchOnWindowFocus: false } } });

export function App() { return <AppErrorBoundary><QueryClientProvider client={queryClient}><AuthProvider><BrowserRouter><Routes><Route path="/login" element={<Login />} /><Route element={<ProtectedRoute />}><Route element={<Layout />}><Route index element={<Dashboard />} /><Route path="/external-sources" element={<Sources />} /><Route path="/dark-web" element={<DarkWebWatches />} /><Route path="/jobs" element={<Jobs />} /><Route path="/manual" element={<Manual />} /><Route path="/exports" element={<Exports />} /><Route path="/reviews" element={<Reviews />} /><Route path="/internal-sources" element={<InternalOverview />} /><Route path="/internal-sources/dionaea" element={<InternalSourcePage integration="dionaea" />} /><Route path="/internal-sources/host-auth" element={<InternalSourcePage integration="host-auth" />} /><Route path="/internal-sources/web-access" element={<InternalSourcePage integration="web-access" />} /><Route path="/intelligence" element={<IntelligenceOverview />} /><Route path="/intelligence/events" element={<EventsPage />} /><Route path="/intelligence/events/:eventId" element={<EventDetailPage />} /><Route path="/intelligence/indicators" element={<IndicatorsPage />} /><Route path="/intelligence/attack" element={<AttackPage />} /><Route path="/intelligence/correlations" element={<CorrelationsPage />} /><Route path="/intelligence/outliers" element={<OutliersPage />} /><Route path="/processing-center" element={<ProcessingCenter />} /><Route path="/analysis" element={<AnalysisPage />} /><Route path="/misp" element={<MISPPage />} /><Route path="/admin" element={<AdminGuard><AdminPage /></AdminGuard>} /><Route path="*" element={<NotFound />} /></Route></Route></Routes></BrowserRouter></AuthProvider></QueryClientProvider></AppErrorBoundary>; }
