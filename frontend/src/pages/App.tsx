import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
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

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 30_000, refetchOnWindowFocus: false } } });

export function App() { return <QueryClientProvider client={queryClient}><AuthProvider><BrowserRouter><Routes><Route path="/login" element={<Login />} /><Route element={<ProtectedRoute />}><Route element={<Layout />}><Route index element={<Dashboard />} /><Route path="/external-sources" element={<Sources />} /><Route path="/jobs" element={<Jobs />} /><Route path="/manual" element={<Manual />} /><Route path="/exports" element={<Exports />} /><Route path="/reviews" element={<Reviews />} /></Route></Route><Route path="*" element={<Navigate to="/" replace />} /></Routes></BrowserRouter></AuthProvider></QueryClientProvider>; }
