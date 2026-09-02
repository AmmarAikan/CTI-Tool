import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/AuthContext';
import { Layout } from '../components/Layout';
import { Placeholder } from '../components/Placeholder';
import { ProtectedRoute } from '../components/ProtectedRoute';
import { Dashboard } from './Dashboard';
import { Login } from './Login';
import { Sources } from './Sources';

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 30_000, refetchOnWindowFocus: false } } });

export function App() { return <QueryClientProvider client={queryClient}><AuthProvider><BrowserRouter><Routes><Route path="/login" element={<Login />} /><Route element={<ProtectedRoute />}><Route element={<Layout />}><Route index element={<Dashboard />} /><Route path="/external-sources" element={<Sources />} /><Route path="/jobs" element={<Placeholder title="الوظائف" />} /><Route path="/manual" element={<Placeholder title="إدخال رابط يدوي" />} /><Route path="/exports" element={<Placeholder title="التصديرات" />} /><Route path="/reviews" element={<Placeholder title="المراجعات" />} /></Route></Route><Route path="*" element={<Navigate to="/" replace />} /></Routes></BrowserRouter></AuthProvider></QueryClientProvider>; }
