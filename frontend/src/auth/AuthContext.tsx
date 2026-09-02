import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, clearToken, getToken, setToken, type Role, type User } from '../api/client';

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  can: (role: Role) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(Boolean(getToken()));

  useEffect(() => {
    const unauthorized = () => { setUser(null); setLoading(false); };
    window.addEventListener('cti:unauthorized', unauthorized);
    if (getToken()) api.me().then(setUser).catch(() => clearToken()).finally(() => setLoading(false));
    return () => window.removeEventListener('cti:unauthorized', unauthorized);
  }, []);

  async function login(username: string, password: string) {
    const response = await api.login(username, password);
    setToken(response.access_token);
    try { setUser(await api.me()); } catch (error) { clearToken(); throw error; }
  }

  function logout() { clearToken(); setUser(null); }
  function can(role: Role) { return user?.role === 'admin' || user?.role === role || (role === 'viewer' && (user?.role === 'analyst')); }

  return <AuthContext.Provider value={{ user, loading, login, logout, can }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used within AuthProvider');
  return value;
}
