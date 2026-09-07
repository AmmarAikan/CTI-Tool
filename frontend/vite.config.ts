import { defineConfig, loadEnv, type UserConfig } from 'vite';
import react from '@vitejs/plugin-react';

export const API_PROXY_PATH = '/api/v1';
export const DEFAULT_BACKEND_PROXY_TARGET = 'http://127.0.0.1:8000';

export function backendProxyTarget(value?: string): string {
  const candidate = value?.trim() || DEFAULT_BACKEND_PROXY_TARGET;
  const target = /^(https?):\/\/([^/?#\s]+)\/?$/.exec(candidate);
  if (!target || target[2].includes('@')) {
    throw new Error('CTI_BACKEND_PROXY_TARGET must be an HTTP(S) origin without credentials or a path');
  }
  return `${target[1]}://${target[2]}`;
}

export function createViteConfig(proxyTarget?: string): UserConfig {
  return {
    plugins: [react()],
    build: { sourcemap: false },
    server: {
      proxy: {
        [API_PROXY_PATH]: {
          target: backendProxyTarget(proxyTarget),
          changeOrigin: false,
        },
      },
    },
  };
}

export default defineConfig(({ mode }) => {
  const serverEnvironment = loadEnv(mode, '.', 'CTI_BACKEND_PROXY_TARGET');
  return createViteConfig(serverEnvironment.CTI_BACKEND_PROXY_TARGET);
});
