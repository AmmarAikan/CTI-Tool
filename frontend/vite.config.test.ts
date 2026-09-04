import { describe, expect, it } from 'vitest';
import {
  API_PROXY_PATH,
  DEFAULT_BACKEND_PROXY_TARGET,
  backendProxyTarget,
  createViteConfig,
} from './vite.config';

describe('Vite Backend proxy', () => {
  it('proxies only the same-origin API prefix to the server-side target', () => {
    const config = createViteConfig('http://127.0.0.1:18000');
    expect(Object.keys(config.server?.proxy || {})).toEqual(['/api/v1']);
    expect(config.server?.proxy?.[API_PROXY_PATH]).toEqual({
      target: 'http://127.0.0.1:18000',
      changeOrigin: false,
    });
  });

  it('keeps the development default local and rejects credentials or paths', () => {
    expect(backendProxyTarget()).toBe(DEFAULT_BACKEND_PROXY_TARGET);
    expect(() => backendProxyTarget('http://user:password@127.0.0.1:18000')).toThrow();
    expect(() => backendProxyTarget('http://127.0.0.1:18000/api/v1')).toThrow();
    expect(() => backendProxyTarget('file:///tmp/backend')).toThrow();
  });
});
