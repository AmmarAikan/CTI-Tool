import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api, clearToken } from '../api/client';

const responses = {
  '/api/v1/auth/login': { access_token: 'test-token', token_type: 'bearer', role: 'analyst' },
  '/api/v1/auth/me': { id: 'u1', username: 'analyst', role: 'analyst', is_active: true },
  '/api/v1/integrations/external-control/health': { configured: true, reachable: true },
  '/api/v1/integrations/external-control/sources': [],
} as const;

describe('Phase 1 API paths', () => {
  beforeEach(() => {
    clearToken();
    vi.restoreAllMocks();
  });

  it('uses only same-origin routes beneath /api/v1', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const path = String(input) as keyof typeof responses;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(responses[path]),
      } as Response);
    });

    await api.login('analyst', 'password');
    await api.me();
    await api.externalHealth();
    await api.externalSources();

    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual(Object.keys(responses));
    for (const [input] of fetchMock.mock.calls) {
      expect(String(input)).toMatch(/^\/api\/v1\//);
      expect(String(input)).not.toMatch(/^https?:\/\//);
    }
  });
});
