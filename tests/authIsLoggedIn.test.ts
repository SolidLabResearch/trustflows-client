import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { MemoryStorage } from './helpers/storage';

describe('Auth.isLoggedIn', (): void => {
  it('returns false when no tokens are present', async(): Promise<void> => {
    const auth = new Auth({
      fetch: async(): Promise<Response> => new Response('', { status: 500 }),
      storage: new MemoryStorage(),
    });

    await expect(auth.isLoggedIn()).resolves.toBe(false);
  });

  it('returns true when an access token is present', async(): Promise<void> => {
    const auth = new Auth({
      fetch: async(): Promise<Response> => new Response('', { status: 500 }),
      storage: new MemoryStorage(),
    });
    auth.oidcAccessToken = 'access-token';

    await expect(auth.isLoggedIn()).resolves.toBe(true);
  });

  it('returns true when an id token is present', async(): Promise<void> => {
    const auth = new Auth({
      fetch: async(): Promise<Response> => new Response('', { status: 500 }),
      storage: new MemoryStorage(),
    });
    auth.oidcToken = 'id-token';

    await expect(auth.isLoggedIn()).resolves.toBe(true);
  });
});
