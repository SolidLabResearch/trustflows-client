/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { createMockFetch } from './helpers/mockFetch';
import { MemoryStorage } from './helpers/storage';
import { oidcConfig } from './fixtures/servers';

describe('Auth.logout', (): void => {
  it('clears tokens and redirects to the end_session_endpoint', async(): Promise<void> => {
    let redirectedTo: string | undefined;
    const storage = new MemoryStorage();
    storage.setItem('oidc_issuer', 'http://localhost:3000');
    storage.setItem('oidc_redirect_uri', 'http://localhost:5173/temp-client/app/');

    const fetchMock = createMockFetch([
      {
        request: {
          url: 'http://localhost:3000/.well-known/openid-configuration',
          method: 'GET',
        },
        response: {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: oidcConfig,
        },
      },
    ]);

    const auth = new Auth({
      fetch: fetchMock,
      redirect: (url: string): void => {
        redirectedTo = url;
      },
      storage,
    });
    auth.oidcToken = 'id-token';
    auth.oidcAccessToken = 'access-token';

    await auth.logout('http://localhost:5173/temp-client/app/');

    expect(auth.oidcToken).toBeUndefined();
    expect(auth.oidcAccessToken).toBeUndefined();
    expect(redirectedTo).toContain('http://localhost:3000/.oidc/session/end');
    expect(redirectedTo).toContain('post_logout_redirect_uri=');
    expect(redirectedTo).toContain('id_token_hint=');
  });
});
