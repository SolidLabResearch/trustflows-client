/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { createMockFetch } from './helpers/mockFetch';
import { installBrowserGlobals } from './helpers/browserGlobals';
import { MemoryStorage } from './helpers/storage';
import { oidcConfig, oidcToken, webId } from './fixtures/servers';

describe('Auth.handleIncomingRedirect', (): void => {
  it('exchanges the auth code and stores tokens', async(): Promise<void> => {
    const { location } = installBrowserGlobals({
      url: 'http://localhost:5173/temp-client/app/?code=test-code&state=test-state',
    });
    const redirectUri = new URL('/temp-client/app/', location.href).toString();
    const clientId = new URL('client-id.jsonld', redirectUri).toString();

    const storage = new MemoryStorage();
    storage.setItem('oidc_state', 'test-state');
    storage.setItem('oidc_code_verifier', 'verifier-123');
    storage.setItem('oidc_issuer', 'http://localhost:3000');
    storage.setItem('oidc_client_id', clientId);
    storage.setItem('oidc_redirect_uri', redirectUri);

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
      {
        request: {
          url: 'http://localhost:3000/.oidc/token',
          method: 'POST',
          body: /grant_type=authorization_code/u,
        },
        response: {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: oidcToken,
        },
      },
    ]);

    const auth = new Auth({ fetch: fetchMock, storage });
    const ok = await auth.handleIncomingRedirect();

    expect(ok).toBe(true);
    expect(auth.oidcAccessToken).toBe(oidcToken.access_token);
    expect(auth.oidcToken).toBe(oidcToken.id_token);
    expect(auth.webId).toBe(webId);
  });
});
