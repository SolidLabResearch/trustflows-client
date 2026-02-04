/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { createMockFetch } from './helpers/mockFetch';
import { MemoryStorage } from './helpers/storage';
import { oidcConfig, oidcToken, webId } from './fixtures/servers';

function installBrowserGlobals(url: string): void {
  globalThis.window = {
    location: { href: url },
    history: {
      replaceState: (...args: unknown[]): void => {
        void args;
      },
    },
  } as unknown as Window;
  globalThis.document = { title: 'Temp client tests' } as Document;
  globalThis.atob = (value: string): string =>
    Buffer.from(value, 'base64').toString('binary');
  globalThis.btoa = (value: string): string =>
    Buffer.from(value, 'binary').toString('base64');
}

describe('Auth.handleIncomingRedirect', (): void => {
  it('exchanges the auth code and stores tokens', async(): Promise<void> => {
    installBrowserGlobals(
      'http://localhost:5173/temp-client/app/?code=test-code&state=test-state',
    );

    const storage = new MemoryStorage();
    storage.setItem('oidc_state', 'test-state');
    storage.setItem('oidc_code_verifier', 'verifier-123');
    storage.setItem('oidc_issuer', 'http://localhost:3000');
    storage.setItem('oidc_client_id', 'http://localhost:5173/temp-client/app/client-id.jsonld');
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
