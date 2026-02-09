/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { createMockFetch } from './helpers/mockFetch';
import { installBrowserGlobals } from './helpers/browserGlobals';
import { MemoryStorage } from './helpers/storage';
import { oidcConfig, oidcToken, webId } from './fixtures/servers';

function resolveRequestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }
  if (input instanceof URL) {
    return input.toString();
  }
  return input.url;
}

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

  it('does not send multiple token requests for concurrent redirects', async(): Promise<void> => {
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

    let releaseToken!: () => void;
    const tokenGate = new Promise<void>((resolve): void => {
      releaseToken = resolve;
    });

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

    let tokenRequests = 0;
    async function gatedFetch(
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> {
      const url = resolveRequestUrl(input);
      if (url === 'http://localhost:3000/.oidc/token') {
        tokenRequests += 1;
        await tokenGate;
      }
      return fetchMock(input, init);
    }

    const auth = new Auth({ fetch: gatedFetch, storage });
    const firstPromise = auth.handleIncomingRedirect();
    const secondPromise = auth.handleIncomingRedirect();

    releaseToken();

    const [ first, second ] = await Promise.all([ firstPromise, secondPromise ]);
    expect(first).toBe(true);
    expect(second).toBe(true);
    expect(tokenRequests).toBe(1);
    expect(auth.oidcAccessToken).toBe(oidcToken.access_token);
    expect(auth.oidcToken).toBe(oidcToken.id_token);
  });

  it('waits for in-progress redirect when checking login', async(): Promise<void> => {
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

    let releaseToken!: () => void;
    const tokenGate = new Promise<void>((resolve): void => {
      releaseToken = resolve;
    });

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

    async function gatedFetch(
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> {
      const url = resolveRequestUrl(input);
      if (url === 'http://localhost:3000/.oidc/token') {
        await tokenGate;
      }
      return fetchMock(input, init);
    }

    const auth = new Auth({ fetch: gatedFetch, storage });
    const handlePromise = auth.handleIncomingRedirect();
    let resolved = false;
    const loggedInPromise = auth.isLoggedIn().then((status): boolean => {
      resolved = true;
      return status;
    });

    await Promise.resolve();

    expect(resolved).toBe(false);

    releaseToken();

    const loggedIn = await loggedInPromise;
    const ok = await handlePromise;
    expect(ok).toBe(true);
    expect(loggedIn).toBe(true);
    expect(auth.oidcAccessToken).toBe(oidcToken.access_token);
    expect(auth.oidcToken).toBe(oidcToken.id_token);
  });
});
