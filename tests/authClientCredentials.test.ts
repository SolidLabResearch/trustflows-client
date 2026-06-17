/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { createMockFetch, type MockFetchStep } from './helpers/mockFetch';
import { MemoryStorage } from './helpers/storage';
import { oidcConfig, oidcToken, webId } from './fixtures/servers';

const issuer = 'http://localhost:3000';
const id = 'test-id';
const secret = 'test-secret';
const email = 'alice@example.org';
const password = 'abc123';
const clientCredentialsToken = {
  access_token: oidcToken.access_token,
  token_type: 'Bearer',
  expires_in: 3600,
};
function expectedBasicHeader(): string {
  const authString = `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;
  return `Basic ${btoa(authString)}`;
}
// Dereferencing the WebID profile to discover the solid:oidcIssuer.
const profileStep: MockFetchStep = {
  request: { url: 'http://localhost:3000/demo/profile/card', method: 'GET' },
  response: {
    status: 200,
    headers: { 'content-type': 'text/turtle' },
    body:
      '@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n' +
      `<${webId}> solid:oidcIssuer <http://localhost:3000/> .\n`,
  },
};
// The four account-API requests that mint a client credentials token.
const accountSteps: MockFetchStep[] = [
  {
    request: { url: 'http://localhost:3000/.account/', method: 'GET' },
    response: {
      status: 200,
      body: {
        controls: {
          password: { login: 'http://localhost:3000/.account/login/password/' },
        },
      },
    },
  },
  {
    request: {
      url: 'http://localhost:3000/.account/login/password/',
      method: 'POST',
      body: (body): boolean => body.includes(email) && body.includes(password),
    },
    response: { status: 200, body: { authorization: 'account-token-123' }},
  },
  {
    request: {
      url: 'http://localhost:3000/.account/',
      method: 'GET',
      headers: { authorization: 'CSS-Account-Token account-token-123' },
    },
    response: {
      status: 200,
      body: {
        controls: {
          account: {
            clientCredentials: 'http://localhost:3000/.account/credentials/',
          },
        },
      },
    },
  },
  {
    request: {
      url: 'http://localhost:3000/.account/credentials/',
      method: 'POST',
      headers: { authorization: 'CSS-Account-Token account-token-123' },
      body: (body): boolean =>
        body.includes('"name":"trustflows-client-') &&
        body.includes(`"webId":"${webId}"`),
    },
    response: {
      status: 200,
      body: { id, secret, resource: 'http://localhost:3000/.account/credentials/x' },
    },
  },
];
const configStep: MockFetchStep = {
  request: {
    url: 'http://localhost:3000/.well-known/openid-configuration',
    method: 'GET',
  },
  response: { status: 200, body: oidcConfig },
};
const tokenStep: MockFetchStep = {
  request: {
    url: 'http://localhost:3000/.oidc/token',
    method: 'POST',
    headers: { authorization: expectedBasicHeader() },
    body: (body): boolean =>
      body.includes('grant_type=client_credentials') &&
      body.includes('scope=webid'),
  },
  response: { status: 200, body: clientCredentialsToken },
};
describe('Auth.loginClientCredentials', (): void => {
  it('derives the server from the WebID, mints a token and logs in', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([ profileStep, ...accountSteps, configStep, tokenStep ]);
    const auth = new Auth({ fetch: fetchMock, storage });
    await auth.loginClientCredentials(webId, email, password);
    expect(auth.oidcToken).toBe(oidcToken.access_token);
    expect(auth.oidcAccessToken).toBe(oidcToken.access_token);
    expect(auth.webId).toBe(webId);
    expect(storage.getItem('oidc_issuer')).toBe(issuer);
    expect(storage.getItem('client_credentials')).toBe(
      JSON.stringify({ id, secret, scope: 'webid' }),
    );
  });
  it('discovers the issuer from a JSON-LD WebID profile', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const jsonLdProfileStep: MockFetchStep = {
      request: { url: 'http://localhost:3000/demo/profile/card', method: 'GET' },
      response: {
        status: 200,
        headers: { 'content-type': 'application/ld+json' },
        body: JSON.stringify({
          '@id': webId,
          'http://www.w3.org/ns/solid/terms#oidcIssuer': { '@id': 'http://localhost:3000/' },
        }),
      },
    };
    const fetchMock = createMockFetch([ jsonLdProfileStep, ...accountSteps, configStep, tokenStep ]);
    const auth = new Auth({ fetch: fetchMock, storage });
    await auth.loginClientCredentials(webId, email, password);
    expect(auth.oidcToken).toBe(oidcToken.access_token);
    expect(auth.oidcAccessToken).toBe(oidcToken.access_token);
    expect(storage.getItem('oidc_issuer')).toBe(issuer);
  });
  it('re-requests a fresh token when the current one expires', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([
      profileStep,
      ...accountSteps,
      configStep,
      tokenStep,
      configStep,
      tokenStep,
    ]);
    const auth = new Auth({ fetch: fetchMock, storage });
    await auth.loginClientCredentials(webId, email, password);
    auth.oidcTokenExpiry = Date.now() - 1000;
    await auth.ensureValidToken();
    expect(auth.oidcToken).toBe(oidcToken.access_token);
    expect(auth.oidcAccessToken).toBe(oidcToken.access_token);
  });
  it('restores client credentials from storage so renewal keeps working', async(): Promise<void> => {
    const storage = new MemoryStorage();
    storage.setItem('oidc_issuer', issuer);
    storage.setItem(
      'client_credentials',
      JSON.stringify({ id, secret, scope: 'webid' }),
    );
    storage.setItem(
      'oidc_tokens',
      JSON.stringify({ access_token: 'stale', expires_at: Date.now() - 1000 }),
    );
    const fetchMock = createMockFetch([ configStep, tokenStep ]);
    const auth = new Auth({ fetch: fetchMock, storage });
    await auth.ensureValidToken();
    expect(auth.oidcToken).toBe(oidcToken.access_token);
    expect(auth.oidcAccessToken).toBe(oidcToken.access_token);
    expect(auth.webId).toBe(webId);
  });
});
