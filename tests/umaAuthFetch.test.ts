/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { createMockFetch } from './helpers/mockFetch';
import { MemoryStorage } from './helpers/storage';
import { oidcToken, umaConfig, umaTicket, umaToken } from './fixtures/servers';

describe('Auth.createAuthFetch', (): void => {
  it('retries UMA-protected resources and uses the UMA access token', async(): Promise<void> => {
    const resourceUrl = 'http://localhost:3000/demo/private.txt';
    const ticket = umaTicket;

    const fetchMock = createMockFetch([
      {
        request: { url: resourceUrl, method: 'GET' },
        response: {
          status: 401,
          headers: {
            'content-type': 'application/json',
            'www-authenticate': `UMA realm="solid", as_uri="http://localhost:4000/uma", ticket="${ticket}"`,
          },
          body: { error: 'unauthorized' },
        },
      },
      {
        request: {
          url: 'http://localhost:4000/uma/.well-known/uma2-configuration',
          method: 'GET',
        },
        response: {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: umaConfig,
        },
      },
      {
        request: {
          url: 'http://localhost:4000/uma/token',
          method: 'POST',
          body: new RegExp(`"ticket":"${ticket}"`, 'u'),
        },
        response: {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: umaToken,
        },
      },
      {
        request: {
          url: resourceUrl,
          method: 'GET',
          headers: {
            authorization: `Bearer ${umaToken.access_token}`,
          },
        },
        response: {
          status: 200,
          headers: { 'content-type': 'text/plain' },
          body: 'ok',
        },
      },
    ]);

    const auth = new Auth({ fetch: fetchMock, storage: new MemoryStorage() });
    auth.oidcToken = oidcToken.id_token;
    const authFetch = auth.createAuthFetch();

    const response = await authFetch(resourceUrl);
    const text = await response.text();

    expect(response.status).toBe(200);
    expect(text).toBe('ok');
  });
});
