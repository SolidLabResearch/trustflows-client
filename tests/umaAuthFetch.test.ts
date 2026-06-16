/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { createMockFetch } from './helpers/mockFetch';
import { MemoryStorage } from './helpers/storage';
import { oidcToken, umaConfig, umaTicket, umaToken, webId } from './fixtures/servers';

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

  it('sends an access request when access is denied and the flag is set', async(): Promise<void> => {
    const resourceUrl = 'http://localhost:3000/demo/private.txt';
    const ticket = umaTicket;
    const escapedWebId = encodeURIComponent(webId);

    let accessRequestBody = '';

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
        },
        response: {
          status: 403,
          headers: { 'content-type': 'application/json' },
          body: { error: 'request_denied' },
        },
      },
      {
        request: {
          url: 'http://localhost:4000/uma/requests',
          method: 'POST',
          headers: {
            authorization: `WebID ${escapedWebId}`,
            'content-type': 'text/turtle',
          },
          body: (body: string): boolean => {
            accessRequestBody = body;
            return true;
          },
        },
        response: {
          status: 201,
          headers: { 'content-type': 'text/turtle' },
          body: '',
        },
      },
    ]);

    const auth = new Auth({ fetch: fetchMock, storage: new MemoryStorage() });
    auth.oidcToken = oidcToken.id_token;
    auth.webId = webId;
    const authFetch = auth.createAuthFetch();

    const response = await authFetch(resourceUrl, undefined, { accessRequest: true });

    expect(response.status).toBe(201);
    expect(accessRequestBody).toContain('a sotw:EvaluationRequest');
    expect(accessRequestBody).toContain(`sotw:requestedTarget <${resourceUrl}>`);
    expect(accessRequestBody).toContain('sotw:requestedAction odrl:read');
    expect(accessRequestBody).toContain(`sotw:requestingParty <${webId}>`);
    expect(accessRequestBody).toContain('ex:requestStatus ex:requested');
  });

  it('maps write methods to odrl:write in access requests', async(): Promise<void> => {
    const resourceUrl = 'http://localhost:3000/demo/private.txt';
    const ticket = umaTicket;

    let accessRequestBody = '';

    const fetchMock = createMockFetch([
      {
        request: { url: resourceUrl, method: 'PUT' },
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
        request: { url: 'http://localhost:4000/uma/token', method: 'POST' },
        response: {
          status: 403,
          headers: { 'content-type': 'application/json' },
          body: { error: 'request_denied' },
        },
      },
      {
        request: {
          url: 'http://localhost:4000/uma/requests',
          method: 'POST',
          body: (body: string): boolean => {
            accessRequestBody = body;
            return true;
          },
        },
        response: { status: 201, body: '' },
      },
    ]);

    const auth = new Auth({ fetch: fetchMock, storage: new MemoryStorage() });
    auth.oidcToken = oidcToken.id_token;
    auth.webId = webId;
    const authFetch = auth.createAuthFetch();

    const response = await authFetch(resourceUrl, { method: 'PUT' }, { accessRequest: true });

    expect(response.status).toBe(201);
    expect(accessRequestBody).toContain('sotw:requestedAction odrl:write');
  });

  it('does not send an access request when the flag is not set', async(): Promise<void> => {
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
        request: { url: 'http://localhost:4000/uma/token', method: 'POST' },
        response: {
          status: 403,
          headers: { 'content-type': 'application/json' },
          body: { error: 'request_denied' },
        },
      },
    ]);

    const auth = new Auth({ fetch: fetchMock, storage: new MemoryStorage() });
    auth.oidcToken = oidcToken.id_token;
    auth.webId = webId;
    const authFetch = auth.createAuthFetch();

    await expect(authFetch(resourceUrl)).rejects.toThrow();
  });
});
