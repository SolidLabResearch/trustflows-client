/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import type {
  Auth,
  Claim,
  ClaimResolverDefinition,
  PermissionDescription,
} from '../src';
import {
  createDefaultClaimResolvers,
  fetchAccessToken,
  ID_TOKEN_CLAIM_FORMAT,
} from '../src';

function makeAuth(
  fetchFn: typeof fetch,
  resolvers: ClaimResolverDefinition[],
): Auth {
  return {
    getFetch: (): typeof fetch => fetchFn,
    createClaimToken: async(): Promise<string> => 'id-token',
    getClaimResolvers: (): ClaimResolverDefinition[] => resolvers,
  } as unknown as Auth;
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  return input.url;
}

function jwt(payload: Record<string, unknown>): string {
  const encoded = btoa(JSON.stringify(payload))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
  return `header.${encoded}.signature`;
}

describe('fetchAccessToken', (): void => {
  it('pushes one claim at a time until an access token is returned', async(): Promise<void> => {
    const calls: { body: Record<string, unknown> }[] = [];
    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const body: Record<string, unknown> = init?.body ?
          (JSON.parse(init.body as string) as Record<string, unknown>) :
          {};
      calls.push({ body });

      if (calls.length === 1) {
        return new Response(
          JSON.stringify({
            error: 'need_info',
            required_claims: [{ claim_type: 'demo-claim' }],
            ticket: 't2',
          }),
          { status: 403, headers: { 'content-type': 'application/json' }},
        );
      }

      if (calls.length === 2) {
        return new Response(
          JSON.stringify({ access_token: 'access-1', token_type: 'Bearer' }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      throw new Error('Unexpected fetch call.');
    };

    const resolvers: ClaimResolverDefinition[] = [
      {
        id: 'demo',
        match: { claim_type: 'demo-claim' },
        resolve: async(): Promise<Claim> => ({
          claim_token: 'demo-token',
          claim_token_format: 'urn:example:demo',
        }),
      },
    ];

    const auth = makeAuth(fetchMock, resolvers);

    const result = await fetchAccessToken(auth, 'https://as.example/token', 't1');

    expect(result).toEqual({
      access_token: 'access-1',
      token_type: 'Bearer',
    });

    expect(calls).toHaveLength(2);
    expect(calls[0].body).toMatchObject({
      grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
      ticket: 't1',
      claim_token: 'id-token',
      claim_token_format: ID_TOKEN_CLAIM_FORMAT,
    });
    expect(calls[0].body).not.toHaveProperty('claim_tokens');

    expect(calls[1].body).toMatchObject({
      grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
      ticket: 't2',
      claim_token: 'demo-token',
      claim_token_format: 'urn:example:demo',
    });
  });

  it('errors when the server requests a claim that was already pushed', async(): Promise<void> => {
    async function fetchMock(): Promise<Response> {
      return new Response(
        JSON.stringify({
          error: 'need_info',
          required_claims: [{ claim_token_format: ID_TOKEN_CLAIM_FORMAT }],
        }),
        { status: 403, headers: { 'content-type': 'application/json' }},
      );
    }

    const auth = makeAuth(fetchMock, []);

    await expect(
      fetchAccessToken(auth, 'https://as.example/token', 't1'),
    ).rejects.toThrow(/already pushed/u);
  });

  it('treats empty claim token formats as unauthorized', async(): Promise<void> => {
    const ticket = 'a84c42a6-adac-4cb8-902c-affcadd41aa2';
    async function fetchMock(): Promise<Response> {
      return new Response(
        JSON.stringify({
          error: 'need_info',
          ticket,
          required_claims: { claim_token_format: [[]]},
        }),
        { status: 403, headers: { 'content-type': 'application/json' }},
      );
    }

    const auth = makeAuth(fetchMock, []);

    await expect(
      fetchAccessToken(auth, 'https://as.example/token', 't1'),
    ).rejects.toMatchObject({
      status: 401,
      payload: { ticket },
    });
  });

  // Replication test for the bug where an auth server requests multiple
  // access-token claims that only differ by the targeted resource
  // (derivation_resource_id / resource_scopes) but share the same
  // claim_type and issuer. These permissions should be combined into a
  // single token request to the shared issuer and satisfied with one claim
  // token, instead of failing with an "already pushed" error.
  it('combines multiple access-token permissions for the same issuer', async(): Promise<void> => {
    const DERIVATION_ACCESS = 'https://w3id.org/aggregator#derivation-access';
    const ACCESS_TOKEN_FORMAT = 'urn:ietf:params:oauth:token-type:access_token';

    const resourceServer = 'https://rs.example/token';
    const issuer = 'https://as.example';
    const issuerConfigUrl = `${issuer}/.well-known/uma2-configuration`;
    const issuerTokenEndpoint = `${issuer}/token`;

    const requiredClaims = [
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'res-A',
        resource_scopes: [ 'read' ],
      },
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'res-B',
        resource_scopes: [ 'write' ],
      },
    ];

    const calls: { url: string; body: Record<string, unknown> }[] = [];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = requestUrl(input);
      const body: Record<string, unknown> = init?.body ?
          (JSON.parse(init.body as string) as Record<string, unknown>) :
          {};
      calls.push({ url, body });

      // The issuer's UMA configuration advertises its token endpoint.
      if (url === issuerConfigUrl) {
        return new Response(
          JSON.stringify({ token_endpoint: issuerTokenEndpoint, issuer }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      // The shared issuer grants a single access token covering all
      // requested permissions in one round trip.
      if (url === issuerTokenEndpoint) {
        return new Response(
          JSON.stringify({ access_token: 'combined-access', token_type: 'Bearer' }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      const resourceServerCalls = calls.filter(
        (call): boolean => call.url === resourceServer,
      );

      // The resource server first asks for the two access-token claims, then
      // grants the token once the combined claim token has been pushed.
      if (resourceServerCalls.length === 1) {
        return new Response(
          JSON.stringify({
            error: 'need_info',
            required_claims: requiredClaims,
            ticket: 't2',
          }),
          { status: 403, headers: { 'content-type': 'application/json' }},
        );
      }

      return new Response(
        JSON.stringify({ access_token: 'access-final', token_type: 'Bearer' }),
        { status: 200, headers: { 'content-type': 'application/json' }},
      );
    };

    const auth = makeAuth(fetchMock, createDefaultClaimResolvers());

    const result = await fetchAccessToken(auth, resourceServer, 't1');

    expect(result).toEqual({
      access_token: 'access-final',
      token_type: 'Bearer',
    });

    const issuerCalls = calls.filter(
      (call): boolean => call.url === issuerTokenEndpoint,
    );
    const resourceServerCalls = calls.filter(
      (call): boolean => call.url === resourceServer,
    );

    // The issuer is contacted exactly once, with both permissions combined.
    expect(issuerCalls).toHaveLength(1);
    expect(issuerCalls[0].body.permissions).toEqual([
      { resource_id: 'res-A', resource_scopes: [ 'read' ]},
      { resource_id: 'res-B', resource_scopes: [ 'write' ]},
    ]);

    // The resource server is satisfied with a single combined claim token.
    expect(resourceServerCalls).toHaveLength(2);
    expect(resourceServerCalls[1].body).toMatchObject({
      ticket: 't2',
      claim_token: 'combined-access',
      claim_token_format: ACCESS_TOKEN_FORMAT,
    });
  });

  it('resolves access-token permissions for multiple issuers before retrying', async(): Promise<void> => {
    const DERIVATION_ACCESS = 'https://w3id.org/aggregator#derivation-access';
    const ACCESS_TOKEN_FORMAT = 'urn:ietf:params:oauth:token-type:access_token';

    const resourceServer = 'https://rs.example/token';
    const issuerA = 'https://as-a.example';
    const issuerB = 'https://as-b.example';
    const requiredClaims = [
      {
        claim_type: DERIVATION_ACCESS,
        issuer: issuerA,
        derivation_resource_id: 'res-A',
        resource_scopes: [ 'read' ],
      },
      {
        claim_type: DERIVATION_ACCESS,
        issuer: issuerB,
        derivation_resource_id: 'res-B',
        resource_scopes: [ 'write' ],
      },
    ];

    const calls: { url: string; body: Record<string, unknown> }[] = [];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = requestUrl(input);
      const body: Record<string, unknown> = init?.body ?
          (JSON.parse(init.body as string) as Record<string, unknown>) :
          {};
      calls.push({ url, body });

      if (url === `${issuerA}/.well-known/uma2-configuration`) {
        return new Response(
          JSON.stringify({ token_endpoint: `${issuerA}/token`, issuer: issuerA }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuerB}/.well-known/uma2-configuration`) {
        return new Response(
          JSON.stringify({ token_endpoint: `${issuerB}/token`, issuer: issuerB }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuerA}/token`) {
        return new Response(
          JSON.stringify({ access_token: 'access-A', token_type: 'Bearer' }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuerB}/token`) {
        return new Response(
          JSON.stringify({ access_token: 'access-B', token_type: 'Bearer' }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      const resourceServerCalls = calls.filter(
        (call): boolean => call.url === resourceServer,
      );
      if (resourceServerCalls.length === 1) {
        return new Response(
          JSON.stringify({
            error: 'need_info',
            required_claims: requiredClaims,
            ticket: 't2',
          }),
          { status: 403, headers: { 'content-type': 'application/json' }},
        );
      }

      if (resourceServerCalls.length === 2) {
        return new Response(
          JSON.stringify({
            error: 'need_info',
            required_claims: requiredClaims,
            ticket: 't3',
          }),
          { status: 403, headers: { 'content-type': 'application/json' }},
        );
      }

      return new Response(
        JSON.stringify({ access_token: 'access-final', token_type: 'Bearer' }),
        { status: 200, headers: { 'content-type': 'application/json' }},
      );
    }

    const auth = makeAuth(fetchMock, createDefaultClaimResolvers());

    const result = await fetchAccessToken(auth, resourceServer, 't1');

    expect(result).toEqual({ access_token: 'access-final', token_type: 'Bearer' });

    const resourceServerCalls = calls.filter(
      (call): boolean => call.url === resourceServer,
    );
    expect(resourceServerCalls).toHaveLength(3);
    expect(resourceServerCalls[1].body).toMatchObject({
      ticket: 't2',
      claim_token: 'access-A',
      claim_token_format: ACCESS_TOKEN_FORMAT,
    });
    expect(resourceServerCalls[2].body).toMatchObject({
      ticket: 't3',
      claim_token: 'access-B',
      claim_token_format: ACCESS_TOKEN_FORMAT,
    });
  });

  it('requests access for all grouped derived resources when their token request is denied', async(): Promise<void> => {
    const DERIVATION_ACCESS = 'https://w3id.org/aggregator#derivation-access';
    const resourceServer = 'https://rs.example/token';
    const issuer = 'https://as.example';
    const requestingParty = 'https://user.example/#me';
    const requiredClaims = [
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/a',
        resource_scopes: [ 'read' ],
      },
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/b',
        resource_scopes: [ 'write' ],
      },
    ];

    const calls: { url: string; body: string }[] = [];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = requestUrl(input);
      const body = typeof init?.body === 'string' ? init.body : '';
      calls.push({ url, body });

      if (url === `${issuer}/.well-known/uma2-configuration`) {
        return new Response(
          JSON.stringify({ token_endpoint: `${issuer}/token`, issuer }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/token`) {
        return new Response(
          JSON.stringify({ error: 'access_denied', ticket: 'request-ticket' }),
          { status: 403, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/requests`) {
        return new Response('', { status: 202 });
      }

      return new Response(
        JSON.stringify({
          error: 'need_info',
          required_claims: requiredClaims,
          ticket: 't2',
        }),
        { status: 403, headers: { 'content-type': 'application/json' }},
      );
    }

    const auth = makeAuth(fetchMock, createDefaultClaimResolvers());
    auth.webId = requestingParty;
    auth.oidcAccessToken = 'oidc-access-token';

    let caught: unknown;
    try {
      await fetchAccessToken(auth, resourceServer, 't1', {
        accessRequest: true,
        requestingParty,
      });
    } catch (error: unknown) {
      caught = error;
    }
    expect(caught).toMatchObject({ status: 403 });
    expect((caught as { accessRequestResponse?: Response }).accessRequestResponse?.status)
      .toBe(202);

    const requestCalls = calls.filter(
      (call): boolean => call.url === `${issuer}/requests`,
    );
    expect(requestCalls).toHaveLength(1);
    expect(JSON.parse(requestCalls[0].body)).toEqual({ ticket: 'request-ticket' });
  });

  it('requests access for permissions missing from a derived JWT access token', async(): Promise<void> => {
    const DERIVATION_ACCESS = 'https://w3id.org/aggregator#derivation-access';
    const resourceServer = 'https://rs.example/token';
    const issuer = 'https://as.example';
    const requestingParty = 'https://user.example/#me';
    const requiredClaims = [
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/a',
        resource_scopes: [ 'read' ],
      },
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/b',
        resource_scopes: [ 'urn:example:css:modes:read' ],
      },
    ];

    const calls: { url: string; body: string }[] = [];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = requestUrl(input);
      const body = typeof init?.body === 'string' ? init.body : '';
      calls.push({ url, body });
      const payload = body ? JSON.parse(body) as Record<string, unknown> : {};

      if (url === `${issuer}/.well-known/uma2-configuration`) {
        return new Response(
          JSON.stringify({ token_endpoint: `${issuer}/token`, issuer }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/token`) {
        const requestedPermissions = payload.permissions;
        if (
          Array.isArray(requestedPermissions) &&
          requestedPermissions.length === 1 &&
          (requestedPermissions[0] as PermissionDescription).resource_id ===
          'https://data.example/b'
        ) {
          return new Response(
            JSON.stringify({ error: 'access_denied', ticket: 'missing-permissions-ticket' }),
            { status: 403, headers: { 'content-type': 'application/json' }},
          );
        }
        return new Response(
          JSON.stringify({
            access_token: jwt({
              permissions: [
                {
                  resource_id: 'https://data.example/a',
                  resource_scopes: [ 'read' ],
                },
              ],
            }),
            token_type: 'Bearer',
            ticket: 'missing-permissions-ticket',
          }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/requests`) {
        return new Response('', { status: 202 });
      }

      return new Response(
        JSON.stringify({
          error: 'need_info',
          required_claims: requiredClaims,
          ticket: 't2',
        }),
        { status: 403, headers: { 'content-type': 'application/json' }},
      );
    }

    const auth = makeAuth(fetchMock, createDefaultClaimResolvers());
    auth.webId = requestingParty;
    auth.oidcAccessToken = 'oidc-access-token';

    await expect(
      fetchAccessToken(auth, resourceServer, 't1', {
        accessRequest: true,
        requestingParty,
      }),
    ).rejects.toMatchObject({ status: 403 });

    const requestCalls = calls.filter(
      (call): boolean => call.url === `${issuer}/requests`,
    );
    expect(requestCalls).toHaveLength(1);
    expect(JSON.parse(requestCalls[0].body)).toEqual({
      ticket: 'missing-permissions-ticket',
    });

    const singlePermissionCalls = calls.filter((call): boolean => {
      if (call.url !== `${issuer}/token`) {
        return false;
      }
      const body = JSON.parse(call.body) as { permissions?: unknown[] };
      return body.permissions?.length === 1;
    });
    expect(singlePermissionCalls).toHaveLength(1);
  });

  it('requests access for multiple permissions missing from a derived JWT access token', async(): Promise<void> => {
    const DERIVATION_ACCESS = 'https://w3id.org/aggregator#derivation-access';
    const resourceServer = 'https://rs.example/token';
    const issuer = 'https://as.example';
    const requiredClaims = [
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/a',
        resource_scopes: [ 'read' ],
      },
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/b',
        resource_scopes: [ 'read' ],
      },
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/c',
        resource_scopes: [ 'read' ],
      },
    ];
    const calls: { url: string; body: string }[] = [];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = requestUrl(input);
      const body = typeof init?.body === 'string' ? init.body : '';
      calls.push({ url, body });
      const payload = body ? JSON.parse(body) as { permissions?: PermissionDescription[] } : {};

      if (url === `${issuer}/.well-known/uma2-configuration`) {
        return new Response(
          JSON.stringify({ token_endpoint: `${issuer}/token`, issuer }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/token`) {
        const [ permission ] = payload.permissions ?? [];
        if (payload.permissions?.length === 1 && permission) {
          const suffix = permission.resource_id.endsWith('/b') ? 'b' : 'c';
          return new Response(
            JSON.stringify({ error: 'access_denied', ticket: `ticket-${suffix}` }),
            { status: 403, headers: { 'content-type': 'application/json' }},
          );
        }
        return new Response(
          JSON.stringify({
            access_token: jwt({
              permissions: [
                {
                  resource_id: 'https://data.example/a',
                  resource_scopes: [ 'read' ],
                },
              ],
            }),
            token_type: 'Bearer',
          }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/requests`) {
        return new Response('', { status: 202 });
      }

      return new Response(
        JSON.stringify({
          error: 'need_info',
          required_claims: requiredClaims,
          ticket: 't2',
        }),
        { status: 403, headers: { 'content-type': 'application/json' }},
      );
    }

    const auth = makeAuth(fetchMock, createDefaultClaimResolvers());
    auth.oidcAccessToken = 'oidc-access-token';

    await expect(
      fetchAccessToken(auth, resourceServer, 't1', { accessRequest: true }),
    ).rejects.toMatchObject({ status: 403 });

    const requestBodies = calls
      .filter((call): boolean => call.url === `${issuer}/requests`)
      .map((call): unknown => JSON.parse(call.body));
    expect(requestBodies).toEqual([
      { ticket: 'ticket-b' },
      { ticket: 'ticket-c' },
    ]);

    const singlePermissionCalls = calls.filter((call): boolean => {
      if (call.url !== `${issuer}/token`) {
        return false;
      }
      const body = JSON.parse(call.body) as { permissions?: unknown[] };
      return body.permissions?.length === 1;
    });
    expect(singlePermissionCalls).toHaveLength(2);
  });

  it('does not request access when the derived JWT covers all requested permissions', async(): Promise<void> => {
    const DERIVATION_ACCESS = 'https://w3id.org/aggregator#derivation-access';
    const resourceServer = 'https://rs.example/token';
    const issuer = 'https://as.example';
    const requiredClaims = [
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/a',
        resource_scopes: [ 'read' ],
      },
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/b',
        resource_scopes: [ 'write' ],
      },
    ];
    const calls: { url: string; body: string }[] = [];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = requestUrl(input);
      const body = typeof init?.body === 'string' ? init.body : '';
      calls.push({ url, body });

      if (url === `${issuer}/.well-known/uma2-configuration`) {
        return new Response(
          JSON.stringify({ token_endpoint: `${issuer}/token`, issuer }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/token`) {
        return new Response(
          JSON.stringify({
            access_token: jwt({
              permissions: [
                {
                  resource_id: 'https://data.example/a',
                  resource_scopes: [ 'read' ],
                },
                {
                  resource_id: 'https://data.example/b',
                  resource_scopes: [ 'write' ],
                },
              ],
            }),
            token_type: 'Bearer',
          }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/requests`) {
        throw new Error('Unexpected access request.');
      }

      const payload = body ? JSON.parse(body) as Record<string, unknown> : {};
      if (payload.claim_token_format === 'urn:ietf:params:oauth:token-type:access_token') {
        return new Response(
          JSON.stringify({ access_token: 'final-access', token_type: 'Bearer' }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      return new Response(
        JSON.stringify({
          error: 'need_info',
          required_claims: requiredClaims,
          ticket: 't2',
        }),
        { status: 403, headers: { 'content-type': 'application/json' }},
      );
    }

    const auth = makeAuth(fetchMock, createDefaultClaimResolvers());
    auth.oidcAccessToken = 'oidc-access-token';

    const result = await fetchAccessToken(auth, resourceServer, 't1', {
      accessRequest: true,
    });

    expect(result).toEqual({ access_token: 'final-access', token_type: 'Bearer' });
    expect(calls.some((call): boolean => call.url === `${issuer}/requests`))
      .toBe(false);
  });

  it('errors when a missing derived permission denial has no ticket', async(): Promise<void> => {
    const DERIVATION_ACCESS = 'https://w3id.org/aggregator#derivation-access';
    const resourceServer = 'https://rs.example/token';
    const issuer = 'https://as.example';
    const requiredClaims = [
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/a',
        resource_scopes: [ 'read' ],
      },
      {
        claim_type: DERIVATION_ACCESS,
        issuer,
        derivation_resource_id: 'https://data.example/b',
        resource_scopes: [ 'read' ],
      },
    ];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = requestUrl(input);
      const body = typeof init?.body === 'string' ? init.body : '';
      const payload = body ? JSON.parse(body) as { permissions?: PermissionDescription[] } : {};

      if (url === `${issuer}/.well-known/uma2-configuration`) {
        return new Response(
          JSON.stringify({ token_endpoint: `${issuer}/token`, issuer }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/token`) {
        if (payload.permissions?.length === 1) {
          return new Response(
            JSON.stringify({ error: 'access_denied' }),
            { status: 403, headers: { 'content-type': 'application/json' }},
          );
        }
        return new Response(
          JSON.stringify({
            access_token: jwt({
              permissions: [
                {
                  resource_id: 'https://data.example/a',
                  resource_scopes: [ 'read' ],
                },
              ],
            }),
            token_type: 'Bearer',
          }),
          { status: 200, headers: { 'content-type': 'application/json' }},
        );
      }

      if (url === `${issuer}/requests`) {
        throw new Error('Unexpected access request.');
      }

      return new Response(
        JSON.stringify({
          error: 'need_info',
          required_claims: requiredClaims,
          ticket: 't2',
        }),
        { status: 403, headers: { 'content-type': 'application/json' }},
      );
    }

    const auth = makeAuth(fetchMock, createDefaultClaimResolvers());
    auth.oidcAccessToken = 'oidc-access-token';

    await expect(
      fetchAccessToken(auth, resourceServer, 't1', { accessRequest: true }),
    ).rejects.toThrow(/without a derived resource denial ticket/u);
  });

  // Extensibility: an external (custom) resolver that matches several distinct
  // required claims must resolve them one at a time without colliding, even
  // when they only differ by a custom field the package knows nothing about.
  it('resolves multiple distinct claims from an external resolver one at a time', async(): Promise<void> => {
    const calls: { body: Record<string, unknown> }[] = [];

    const requiredClaims = [
      { claim_type: 'custom-claim', resource: 'alpha' },
      { claim_type: 'custom-claim', resource: 'beta' },
    ];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const body: Record<string, unknown> = init?.body ?
          (JSON.parse(init.body as string) as Record<string, unknown>) :
          {};
      calls.push({ body });

      if (calls.length < 3) {
        return new Response(
          JSON.stringify({
            error: 'need_info',
            required_claims: requiredClaims,
            ticket: `t${calls.length + 1}`,
          }),
          { status: 403, headers: { 'content-type': 'application/json' }},
        );
      }

      return new Response(
        JSON.stringify({ access_token: 'access-final', token_type: 'Bearer' }),
        { status: 200, headers: { 'content-type': 'application/json' }},
      );
    };

    const resolvers: ClaimResolverDefinition[] = [
      {
        id: 'custom',
        match: { claim_type: 'custom-claim' },
        resolve: (required): Claim => ({
          claim_token: `custom-${String(
            (required as Record<string, unknown>).resource,
          )}`,
          claim_token_format: 'urn:example:custom',
        }),
      },
    ];

    const auth = makeAuth(fetchMock, resolvers);

    const result = await fetchAccessToken(auth, 'https://rs.example/token', 't1');

    expect(result).toEqual({ access_token: 'access-final', token_type: 'Bearer' });

    // Each distinct custom claim is pushed on its own round trip.
    expect(calls).toHaveLength(3);
    expect(calls[1].body).toMatchObject({ claim_token: 'custom-alpha' });
    expect(calls[2].body).toMatchObject({ claim_token: 'custom-beta' });
  });

  // Extensibility: an external resolver can opt in to combining related claims
  // by providing `groupBy` and `resolveGroup`, exactly like the built-in
  // access-token resolver does.
  it('lets an external resolver combine related claims via groupBy/resolveGroup', async(): Promise<void> => {
    const calls: { body: Record<string, unknown> }[] = [];

    const requiredClaims = [
      { claim_type: 'custom-claim', issuer: 'https://issuer.example', resource: 'alpha' },
      { claim_type: 'custom-claim', issuer: 'https://issuer.example', resource: 'beta' },
    ];

    async function fetchMock(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const body: Record<string, unknown> = init?.body ?
          (JSON.parse(init.body as string) as Record<string, unknown>) :
          {};
      calls.push({ body });

      if (calls.length === 1) {
        return new Response(
          JSON.stringify({
            error: 'need_info',
            required_claims: requiredClaims,
            ticket: 't2',
          }),
          { status: 403, headers: { 'content-type': 'application/json' }},
        );
      }

      return new Response(
        JSON.stringify({ access_token: 'access-final', token_type: 'Bearer' }),
        { status: 200, headers: { 'content-type': 'application/json' }},
      );
    };

    const resolvers: ClaimResolverDefinition[] = [
      {
        id: 'custom-group',
        match: { claim_type: 'custom-claim' },
        resolve: (): Claim | undefined => undefined,
        groupBy: (required): string | undefined =>
          required.issuer as string | undefined,
        resolveGroup: (claims): Claim => ({
          claim_token: `custom-${claims
            .map((claim): string => String(
              (claim as Record<string, unknown>).resource,
            ))
            .join('+')}`,
          claim_token_format: 'urn:example:custom',
        }),
      },
    ];

    const auth = makeAuth(fetchMock, resolvers);

    const result = await fetchAccessToken(auth, 'https://rs.example/token', 't1');

    expect(result).toEqual({ access_token: 'access-final', token_type: 'Bearer' });

    // Both claims for the same issuer are combined into a single round trip.
    expect(calls).toHaveLength(2);
    expect(calls[1].body).toMatchObject({ claim_token: 'custom-alpha+beta' });
  });
});
