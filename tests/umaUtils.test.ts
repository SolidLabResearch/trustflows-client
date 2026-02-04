/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import type { Auth, Claim, ClaimResolverDefinition } from '../src';
import { fetchAccessToken, ID_TOKEN_CLAIM_FORMAT } from '../src';

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
});
