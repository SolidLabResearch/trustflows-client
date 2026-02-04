/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import type { ClaimResolverDefinition, RequiredClaims } from '../src/uma/claims/types';
import { gatherClaims, resolveClaimResolver } from '../src/uma/claims/registry';
import { ID_TOKEN_CLAIM_FORMAT } from '../src/uma/claims/idToken';
import { MemoryStorage } from './helpers/storage';

async function noopFetch(): Promise<Response> {
  return new Response('', { status: 200 });
}

describe('Auth.addClaimResolver', (): void => {
  it('adds a resolver by format string and resolves it', async(): Promise<void> => {
    const auth = new Auth({ fetch: noopFetch, storage: new MemoryStorage() });
    auth.addClaimResolver('urn:example:custom', async(): Promise<{
      claim_token: string;
      claim_token_format: string;
    }> => ({
      claim_token: 'custom-token',
      claim_token_format: 'urn:example:custom',
    }));

    const required: RequiredClaims = { claim_token_format: 'urn:example:custom' };
    const claims = await gatherClaims([], [ required ], auth, auth.getClaimResolvers());

    expect(claims).toHaveLength(1);
    expect(claims[0]).toMatchObject({
      claim_token: 'custom-token',
      claim_token_format: 'urn:example:custom',
    });
  });

  it('prefers higher priority resolvers over defaults', (): void => {
    const auth = new Auth({ fetch: noopFetch, storage: new MemoryStorage() });
    const custom: ClaimResolverDefinition = {
      id: 'custom-id-token',
      priority: 10,
      match: { claim_token_format: ID_TOKEN_CLAIM_FORMAT },
      resolve: async(): Promise<{ claim_token: string; claim_token_format: string }> => ({
        claim_token: 'override',
        claim_token_format: ID_TOKEN_CLAIM_FORMAT,
      }),
    };

    auth.addClaimResolver(custom);

    const resolver = resolveClaimResolver(
      { claim_token_format: ID_TOKEN_CLAIM_FORMAT },
      auth.getClaimResolvers(),
    );

    expect(resolver?.id).toBe('custom-id-token');
  });
});
