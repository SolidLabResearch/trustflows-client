/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import type { Claim, ClaimResolverDefinition, RequiredClaims } from '../src';
import { Auth, gatherClaims } from '../src';

describe('gatherClaims', (): void => {
  it('resolves a claim based on optional fields', async(): Promise<void> => {
    const auth = new Auth();
    const resolvers: ClaimResolverDefinition[] = [
      {
        id: 'custom-claim',
        match: { claim_type: 'demo-claim' },
        resolve: async(): Promise<Claim> => ({
          claim_token: 'demo',
          claim_token_format: 'urn:example:demo',
        }),
      },
    ];

    const required: RequiredClaims[] = [{ claim_type: 'demo-claim' }];
    const result = await gatherClaims([], required, auth, resolvers);

    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({
      claim_token: 'demo',
      claim_token_format: 'urn:example:demo',
    });
  });
});
