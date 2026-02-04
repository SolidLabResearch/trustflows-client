/* eslint-disable @typescript-eslint/naming-convention */
import type { Auth } from '../../auth';
import type { Claim } from '../types';
import type {
  ClaimResolverDefinition,
  RequiredClaims,
} from './types';

export const ID_TOKEN_CLAIM_FORMAT =
  'http://openid.net/specs/openid-connect-core-1_0.html#IDToken';
export const ID_TOKEN_CLAIM_FORMAT_URN =
  'urn:ietf:params:oauth:token-type:id_token';

export async function idTokenClaimResolver(
  required: RequiredClaims,
  auth: Auth,
): Promise<Claim | undefined> {
  void required;
  return {
    claim_token: await auth.createClaimToken(),
    claim_token_format: ID_TOKEN_CLAIM_FORMAT,
  };
}

export const idTokenClaimResolvers: ClaimResolverDefinition[] = [
  {
    id: 'id-token',
    match: [
      {
        claim_token_format: [ ID_TOKEN_CLAIM_FORMAT, ID_TOKEN_CLAIM_FORMAT_URN ],
      },
      { claim_type: [ ID_TOKEN_CLAIM_FORMAT, ID_TOKEN_CLAIM_FORMAT_URN ]},
    ],
    resolve: idTokenClaimResolver,
  },
];
