/* eslint-disable @typescript-eslint/naming-convention */
import { fetchAccessToken } from '../utils';
import type { Auth } from '../../auth';
import type { Claim } from '../types';
import type {
  ClaimResolverDefinition,
  RequiredClaims,
} from './types';

export const ACCESS_TOKEN_CLAIM_FORMAT =
  'urn:ietf:params:oauth:token-type:access_token';
export const ACCESS_TOKEN_CLAIM_TYPE =
  'https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#derivation-access';

function pickSingle(
  value: string | string[] | undefined,
  field: string,
): string | undefined {
  if (!value) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    return value;
  }
  if (value.length === 1) {
    return value[0];
  }
  throw new Error(`UMA claim field "${field}" must be a single value.`);
}

export async function accessTokenClaimResolver(
  required: RequiredClaims,
  auth: Auth,
): Promise<Claim | undefined> {
  const issuer = pickSingle(required.issuer, 'issuer');
  const resourceId =
    required.name ?? pickSingle(required.claim_type, 'claim_type');
  if (!issuer || !resourceId) {
    throw new Error(
      'UMA access_token claim requires issuer and resource identifier.',
    );
  }
  const endpoint = `${issuer.replace(/\/$/u, '')}/token`;
  const tokenResult = await fetchAccessToken(auth, endpoint, [
    { resource_id: resourceId },
  ]);
  return {
    claim_token: tokenResult.access_token,
    claim_token_format: ACCESS_TOKEN_CLAIM_FORMAT,
  };
}

export const accessTokenClaimResolvers: ClaimResolverDefinition[] = [
  {
    id: 'access-token',
    match: [
      { claim_token_format: ACCESS_TOKEN_CLAIM_FORMAT },
      { claim_type: ACCESS_TOKEN_CLAIM_FORMAT },
      { claim_type: ACCESS_TOKEN_CLAIM_TYPE },
    ],
    resolve: accessTokenClaimResolver,
  },
];
