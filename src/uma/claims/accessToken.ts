/* eslint-disable @typescript-eslint/naming-convention */
import { fetchAccessToken } from '../utils';
import type { Auth } from '../../auth';
import type { Claim, PermissionDescription } from '../types';
import type {
  ClaimResolverDefinition,
  RequiredClaims,
} from './types';

export const ACCESS_TOKEN_CLAIM_FORMAT =
  'urn:ietf:params:oauth:token-type:access_token';
export const ACCESS_TOKEN_CLAIM_TYPE =
  'https://w3id.org/aggregator#derivation-access';

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

function matchesAccessTokenValue(
  value: string | string[] | undefined,
  target: string,
): boolean {
  if (!value) {
    return false;
  }
  return Array.isArray(value) ? value.includes(target) : value === target;
}

/**
 * Determines whether a required claim should be satisfied by an access token.
 */
export function isAccessTokenRequiredClaim(required: RequiredClaims): boolean {
  return (
    matchesAccessTokenValue(required.claim_token_format, ACCESS_TOKEN_CLAIM_FORMAT) ||
    matchesAccessTokenValue(required.claim_type, ACCESS_TOKEN_CLAIM_FORMAT) ||
    matchesAccessTokenValue(required.claim_type, ACCESS_TOKEN_CLAIM_TYPE)
  );
}

/**
 * Returns the single issuer for an access-token required claim, if any.
 * Access-token claims that share an issuer can be combined into one request.
 */
export function accessTokenIssuer(required: RequiredClaims): string | undefined {
  return pickSingle(required.issuer, 'issuer');
}

/**
 * Resolves one or more access-token required claims that share the same issuer
 * into a single claim. All requested permissions are combined into a single
 * token request so the issuer only has to be contacted once.
 */
export async function resolveAccessTokenClaims(
  requiredClaims: RequiredClaims[],
  auth: Auth,
): Promise<Claim> {
  if (requiredClaims.length === 0) {
    throw new Error('No access_token required claims provided to resolve.');
  }

  const issuer = accessTokenIssuer(requiredClaims[0]);
  if (!issuer) {
    throw new Error('UMA access_token claim requires an issuer.');
  }

  const permissions: PermissionDescription[] = requiredClaims.map(
    (required): PermissionDescription => {
      const resourceId = required.derivation_resource_id;
      const resourceScopes = required.resource_scopes;
      if (!resourceId || !resourceScopes || resourceScopes.length === 0) {
        throw new Error(
          'UMA access_token claim requires issuer, resource identifier and scopes.',
        );
      }
      return {
        resource_id: resourceId,
        resource_scopes: resourceScopes,
      };
    },
  );

  // TODO fetch the actual config to discover the token endpoint
  const endpoint = `${issuer.replace(/\/$/u, '')}/token`;
  const tokenResult = await fetchAccessToken(auth, endpoint, permissions);
  return {
    claim_token: tokenResult.access_token,
    claim_token_format: ACCESS_TOKEN_CLAIM_FORMAT,
  };
}

export async function accessTokenClaimResolver(
  required: RequiredClaims,
  auth: Auth,
): Promise<Claim | undefined> {
  return resolveAccessTokenClaims([ required ], auth);
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
    // Combine all access-token permissions for the same issuer into a single
    // token request so the issuer is contacted only once.
    groupBy: accessTokenIssuer,
    resolveGroup: resolveAccessTokenClaims,
  },
];
