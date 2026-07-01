/* eslint-disable @typescript-eslint/naming-convention */
import {
  discoverUmaConfiguration,
  fetchAccessToken,
  requestDerivedResourceAccess,
  TokenRequestError,
} from '../utils';
import type { Auth } from '../../auth';
import type { Claim, PermissionDescription, SuccessfulTokenResponse } from '../types';
import type {
  ClaimResolutionContext,
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
  context: ClaimResolutionContext = {},
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

  const metadata = await discoverUmaConfiguration(issuer, auth.getFetch());
  const endpoint = metadata.token_endpoint;
  if (!endpoint) {
    throw new Error(
      `UMA configuration for issuer "${issuer}" is missing a token_endpoint.`,
    );
  }
  let tokenResult: SuccessfulTokenResponse;
  try {
    tokenResult = await fetchAccessToken(auth, endpoint, permissions, context);
  } catch (error: unknown) {
    if (
      context.accessRequest &&
      error instanceof TokenRequestError &&
      error.status >= 400 &&
      error.status < 500
    ) {
      error.accessRequestResponse = await requestDerivedResourceAccess(
        issuer,
        auth,
        context,
        extractTicket(error.payload),
      );
    }
    throw error;
  }
  const missingPermissions = missingPermissionsFromJwt(
    tokenResult.access_token,
    permissions,
  );
  if (context.accessRequest && missingPermissions && missingPermissions.length > 0) {
    const error = new TokenRequestError(
      'UMA access token is missing requested permissions.',
      403,
      { permissions: missingPermissions },
    );
    error.accessRequestResponse = await requestDerivedResourceAccess(
      issuer,
      auth,
      context,
      extractTicket(tokenResult),
    );
    throw error;
  }
  return {
    claim_token: tokenResult.access_token,
    claim_token_format: ACCESS_TOKEN_CLAIM_FORMAT,
  };
}

interface GrantedPermission {
  resource_id: string;
  resource_scopes: string[];
}

function missingPermissionsFromJwt(
  token: string,
  requested: PermissionDescription[],
): PermissionDescription[] | undefined {
  const payload = decodeJwtPayload(token);
  if (!payload) {
    return undefined;
  }

  const granted = extractGrantedPermissions(payload);
  if (!granted) {
    return undefined;
  }

  return requested.filter(
    (permission): boolean => !permissionGranted(permission, granted),
  );
}

function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  const parts = token.split('.');
  if (parts.length < 2) {
    return undefined;
  }

  try {
    const base64 = parts[1].replaceAll('-', '+').replaceAll('_', '/');
    const padded = base64.padEnd(
      base64.length + ((4 - base64.length % 4) % 4),
      '=',
    );
    const decoded = globalThis.atob(padded);
    const payload = JSON.parse(decoded) as unknown;
    return isRecord(payload) ? payload : undefined;
  } catch {
    return undefined;
  }
}

function extractGrantedPermissions(
  payload: Record<string, unknown>,
): GrantedPermission[] | undefined {
  const candidates = [
    payload.permissions,
    isRecord(payload.authorization) ? payload.authorization.permissions : undefined,
    payload.uma_permissions,
  ];

  const permissions: GrantedPermission[] = [];
  for (const candidate of candidates) {
    if (!Array.isArray(candidate)) {
      continue;
    }
    for (const entry of candidate) {
      const permission = parseGrantedPermission(entry);
      if (permission) {
        permissions.push(permission);
      }
    }
  }

  return permissions.length > 0 ? permissions : undefined;
}

function parseGrantedPermission(value: unknown): GrantedPermission | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const resourceId =
    pickString(value.resource_id) ??
    pickString(value.derivation_resource_id) ??
    pickString(value.resource) ??
    pickString(value.rsid) ??
    pickString(value.rsname);
  const scopes = pickStringArray(value.resource_scopes) ??
    pickStringArray(value.scopes) ??
    splitScopeString(value.scope);

  if (!resourceId || !scopes || scopes.length === 0) {
    return undefined;
  }

  return {
    resource_id: resourceId,
    resource_scopes: scopes,
  };
}

function permissionGranted(
  requested: PermissionDescription,
  granted: GrantedPermission[],
): boolean {
  const requestedScopes = requested.resource_scopes ?? [];
  return granted.some((permission): boolean => {
    if (permission.resource_id !== requested.resource_id) {
      return false;
    }
    const grantedScopes = new Set(permission.resource_scopes);
    return requestedScopes.every((scope): boolean => grantedScopes.has(scope));
  });
}

function pickString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function pickStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const strings: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string') {
      return undefined;
    }
    strings.push(entry);
  }
  return strings;
}

function splitScopeString(value: unknown): string[] | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const scopes = value.split(/\s+/u).filter(Boolean);
  return scopes.length > 0 ? scopes : undefined;
}

function extractTicket(payload: unknown): string | undefined {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }
  const ticket = (payload as { ticket?: unknown }).ticket;
  return typeof ticket === 'string' && ticket ? ticket : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function accessTokenClaimResolver(
  required: RequiredClaims,
  auth: Auth,
  context?: ClaimResolutionContext,
): Promise<Claim | undefined> {
  return resolveAccessTokenClaims([ required ], auth, context);
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
