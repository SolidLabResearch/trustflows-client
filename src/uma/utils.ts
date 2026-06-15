/* eslint-disable @typescript-eslint/naming-convention */
import type { Auth } from '../auth';
import { joinUrl, mergeHeaders, safeJson } from '../utils';
import type {
  AuthorizationChallenge,
  AuthorizationServerMetadata,
  FailedTokenResponse,
  PermissionDescription,
  SuccessfulTokenResponse,
  TokenRequest,
  Claim as UmaClaimToken,
} from './types';
import type { RequiredClaims } from './claims/types';
import { resolveClaimResolver } from './claims/registry';
import {
  ID_TOKEN_CLAIM_FORMAT,
  ID_TOKEN_CLAIM_FORMAT_URN,
} from './claims/idToken';

export class TokenRequestError extends Error {
  public readonly status: number;
  public readonly payload?: unknown;

  public constructor(message: string, status: number, payload?: unknown) {
    super(message);
    this.name = 'TokenRequestError';
    this.status = status;
    this.payload = payload;
  }
}

export function parseUmaAuthenticateHeader(
  headers: Headers,
): AuthorizationChallenge | null {
  const header = headers.get('WWW-Authenticate');
  if (!header) {
    return null;
  }
  const umaIndex = header.toLowerCase().indexOf('uma');
  if (umaIndex === -1) {
    return null;
  }

  const challengePart = header.slice(umaIndex);
  const schemeMatch = /uma\s+(.+)/iu.exec(challengePart);
  const paramsPart = schemeMatch ? schemeMatch[1] : '';
  const params: Record<string, string> = {};

  const regex = /(\w+)=("[^"]*"|[^\s,]+)/gu;
  let match = regex.exec(paramsPart);
  while (match) {
    const key = match[1];
    const rawValue = match[2];
    const value = rawValue.startsWith('"') ?
        rawValue.slice(1, -1) :
      rawValue;
    params[key] = value;
    match = regex.exec(paramsPart);
  }

  return {
    scheme: 'UMA',
    as_uri: params.as_uri,
    ticket: params.ticket,
  };
}

export async function discoverUmaConfiguration(
  asUri: string,
  fetchFn: typeof fetch = fetch,
): Promise<AuthorizationServerMetadata> {
  const wellKnown = asUri.includes('/.well-known/') ?
    asUri :
      joinUrl(asUri, '.well-known/uma2-configuration');

  const res = await fetchFn(wellKnown, {
    headers: { accept: 'application/json' },
  });

  if (!res.ok) {
    throw new TokenRequestError(
      `Failed to discover UMA metadata (${res.status}).`,
      res.status,
    );
  }

  const data = await safeJson<AuthorizationServerMetadata>(res);
  if (!data) {
    throw new TokenRequestError(
      'UMA metadata response was empty.',
      res.status,
    );
  }
  return data;
}

export async function fetchAccessToken(
  auth: Auth,
  tokenEndpoint: string,
  request: string | PermissionDescription[],
): Promise<SuccessfulTokenResponse> {
  const fetchFn = auth.getFetch();
  const pushedClaimKeys = new Set<string>();
  seedIdTokenClaims(pushedClaimKeys);

  const claimToken = await auth.createClaimToken();
  let pendingClaim: UmaClaimToken | undefined = {
    claim_token: claimToken,
    claim_token_format: ID_TOKEN_CLAIM_FORMAT,
  };

  let currentRequest: string | PermissionDescription[] = request;

  while (true) {
    const payload: TokenRequest = {
      grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
    };

    if (typeof currentRequest === 'string') {
      payload.ticket = currentRequest;
    } else {
      payload.permissions = currentRequest;
    }

    if (pendingClaim) {
      if (!pendingClaim.claim_token || !pendingClaim.claim_token_format) {
        throw new Error('Resolved claim is missing claim_token or format.');
      }
      payload.claim_token = pendingClaim.claim_token;
      payload.claim_token_format = pendingClaim.claim_token_format;
    }

    const response = await fetchFn(tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (response.ok) {
      const data = await safeJson<SuccessfulTokenResponse>(response);
      if (!data) {
        throw new TokenRequestError('UMA token response was empty.', response.status);
      }
      if (!data.access_token || !data.token_type) {
        throw new TokenRequestError(
          'UMA token response missing access_token or token_type.',
          response.status,
          data,
        );
      }
      return data;
    }

    const errorPayload = await safeJson<FailedTokenResponse>(response);
    if (errorPayload?.error !== 'need_info') {
      throw new TokenRequestError(
        `UMA token request failed (${response.status}).`,
        response.status,
        errorPayload,
      );
    }

    const requiredClaims = errorPayload.required_claims ?? [];
    if (requiredClaims.length === 0) {
      throw new TokenRequestError(
        'UMA server requested additional claims but did not specify any.',
        response.status,
        errorPayload,
      );
    }

    const pending = requiredClaims.filter(
      (claim): boolean => !pushedClaimKeys.has(buildClaimKey(claim)),
    );

    if (pending.length === 0) {
      throw new Error(
        `UMA server requested claims that were already pushed: ${JSON.stringify(
          requiredClaims,
        )}`,
      );
    }

    const resolvers = auth.getClaimResolvers();
    const nextRequired = pending[0];
    const resolver = resolveClaimResolver(nextRequired, resolvers);
    if (!resolver) {
      throw new Error(
        `No claim resolver matched required claim: ${JSON.stringify(
          nextRequired,
        )}`,
      );
    }

    let resolvedClaim: UmaClaimToken | undefined;
    const handledClaims: RequiredClaims[] = [];

    const { groupBy, resolveGroup } = resolver;
    if (groupBy && resolveGroup) {
      // The resolver opted in to combining several required claims that it
      // matches and that share the same group key into a single resolution
      // (e.g. all access-token permissions for the same issuer). This stays
      // generic so external resolvers can use it too.
      const groupKey = groupBy(nextRequired);
      const group = pending.filter(
        (claim): boolean =>
          resolveClaimResolver(claim, resolvers) === resolver &&
          groupBy(claim) === groupKey,
      );
      resolvedClaim = await resolveGroup(group, auth);
      handledClaims.push(...group);
    } else {
      resolvedClaim = await resolver.resolve(nextRequired, auth);
      handledClaims.push(nextRequired);
    }

    if (!resolvedClaim?.claim_token || !resolvedClaim.claim_token_format) {
      throw new Error('Resolved claim is missing claim_token or format.');
    }

    for (const claim of handledClaims) {
      pushedClaimKeys.add(buildClaimKey(claim));
    }

    pendingClaim = resolvedClaim;
    if (typeof currentRequest === 'string' && errorPayload.ticket) {
      currentRequest = errorPayload.ticket;
    }
  }
}

export interface UmaFetchOptions {
  auth: Auth;
  challenge: AuthorizationChallenge;
}

export async function fetchWithUma(
  input: RequestInfo | URL,
  init?: RequestInit,
  options?: UmaFetchOptions,
): Promise<Response> {
  if (!options) {
    throw new Error('fetchWithUma requires auth and challenge options.');
  }

  const { auth, challenge } = options;
  if (!challenge.ticket) {
    throw new Error('UMA challenge is missing a ticket.');
  }

  const fetchFn = auth.getFetch();
  const metadata = await discoverUmaConfiguration(challenge.as_uri, fetchFn);
  const tokenEndpoint = metadata.token_endpoint;
  if (!tokenEndpoint) {
    throw new Error('UMA metadata is missing a token_endpoint.');
  }

  const tokenResult = await fetchAccessToken(
    auth,
    tokenEndpoint,
    challenge.ticket,
  );

  const headers = mergeHeaders(init?.headers, {
    Authorization: `${tokenResult.token_type} ${tokenResult.access_token}`,
  });

  return fetchFn(input, {
    ...init,
    headers,
  });
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    // Treat array fields (scopes, issuers, ...) as order-independent sets.
    return `[${value.map(stableStringify).sort().join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([ , entryValue ]): boolean => entryValue !== undefined)
      .map(([ key, entryValue ]): [string, string] =>
        [ key, stableStringify(entryValue) ])
      .sort(([ a ], [ b ]): number => a.localeCompare(b));
    return `{${entries
      .map(([ key, entryValue ]): string => `${JSON.stringify(key)}:${entryValue}`)
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/**
 * Builds a stable, content-based key for a required claim. The key covers every
 * field of the claim (including fields used by external resolvers), so that two
 * genuinely different required claims never collide.
 */
function buildClaimKey(claim: RequiredClaims): string {
  return stableStringify(claim);
}

function seedIdTokenClaims(pushedClaimKeys: Set<string>): void {
  const formats = [ ID_TOKEN_CLAIM_FORMAT, ID_TOKEN_CLAIM_FORMAT_URN ];
  for (const format of formats) {
    pushedClaimKeys.add(buildClaimKey({ claim_token_format: format }));
    pushedClaimKeys.add(buildClaimKey({ claim_type: format }));
  }
}
