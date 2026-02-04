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
import { gatherClaims } from './claims/registry';
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

    let nextRequired: RequiredClaims | undefined;
    let nextKey: string | undefined;
    for (const claim of requiredClaims) {
      const key = buildClaimKey(claim);
      if (!pushedClaimKeys.has(key)) {
        nextRequired = claim;
        nextKey = key;
        break;
      }
    }

    if (!nextRequired || !nextKey) {
      throw new Error(
        `UMA server requested claims that were already pushed: ${JSON.stringify(
          requiredClaims,
        )}`,
      );
    }

    pushedClaimKeys.add(nextKey);

    const resolved = await gatherClaims(
      [],
      [ nextRequired ],
      auth,
      auth.getClaimResolvers(),
    );

    if (resolved.length === 0) {
      throw new Error('No resolver produced a claim for the required claim.');
    }

    const nextClaim = resolved[0];
    if (!nextClaim?.claim_token || !nextClaim.claim_token_format) {
      throw new Error('Resolved claim is missing claim_token or format.');
    }

    pendingClaim = nextClaim;
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

function normalizeClaimValue(
  value: string | string[] | undefined,
): string | string[] | undefined {
  if (!value) {
    return undefined;
  }
  if (Array.isArray(value)) {
    return [ ...value ].sort();
  }
  return value;
}

function buildClaimKey(claim: RequiredClaims): string {
  const entries: [string, string | string[]][] = [];
  const normalized = {
    claim_token_format: normalizeClaimValue(claim.claim_token_format),
    claim_type: normalizeClaimValue(claim.claim_type),
    issuer: normalizeClaimValue(claim.issuer),
    name: claim.name,
    friendly_name: claim.friendly_name,
  };

  for (const [ key, value ] of Object.entries(normalized)) {
    if (value === undefined) {
      continue;
    }
    entries.push([ key, value ]);
  }

  entries.sort(([ a ], [ b ]): number => a.localeCompare(b));
  return JSON.stringify(Object.fromEntries(entries));
}

function seedIdTokenClaims(pushedClaimKeys: Set<string>): void {
  const formats = [ ID_TOKEN_CLAIM_FORMAT, ID_TOKEN_CLAIM_FORMAT_URN ];
  for (const format of formats) {
    pushedClaimKeys.add(buildClaimKey({ claim_token_format: format }));
    pushedClaimKeys.add(buildClaimKey({ claim_type: format }));
  }
}
