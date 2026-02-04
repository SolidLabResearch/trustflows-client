/* eslint-disable @typescript-eslint/naming-convention */
import type { JsonObject } from '../types';
import type { RequiredClaims } from './claims/types';

/**
 * The WWW-Authenticate challenge for UMA authorization.
 */
export interface AuthorizationChallenge extends JsonObject {
  /**
   * The scheme, which is always "UMA".
   */
  scheme: 'UMA';

  /**
   * The authorization server URI.
   */
  as_uri: string;

  /**
   * The ticket issued by the authorization server.
   */
  ticket: string;
}

/**
 * The .well-known UMA authorization server metadata.
 */
export interface AuthorizationServerMetadata extends JsonObject {
  /**
   * The UMA profiles supported by the authorization server.
   */
  uma_profiles_supported: string[];

  /**
   * Whether the authorization server supports client ID metadata documents.
   */
  client_id_metadata_document_supported: true;

  /**
   * The issuer identifier for the authorization server.
   */
  issuer: string;

  /**
   * The resource registration endpoint URL.
   */
  resource_registration_endpoint: string;

  /**
   * The permission endpoint URL.
   */
  permission_endpoint: string;

  /**
   * The token endpoint URL.
   */
  token_endpoint: string;

  /**
   * The introspection endpoint URL.
   */
  introspection_endpoint: string;

  /**
   * The claim interaction endpoint URL.
   */
  claims_interaction_endpoint?: string;

  /**
   * The JWKS URI for the authorization server.
   */
  jwks_uri?: string;
}

/**
 * The UMA token request payload.
 */
export interface TokenRequest extends Claim, JsonObject {
  /**
   * The grant type, which is always "urn:ietf:params:oauth:grant-type:uma-ticket".
   */
  grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket';

  /**
   * The ticket issued by the authorization server.
   * Either this or permissions must be provided.
   */
  ticket?: string;

  /**
   * The permissions being requested.
   * Either this or ticket must be provided.
   */
  permissions?: PermissionDescription | PermissionDescription[];

  /**
   * An optional global scope.
   */
  scope?: string;
}

/**
 * UMA claim.
 */
export interface Claim {
  /**
   * A claim token to satisfy required claims.
   */
  claim_token?: string;

  /**
   * The format of the claim token.
   */
  claim_token_format?: string;
}

/**
 * A UMA permission description.
 */
export interface PermissionDescription {
  /**
   * The resource ID for the permission.
   */
  resource_id: string;

  /**
   * The scopes associated with the permission.
   */
  resource_scopes?: string[];
}

/**
 * A UMA need_info response indicating additional claims are required.
 */
export interface FailedTokenResponse extends JsonObject {
  /**
   * The error code.
   */
  error: 'need_info';

  /**
   * The error description.
   */
  error_description?: string;

  /**
   * The URI reference of a web page with human-readable information about the error.
   */
  error_uri?: string;

  /**
   * If a state parameter was present in the request that triggered the error.
   */
  state?: string;

  /**
   * The ticket issued by the authorization server.
   */
  ticket?: string;

  /**
   * The required claims to satisfy the authorization request.
   */
  required_claims?: RequiredClaims[];

  /**
   * The URI to redirect the user to for interactive authorization, if applicable.
   */
  redirect_user?: string;

  /**
   * The minimum amount of time in seconds that the client SHOULD wait between polling requests
   */
  interval?: number;
}

/**
 * The UMA token response.
 */
export interface SuccessfulTokenResponse extends JsonObject {
  /**
   * The access token issued by the authorization server.
   */
  access_token: string;

  /**
   * The type of the token, which is typically "Bearer".
   */
  token_type: string;
}

export type TokenResponse = SuccessfulTokenResponse | FailedTokenResponse;
