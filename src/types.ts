/* eslint-disable @typescript-eslint/naming-convention */
export type JsonObject = Record<string, unknown>;

/**
 * The dereferencable identifier of a client, which is also the URL where the client's metadata document is served.
 */
export interface ClientMetadata extends JsonObject {
  /**
   * Client identifier URL.
   */
  client_id: string;

  /**
   * Redirect URIs for redirect-based flows.
   */
  redirect_uris?: string[];

  /**
   * JWK Set (inline).
   */
  jwks?: {
    keys: Record<string, unknown>[];
  };

  /**
   * URI pointing to the JWK Set.
   */
  jwks_uri?: string;

  /**
   * Authentication method at the token endpoint.
   * REQUIRED for confidential clients and MUST be "private_key_jwt".
   */
  token_endpoint_auth_method?: 'private_key_jwt';

  /**
   * Declares UMA / A4DS profiles supported by the client.
   */
  uma_profiles_supported?: string[];

  /**
   * Indicates the client can act as an automated requesting party
   * (e.g., Aggregator-style non-interactive access).
   */
  automated?: boolean;
};
