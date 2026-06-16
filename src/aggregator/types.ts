/* eslint-disable @typescript-eslint/naming-convention */
import type { Auth } from '../auth';

/**
 * The management flow used to create (and re-authenticate) an Aggregator Instance.
 * `none` and `provision` complete server-side in a single step, while
 * `authorization_code` and `device_code` require user interaction.
 */
export type AggregatorManagementFlow =
  | 'none' |
  'provision' |
  'authorization_code' |
  'device_code';

/**
 * Options for constructing an {@link Aggregator}.
 */
export interface AggregatorOptions {
  /**
   * The Aggregator Server base URL (where the Aggregator Server Description is
   * served).
   */
  serverUrl: string;

  /**
   * The authenticated {@link Auth} instance used for all requests.
   */
  auth: Auth;

  /**
   * The management flow to use when an instance has to be created. Defaults to
   * the first entry of `supported_management_flows` in the Server Description.
   */
  creationFlow?: AggregatorManagementFlow;

  /**
   * The UMA Authorization Server that governs the Aggregator's resources.
   * Required by the interactive (`authorization_code` / `device_code`) creation
   * flows; can also be supplied per call via {@link StartCreationOptions}.
   */
  authorizationServer?: string;

  /**
   * Whether to persist discovered instances and services in `storage` so they
   * can be reused across sessions. Defaults to `true`.
   */
  cache?: boolean;

  /**
   * The storage used for the persistent cache. Defaults to `localStorage`.
   */
  storage?: Storage;
}

/**
 * The Aggregator Server Description document.
 */
export interface AggregatorServerDescription {
  management_endpoint: string;
  supported_management_flows: AggregatorManagementFlow[];
  supported_management_request_formats: string[];
  version: string;
  client_identifier: string;
  transformation_catalog: string;
}

/**
 * The Aggregator Instance Description document (instance metadata).
 */
export interface AggregatorDescription {
  /**
   * The absolute URL identifying the Aggregator Instance (the `@id` of the
   * description, aliased as `aggregator_base_url` in JSON-LD).
   */
  aggregator_base_url?: string;
  created_at: string;
  login_status: boolean;
  token_expiry?: string;
  transformation_catalog: string;
  service_collection_endpoint: string;
}

/**
 * An RDF term used as the bound value of a transformation parameter. A plain
 * string is treated as a literal; use `{ type: 'iri' }` for an IRI term.
 */
export interface Term {
  value: string;
  type?: 'iri' | 'literal';
  datatype?: string;
  language?: string;
}

export type TermInput = Term | string;

/**
 * Describes the service a caller wants, used to find or deploy a service.
 */
export interface ServiceRequest {
  /**
   * The `fno:Function` IRI the service must perform.
   */
  transformation: string;

  /**
   * An optional `fno:Implementation` IRI (`aggr:implements`).
   */
  implementation?: string;

  /**
   * Parameter bindings, keyed by `fno:Parameter` IRI, bound to a term.
   */
  parameters?: Record<string, TermInput>;
}

/**
 * Information about a found or deployed Aggregator Service.
 */
export interface ServiceInfo {
  /**
   * The Service Description Endpoint URL.
   */
  service: string;

  /**
   * Map of `fno:Output` IRI to the `dcat:accessURL`(s) of its distributions.
   * Multiple distributions for the same output are all returned.
   */
  outputs: Record<string, string[]>;

  /**
   * The `aggr:provenanceLog` URL, when the service exposes one.
   */
  provenanceLog?: string;
}

/**
 * Describes what (if anything) a caller must do to finish creating an instance,
 * returned by `Aggregator.startCreation`.
 */
export type AggregatorCreationStep =
  | AggregatorCreationDone |
  AggregatorRedirectChallenge |
  AggregatorDeviceChallenge;

/**
 * The instance was created (or re-authenticated) without further interaction.
 */
export interface AggregatorCreationDone {
  type: 'done';
  aggregator: string;
}

/**
 * The user agent must be redirected to `authorizationUrl` (authorization_code
 * flow). After returning, call `finishCreation`.
 */
export interface AggregatorRedirectChallenge {
  type: 'redirect';
  authorizationUrl: string;
  state: string;
}

/**
 * The user must authorize at `verification_uri` using `user_code` (device_code
 * flow). Then call `finishCreation` to poll for completion.
 */
export interface AggregatorDeviceChallenge {
  type: 'device';
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
  state: string;
}

/**
 * Parameters for `Aggregator.finishCreation`.
 */
export interface FinishCreationParams {
  /**
   * The authorization code (authorization_code flow). When omitted, it is read
   * from the current URL.
   */
  code?: string;

  /**
   * The `state` value echoed back by the IdP / used to poll the device flow.
   * When omitted, it is read from the current URL or the pending flow.
   */
  state?: string;

  /**
   * Abort signal to stop polling (device_code flow).
   */
  signal?: AbortSignal;
}

/**
 * Options for `Aggregator.startCreation`.
 */
export interface StartCreationOptions {
  /**
   * The redirect URI the IdP returns to (required for the authorization_code
   * flow).
   */
  redirectUri?: string;

  /**
   * The OAuth scope requested from the IdP. Defaults to
   * `openid webid offline_access`.
   */
  scope?: string;

  /**
   * The UMA Authorization Server governing the Aggregator's resources. Falls
   * back to the value passed to the {@link Aggregator} constructor.
   */
  authorizationServer?: string;
}
