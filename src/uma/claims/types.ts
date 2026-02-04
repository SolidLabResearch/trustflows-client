/* eslint-disable @typescript-eslint/naming-convention */
import type { Auth } from '../../auth';
import type { JsonObject } from '../../types';
import type { Claim } from '../types';

/**
 * An UMA Required Claim object.
 */
export interface RequiredClaims extends JsonObject {
  /**
   * A URI(s) that identifies the claim token format.
   */
  claim_token_format?: string | string[];

  /**
   * A URI(s) that identifies the type of claim.
   */
  claim_type?: string | string[];

  /**
   * The issuer(s) the claim needs to come from.
   */
  issuer?: string | string[];

  /**
   * The name of the claim request.
   */
  name?: string;

  /**
   * A human-friendly name for the claim.
   */
  friendly_name?: string;
}

/**
 * Resolves a required claim into a claim token.
 */
export type ClaimResolver = (
  required: RequiredClaims,
  auth: Auth,
) => Promise<Claim | undefined> | Claim | undefined;

export type ClaimField =
  | 'claim_token_format' |
  'claim_type' |
  'issuer' |
  'name' |
  'friendly_name';
export type ClaimFieldMatcher = string | string[];
export type ClaimMatcher = Partial<Record<ClaimField, ClaimFieldMatcher>>;
export type ClaimResolverMatch = ClaimMatcher | ClaimMatcher[];

/**
 * A claim resolver definition that can be registered with the registry.
 */
export interface ClaimResolverDefinition {
  /**
   * Resolver identifier.
   */
  id: string;

  /**
   * Declarative matchers for required claim fields.
   */
  match?: ClaimResolverMatch;

  /**
   * Resolver priority (higher wins).
   */
  priority?: number;

  /**
   * Resolver implementation.
   */
  resolve: ClaimResolver;
}

export type ClaimResolverRegistry = ClaimResolverDefinition[];
