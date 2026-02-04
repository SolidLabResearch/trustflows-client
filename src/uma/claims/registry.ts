import type { Claim } from '../types';
import type { Auth } from '../../auth';
import type {
  ClaimField,
  ClaimFieldMatcher,
  ClaimMatcher,
  ClaimResolverDefinition,
  ClaimResolverMatch,
  ClaimResolverRegistry,
  RequiredClaims,
} from './types';
import { accessTokenClaimResolvers } from './accessToken';
import { idTokenClaimResolvers } from './idToken';

export function createDefaultClaimResolvers(): ClaimResolverRegistry {
  return [ ...idTokenClaimResolvers, ...accessTokenClaimResolvers ];
}

function matchesField(
  value: string | string[] | undefined,
  matcher: ClaimFieldMatcher,
): boolean {
  if (!value) {
    return false;
  }
  const values = Array.isArray(value) ? value : [ value ];
  const matchers = Array.isArray(matcher) ? matcher : [ matcher ];
  return matchers.some((match): boolean => values.includes(match));
}

function evaluateMatcher(
  claim: RequiredClaims,
  matcher: ClaimMatcher,
): { matched: boolean; specificity: number } {
  const keys = Object.keys(matcher) as ClaimField[];
  let specificity = 0;
  for (const key of keys) {
    const fieldMatcher = matcher[key];
    if (!fieldMatcher) {
      continue;
    }
    specificity += 1;
    const value = claim[key];
    if (!matchesField(value, fieldMatcher)) {
      return { matched: false, specificity };
    }
  }

  return { matched: true, specificity };
}

function evaluateMatch(
  claim: RequiredClaims,
  matcher: ClaimResolverMatch | undefined,
): { matched: boolean; specificity: number } {
  if (!matcher) {
    return { matched: true, specificity: 0 };
  }

  const matchers = Array.isArray(matcher) ? matcher : [ matcher ];
  let bestSpecificity = -1;
  for (const entry of matchers) {
    const result = evaluateMatcher(claim, entry);
    if (result.matched && result.specificity > bestSpecificity) {
      bestSpecificity = result.specificity;
    }
  }

  if (bestSpecificity >= 0) {
    return { matched: true, specificity: bestSpecificity };
  }
  return { matched: false, specificity: 0 };
}

export function resolveClaimResolver(
  requiredClaim: RequiredClaims,
  resolvers: ClaimResolverRegistry,
): ClaimResolverDefinition | undefined {
  let best: ClaimResolverDefinition | undefined;
  let bestPriority = Number.NEGATIVE_INFINITY;
  let bestSpecificity = -1;

  for (const resolver of resolvers) {
    const { matched, specificity } = evaluateMatch(
      requiredClaim,
      resolver.match,
    );
    if (!matched) {
      continue;
    }

    const priority = resolver.priority ?? 0;
    if (
      priority > bestPriority ||
      (priority === bestPriority && specificity > bestSpecificity)
    ) {
      best = resolver;
      bestPriority = priority;
      bestSpecificity = specificity;
    }
  }

  return best;
}

export async function gatherClaims(
  existing: Claim[],
  requiredClaims: RequiredClaims[] | undefined,
  auth: Auth,
  resolvers: ClaimResolverRegistry,
): Promise<Claim[]> {
  if (!Array.isArray(requiredClaims) || requiredClaims.length === 0) {
    return existing;
  }

  const claims = [ ...existing ];
  for (const requiredClaim of requiredClaims) {
    const resolver = resolveClaimResolver(requiredClaim, resolvers);
    if (!resolver) {
      throw new Error(
        `No claim resolver matched required claim: ${JSON.stringify(
          requiredClaim,
        )}`,
      );
    }
    const claim = await resolver.resolve(requiredClaim, auth);
    if (claim) {
      claims.push(claim);
    }
  }
  return claims;
}
