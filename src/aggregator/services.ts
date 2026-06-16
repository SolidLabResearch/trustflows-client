/* eslint-disable @typescript-eslint/naming-convention */
import { AggregatorServiceError } from './errors';
import type { AggregatorFetch } from './management';
import {
  type ParsedServiceDescription,
  parseServiceCollection,
  parseServiceDescription,
  RDF_ACCEPT,
  serializeServiceRequest,
} from './rdf';
import type { ServiceRequest } from './types';

const JSONLD = 'application/ld+json';
const JSON_CT = 'application/json';

/**
 * Reads an RDF response body, tolerating two server-side quirks that would
 * otherwise make the parser fail on line 1: a leading UTF-8 BOM, and a document
 * that was mistakenly JSON-encoded (returned as a quoted string).
 */
async function readRdfBody(res: Response): Promise<string> {
  const text = await res.text();
  const withoutBom = text.codePointAt(0) === 0xFEFF ? text.slice(1) : text;
  if (withoutBom.trimStart().startsWith('"')) {
    try {
      const unwrapped: unknown = JSON.parse(withoutBom);
      if (typeof unwrapped === 'string') {
        return unwrapped;
      }
    } catch {
      // Not JSON after all; fall through and let the RDF parser report it.
    }
  }
  return withoutBom;
}

/**
 * The result of fetching the Service Collection.
 */
export interface ServiceCollectionResult {
  services: string[];
  acceptPost?: string;
}

/**
 * Fetches the Service Collection and returns the Service Description URLs it
 * advertises, along with the `Accept-Post` header (supported deploy formats).
 */
export async function fetchServiceCollection(
  authFetch: AggregatorFetch,
  collectionUrl: string,
): Promise<ServiceCollectionResult> {
  const res = await authFetch(collectionUrl, { headers: { accept: RDF_ACCEPT }});
  if (!res.ok) {
    throw new AggregatorServiceError(
      `Failed to fetch service collection (${res.status}).`,
      res.status,
    );
  }
  const acceptPost = res.headers.get('accept-post') ?? undefined;
  const contentType = res.headers.get('content-type') ?? undefined;
  const text = await readRdfBody(res);
  return {
    services: await parseServiceCollection(text, collectionUrl, contentType),
    acceptPost,
  };
}

/**
 * Fetches and parses a single Service Description.
 */
export async function loadServiceDescription(
  authFetch: AggregatorFetch,
  serviceUrl: string,
): Promise<ParsedServiceDescription> {
  const res = await authFetch(serviceUrl, { headers: { accept: RDF_ACCEPT }});
  if (!res.ok) {
    throw new AggregatorServiceError(
      `Failed to fetch service description (${res.status}).`,
      res.status,
    );
  }
  const contentType = res.headers.get('content-type') ?? undefined;
  const text = await readRdfBody(res);
  return parseServiceDescription(text, serviceUrl, contentType);
}

/**
 * Picks the JSON content type to deploy with, honoring `Accept-Post` when it
 * advertises a JSON family, and defaulting to JSON-LD otherwise.
 */
function selectDeployContentType(acceptPost?: string): string {
  const offered = new Set(
    (acceptPost ?? '')
      .split(',')
      .map((entry): string => entry.trim().split(';')[0].toLowerCase()),
  );
  if (offered.has(JSONLD)) {
    return JSONLD;
  }
  if (offered.has(JSON_CT)) {
    return JSON_CT;
  }
  return JSONLD;
}

/**
 * Deploys a new service to the Service Collection and returns the parsed
 * description of the created service.
 */
export async function deployService(
  authFetch: AggregatorFetch,
  collectionUrl: string,
  request: ServiceRequest,
  acceptPost?: string,
): Promise<ParsedServiceDescription> {
  const contentType = selectDeployContentType(acceptPost);
  const body = serializeServiceRequest(request);
  const res = await authFetch(collectionUrl, {
    method: 'POST',
    headers: { 'content-type': contentType, accept: RDF_ACCEPT },
    body,
  });
  if (res.status !== 201) {
    throw new AggregatorServiceError(
      `Failed to deploy service (${res.status}).`,
      res.status,
      await res.text(),
    );
  }

  const location = res.headers.get('location') ?? undefined;
  const resolved = location ? new URL(location, collectionUrl).toString() : undefined;
  const responseType = res.headers.get('content-type') ?? undefined;
  const text = await readRdfBody(res);

  let parsed: ParsedServiceDescription;
  try {
    parsed = await parseServiceDescription(text, resolved ?? collectionUrl, responseType);
  } catch (error: unknown) {
    if (!resolved) {
      throw error;
    }
    parsed = await loadServiceDescription(authFetch, resolved);
  }

  return resolved ? { ...parsed, service: resolved } : parsed;
}

/**
 * Deletes a service by its Service Description URL.
 */
export async function deleteService(
  authFetch: AggregatorFetch,
  serviceUrl: string,
): Promise<void> {
  const res = await authFetch(serviceUrl, { method: 'DELETE' });
  if (res.status !== 204 && res.status !== 200 && !res.ok) {
    throw new AggregatorServiceError(
      `Failed to delete service (${res.status}).`,
      res.status,
    );
  }
}
