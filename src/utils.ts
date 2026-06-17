import jsonld from 'jsonld';
import { DataFactory, Parser, Store } from 'n3';

export type FetchLike = typeof fetch;

export function ensureTrailingSlash(url: string): string {
  return url.endsWith('/') ? url : `${url}/`;
}

export function withoutTrailingSlash(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

export function joinUrl(base: string, path: string): string {
  return new URL(path, ensureTrailingSlash(base)).toString();
}

export async function safeJson<T>(res: Response): Promise<T | undefined> {
  const text = await res.text();
  if (!text) {
    return undefined;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}

export function mergeHeaders(
  base?: HeadersInit,
  extra?: HeadersInit,
): HeadersInit | undefined {
  if (!base && !extra) {
    return undefined;
  }
  const headers = new Headers(base);
  if (extra) {
    const extraHeaders = new Headers(extra);
    // eslint-disable-next-line unicorn/no-array-for-each
    extraHeaders.forEach((value, key): void => {
      headers.set(key, value);
    });
  }
  return headers;
}

export function withBearer(token: string, headers?: HeadersInit): HeadersInit {
  const authHeaderKey = 'Authorization';
  return mergeHeaders(headers, { [authHeaderKey]: `Bearer ${token}` }) ?? {
    [authHeaderKey]: `Bearer ${token}`,
  };
}

export function normalizeBaseUrl(url: string): string {
  return withoutTrailingSlash(url.trim());
}

// DataFactory exposes pure factory functions that never rely on `this`.
// eslint-disable-next-line @typescript-eslint/unbound-method
const { namedNode } = DataFactory;

const SOLID_OIDC_ISSUER = 'http://www.w3.org/ns/solid/terms#oidcIssuer';
const JSON_LD_MEDIA_TYPE = 'application/ld+json';
const PROFILE_ACCEPT = `text/turtle,${JSON_LD_MEDIA_TYPE};q=0.9`;

function isJsonLd(text: string, contentType?: string): boolean {
  const type = contentType?.split(';')[0].trim().toLowerCase();
  if (type) {
    return type === JSON_LD_MEDIA_TYPE || type === 'application/json' || type.endsWith('+json');
  }
  const trimmed = text.trimStart();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

/**
 * Parses an RDF document into a queryable `n3` {@link Store}. `n3` reads the
 * Turtle/TriG/N-Triples/N-Quads family directly; JSON-LD (detected from the
 * content type, or a leading `{`/`[`) is first converted to N-Quads.
 */
async function parseRdf(text: string, baseIRI: string, contentType?: string): Promise<Store> {
  if (isJsonLd(text, contentType)) {
    const nquads = (await jsonld.toRDF(JSON.parse(text) as jsonld.JsonLdDocument, {
      format: 'application/n-quads',
      base: baseIRI,
    })) as unknown as string;
    return new Store(new Parser({ format: 'application/n-quads' }).parse(nquads));
  }
  return new Store(new Parser({ baseIRI }).parse(text));
}

/**
 * Discovers a user's Solid-OIDC issuer from their WebID profile's
 * `solid:oidcIssuer`. The profile document (the WebID without its fragment) is
 * fetched and parsed as RDF; any trailing slash on the
 * issuer is removed.
 *
 * @throws If the profile cannot be fetched or declares no `solid:oidcIssuer`.
 */
export async function discoverOidcIssuer(
  fetchFn: FetchLike,
  webId: string,
): Promise<string> {
  const documentUrl = webId.split('#')[0];
  const response = await fetchFn(documentUrl, { headers: { accept: PROFILE_ACCEPT }});
  if (!response.ok) {
    throw new Error(`Failed fetching WebID profile ${documentUrl} (${response.status}).`);
  }

  const store = await parseRdf(
    await response.text(),
    documentUrl,
    response.headers.get('content-type') ?? undefined,
  );
  const issuer =
    store.getObjects(namedNode(webId), namedNode(SOLID_OIDC_ISSUER), null)[0]?.value ??
    store.getObjects(namedNode(documentUrl), namedNode(SOLID_OIDC_ISSUER), null)[0]?.value ??
    store.getObjects(null, namedNode(SOLID_OIDC_ISSUER), null)[0]?.value;
  if (!issuer) {
    throw new Error(`WebID profile ${webId} does not declare a solid:oidcIssuer.`);
  }
  return issuer.replace(/\/$/u, '');
}
