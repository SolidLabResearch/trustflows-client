/* eslint-disable @typescript-eslint/naming-convention */
import jsonld from 'jsonld';
import { DataFactory, Parser, Store } from 'n3';
import type { Term as RdfTerm } from 'n3';
import type { ServiceInfo, ServiceRequest, Term, TermInput } from './types';

// DataFactory exposes pure factory functions that never rely on `this`.
// eslint-disable-next-line @typescript-eslint/unbound-method
const { namedNode } = DataFactory;

export const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
export const AGGR = 'https://w3id.org/aggregator#';
export const FNO = 'https://w3id.org/function/ontology#';
export const FNOC = 'https://fno.io/vocabulary/composition/0.1.0/';
export const DCAT = 'http://www.w3.org/ns/dcat#';

const RDF_FIRST = `${RDF}first`;
const RDF_REST = `${RDF}rest`;
const RDF_NIL = `${RDF}nil`;

const JSON_LD_MEDIA_TYPE = 'application/ld+json';

/**
 * RDF media types the `n3` parser can read. Passed straight through as its
 * `format` option (which matches on the media type sub-string).
 */
const N3_MEDIA_TYPES = new Set([
  'text/turtle',
  'application/trig',
  'application/n-triples',
  'application/n-quads',
  'text/n3',
]);

/**
 * `Accept` header advertising every RDF serialization this module can parse,
 * ordered by preference, so RDF endpoints can perform HTTP content negotiation
 * ([[RFC9110]]) instead of being forced into a single format.
 */
export const RDF_ACCEPT =
  `${JSON_LD_MEDIA_TYPE},text/turtle;q=0.9,application/trig;q=0.8,` +
  'application/n-quads;q=0.8,application/n-triples;q=0.8';

function mediaType(contentType?: string): string | undefined {
  const type = contentType?.split(';')[0].trim().toLowerCase();
  if (!type) {
    return undefined;
  }
  return type;
}

function isJsonLdMediaType(type: string): boolean {
  return type === JSON_LD_MEDIA_TYPE || type === 'application/json' || type.endsWith('+json');
}

/**
 * A parsed Aggregator Service Description.
 */
export interface ParsedServiceDescription {
  service: string;
  performs?: string;
  applies?: string;
  implementation?: string;
  bindings: { parameter: string; term: Term }[];
  outputs: Record<string, string[]>;
  provenanceLog?: string;
}

/**
 * Normalizes a {@link TermInput} into a {@link Term}. Strings become literals.
 */
export function normalizeTerm(input: TermInput): Term {
  if (typeof input === 'string') {
    return { value: input, type: 'literal' };
  }
  return { type: 'literal', ...input };
}

function termToJsonLd(term: Term): unknown {
  if (term.type === 'iri') {
    return { '@id': term.value };
  }
  if (term.datatype) {
    return { '@value': term.value, '@type': term.datatype };
  }
  if (term.language) {
    return { '@value': term.value, '@language': term.language };
  }
  return term.value;
}

function rdfToTerm(term: RdfTerm): Term {
  if (term.termType === 'NamedNode') {
    return { value: term.value, type: 'iri' };
  }
  const datatype = 'datatype' in term ? term.datatype?.value : undefined;
  const language = 'language' in term ? term.language : undefined;
  return {
    value: term.value,
    type: 'literal',
    ...datatype && datatype !== `${RDF}langString` &&
    datatype !== 'http://www.w3.org/2001/XMLSchema#string' ?
        { datatype } :
        {},
    ...language ? { language } : {},
  };
}

/**
 * Serializes a {@link ServiceRequest} into a JSON-LD document describing a
 * single requested `aggr:Service`.
 */
export function serializeServiceRequest(request: ServiceRequest): string {
  const service: Record<string, unknown> = {
    '@context': { aggr: AGGR, fno: FNO, fnoc: FNOC },
    '@type': 'aggr:Service',
    'aggr:performs': { '@id': request.transformation },
  };
  if (request.implementation) {
    service['aggr:implements'] = { '@id': request.implementation };
  }

  const entries = Object.entries(request.parameters ?? {});
  if (entries.length > 0) {
    service['aggr:applies'] = {
      '@type': 'fno:AppliedFunction',
      'fnoc:applies': { '@id': request.transformation },
      'fnoc:parameterBindings': {
        '@list': entries.map(([ parameter, termInput ]): unknown => ({
          'fnoc:boundParameter': { '@id': parameter },
          'fnoc:boundToTerm': termToJsonLd(normalizeTerm(termInput)),
        })),
      },
    };
  }

  return JSON.stringify(service);
}

/**
 * Parses an RDF document into a queryable {@link Store}, selecting the parser
 * from the response `Content-Type` when it names a known RDF media type. When
 * the type is absent or unrecognized it falls back to sniffing the body (a
 * leading `{`/`[` is treated as JSON-LD, everything else as Turtle-family RDF).
 */
async function parse(text: string, baseIRI?: string, contentType?: string): Promise<Store> {
  const type = mediaType(contentType);
  const trimmed = text.trimStart();
  const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[');

  let useJsonLd: boolean;
  if (type && isJsonLdMediaType(type)) {
    useJsonLd = true;
  } else if (type && N3_MEDIA_TYPES.has(type)) {
    useJsonLd = false;
  } else {
    useJsonLd = looksJson;
  }

  if (useJsonLd) {
    const document = JSON.parse(trimmed) as jsonld.JsonLdDocument;
    const nquads = await jsonld.toRDF(document, {
      format: 'application/n-quads',
      ...baseIRI ? { base: baseIRI } : {},
    }) as unknown as string;
    return new Store(new Parser({ format: 'application/n-quads' }).parse(nquads));
  }

  const format = type && N3_MEDIA_TYPES.has(type) ? type : undefined;
  return new Store(new Parser({
    ...baseIRI ? { baseIRI } : {},
    ...format ? { format } : {},
  }).parse(text));
}

function readList(store: Store, head: RdfTerm): RdfTerm[] {
  const result: RdfTerm[] = [];
  let node: RdfTerm | undefined = head;
  while (node && node.value !== RDF_NIL) {
    const first = store.getObjects(node, namedNode(RDF_FIRST), null)[0];
    if (first) {
      result.push(first);
    }
    node = store.getObjects(node, namedNode(RDF_REST), null)[0];
  }
  return result;
}

/**
 * Extracts the Service Description Endpoint URLs from an `aggr:ServiceCollection`.
 */
export async function parseServiceCollection(
  text: string,
  baseIRI?: string,
  contentType?: string,
): Promise<string[]> {
  const store = await parse(text, baseIRI, contentType);
  return store
    .getObjects(null, namedNode(`${AGGR}hasService`), null)
    .map((term): string => term.value);
}

/**
 * Parses an Aggregator Service Description, extracting the applied
 * transformation, its parameter bindings, the output access URLs, and the
 * provenance log URL.
 */
export async function parseServiceDescription(
  text: string,
  baseIRI?: string,
  contentType?: string,
): Promise<ParsedServiceDescription> {
  const store = await parse(text, baseIRI, contentType);
  const service =
    store.getSubjects(namedNode(`${RDF}type`), namedNode(`${AGGR}Service`), null)[0];
  if (!service) {
    throw new Error('Service description does not contain an aggr:Service.');
  }

  const performs = store.getObjects(service, namedNode(`${AGGR}performs`), null)[0];
  const implementation = store.getObjects(service, namedNode(`${AGGR}implements`), null)[0];

  const applied = store.getObjects(service, namedNode(`${AGGR}applies`), null)[0];
  let applies: string | undefined;
  const bindings: { parameter: string; term: Term }[] = [];
  if (applied) {
    applies = store.getObjects(applied, namedNode(`${FNOC}applies`), null)[0]?.value;
    const listHead = store.getObjects(applied, namedNode(`${FNOC}parameterBindings`), null)[0];
    if (listHead) {
      for (const node of readList(store, listHead)) {
        const parameter = store.getObjects(node, namedNode(`${FNOC}boundParameter`), null)[0];
        const termValue = store.getObjects(node, namedNode(`${FNOC}boundToTerm`), null)[0];
        if (parameter && termValue) {
          bindings.push({ parameter: parameter.value, term: rdfToTerm(termValue) });
        }
      }
    }
  }

  const outputs: Record<string, string[]> = {};
  for (const dataset of store.getObjects(service, namedNode(`${DCAT}servesDataset`), null)) {
    const output = store.getObjects(dataset, namedNode(`${AGGR}forOutput`), null)[0];
    if (!output) {
      continue;
    }
    const urls = new Set(outputs[output.value] ?? []);
    for (const distribution of store.getObjects(dataset, namedNode(`${DCAT}distribution`), null)) {
      for (const accessUrl of store.getObjects(distribution, namedNode(`${DCAT}accessURL`), null)) {
        urls.add(accessUrl.value);
      }
    }
    outputs[output.value] = [ ...urls ];
  }

  const provenanceLog = store.getObjects(service, namedNode(`${AGGR}provenanceLog`), null)[0];

  return {
    service: service.value,
    performs: performs?.value,
    applies,
    implementation: implementation?.value,
    bindings,
    outputs,
    provenanceLog: provenanceLog?.value,
  };
}

/**
 * Builds a {@link ServiceInfo} from a parsed service description.
 */
export function toServiceInfo(parsed: ParsedServiceDescription): ServiceInfo {
  return {
    service: parsed.service,
    outputs: parsed.outputs,
    ...parsed.provenanceLog ? { provenanceLog: parsed.provenanceLog } : {},
  };
}

function canonicalTerm(term: Term): string {
  const normalized = normalizeTerm(term);
  return JSON.stringify([
    normalized.type ?? 'literal',
    normalized.value,
    normalized.datatype ?? '',
    normalized.language ?? '',
  ]);
}

/**
 * Computes a stable, order-independent key for a service request so equivalent
 * requests map to the same cache entry and match the same deployed service.
 */
export function serviceRequestKey(request: ServiceRequest): string {
  const bindings = Object.entries(request.parameters ?? {})
    .map(([ parameter, termInput ]): string =>
      `${parameter}=${canonicalTerm(normalizeTerm(termInput))}`)
    .sort((a, b): number => a.localeCompare(b));
  return JSON.stringify({
    transformation: request.transformation,
    implementation: request.implementation ?? '',
    bindings,
  });
}

/**
 * Determines whether a parsed service description satisfies a service request:
 * same transformation, same implementation (if requested), and the same set of
 * parameter bindings.
 */
export function serviceMatchesRequest(
  parsed: ParsedServiceDescription,
  request: ServiceRequest,
): boolean {
  const transformationMatches =
    parsed.applies === request.transformation ||
    parsed.performs === request.transformation;
  if (!transformationMatches) {
    return false;
  }
  if (request.implementation && parsed.implementation !== request.implementation) {
    return false;
  }

  const requested = Object.entries(request.parameters ?? {})
    .map(([ parameter, termInput ]): string =>
      `${parameter}=${canonicalTerm(normalizeTerm(termInput))}`)
    .sort((a, b): number => a.localeCompare(b));
  const found = parsed.bindings
    .map((binding): string => `${binding.parameter}=${canonicalTerm(binding.term)}`)
    .sort((a, b): number => a.localeCompare(b));

  return requested.length === found.length &&
    requested.every((value, index): boolean => value === found[index]);
}
