/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import {
  parseServiceCollection,
  parseServiceDescription,
  RDF_ACCEPT,
  serializeServiceRequest,
  serviceMatchesRequest,
  serviceRequestKey,
  toServiceInfo,
} from '../src/aggregator/rdf';
import type { ServiceRequest } from '../src';

const request: ServiceRequest = {
  transformation: 'https://example.org/transformations#QueryView',
  implementation: 'https://example.org/transformations#QueryViewImpl',
  parameters: {
    'https://example.org/transformations#Query': 'SELECT * WHERE { ?s ?p ?o }',
    'https://example.org/transformations#Sources': {
      value: 'http://example.org/source1',
      type: 'iri',
    },
  },
};

describe('aggregator rdf', (): void => {
  it('round-trips a service request through JSON-LD', async(): Promise<void> => {
    const jsonLd = serializeServiceRequest(request);
    const parsed = await parseServiceDescription(jsonLd);

    expect(parsed.performs).toBe(request.transformation);
    expect(parsed.applies).toBe(request.transformation);
    expect(parsed.implementation).toBe(request.implementation);
    expect(parsed.bindings).toHaveLength(2);
    expect(serviceMatchesRequest(parsed, request)).toBe(true);
  });

  it('does not match when a binding differs', async(): Promise<void> => {
    const jsonLd = serializeServiceRequest(request);
    const parsed = await parseServiceDescription(jsonLd);

    const other: ServiceRequest = {
      ...request,
      parameters: {
        ...request.parameters,
        'https://example.org/transformations#Query': 'SELECT ?s WHERE { ?s ?p ?o }',
      },
    };
    expect(serviceMatchesRequest(parsed, other)).toBe(false);
  });

  it('parses outputs and provenance from a service description', async(): Promise<void> => {
    const turtle = `
@prefix aggr: <https://w3id.org/aggregator#> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .

<https://aggregator.example/agg1/services/s1>
  a aggr:Service ;
  aggr:performs <https://example.org/transformations#view> ;
  aggr:provenanceLog <https://aggregator.example/agg1/services/s1/provenance> ;
  dcat:servesDataset <https://aggregator.example/agg1/services/s1#dataset> .

<https://aggregator.example/agg1/services/s1#dataset>
  a dcat:Dataset ;
  aggr:forOutput <https://example.org/transformations#view-output> ;
  dcat:distribution
    <https://aggregator.example/agg1/services/s1#dist-xml>,
    <https://aggregator.example/agg1/services/s1#dist-json> .

<https://aggregator.example/agg1/services/s1#dist-xml>
  a dcat:Distribution ;
  dcat:accessURL <https://aggregator.example/agg1/services/s1/output> .

<https://aggregator.example/agg1/services/s1#dist-json>
  a dcat:Distribution ;
  dcat:accessURL <https://aggregator.example/agg1/services/s1/output.json> .
`;
    const parsed = await parseServiceDescription(turtle);
    const info = toServiceInfo(parsed);

    expect(info.service).toBe('https://aggregator.example/agg1/services/s1');
    expect(info.provenanceLog).toBe(
      'https://aggregator.example/agg1/services/s1/provenance',
    );
    expect(info.outputs).toEqual({
      'https://example.org/transformations#view-output': [
        'https://aggregator.example/agg1/services/s1/output',
        'https://aggregator.example/agg1/services/s1/output.json',
      ],
    });
  });

  it('extracts service URLs from a JSON-LD service collection', async(): Promise<void> => {
    const collection = JSON.stringify({
      '@context': {
        aggr: 'https://w3id.org/aggregator#',
        hasService: { '@id': 'aggr:hasService', '@type': '@id' },
      },
      '@id': 'https://aggregator.example/agg1/services',
      '@type': 'aggr:ServiceCollection',
      hasService: [
        'https://aggregator.example/agg1/services/s1',
        'https://aggregator.example/agg1/services/s2',
      ],
    });
    expect((await parseServiceCollection(collection)).sort()).toEqual([
      'https://aggregator.example/agg1/services/s1',
      'https://aggregator.example/agg1/services/s2',
    ]);
  });

  it('extracts service URLs from a Turtle service collection', async(): Promise<void> => {
    const turtle = `
@prefix aggr: <https://w3id.org/aggregator#> .
<https://aggregator.example/agg1/services>
  a aggr:ServiceCollection ;
  aggr:hasService
    <https://aggregator.example/agg1/services/s1>,
    <https://aggregator.example/agg1/services/s2> .
`;
    expect((await parseServiceCollection(turtle)).sort()).toEqual([
      'https://aggregator.example/agg1/services/s1',
      'https://aggregator.example/agg1/services/s2',
    ]);
  });

  it('computes an order-independent request key', (): void => {
    const reordered: ServiceRequest = {
      transformation: request.transformation,
      implementation: request.implementation,
      parameters: {
        'https://example.org/transformations#Sources': {
          value: 'http://example.org/source1',
          type: 'iri',
        },
        'https://example.org/transformations#Query': 'SELECT * WHERE { ?s ?p ?o }',
      },
    };
    expect(serviceRequestKey(reordered)).toBe(serviceRequestKey(request));
  });

  it('advertises every parseable RDF format in the Accept header', (): void => {
    expect(RDF_ACCEPT).toContain('application/ld+json');
    expect(RDF_ACCEPT).toContain('text/turtle');
    expect(RDF_ACCEPT).toContain('application/n-quads');
  });

  it('parses by the response Content-Type rather than sniffing the body', async(): Promise<void> => {
    const nquads =
      '<https://aggregator.example/agg1/services> ' +
      '<https://w3id.org/aggregator#hasService> ' +
      '<https://aggregator.example/agg1/services/s1> .\n';
    const services = await parseServiceCollection(
      nquads,
      undefined,
      'application/n-quads; charset=utf-8',
    );
    expect(services).toEqual([ 'https://aggregator.example/agg1/services/s1' ]);
  });

  it('honors a JSON-LD Content-Type for a service description', async(): Promise<void> => {
    const jsonLd = serializeServiceRequest(request);
    const parsed = await parseServiceDescription(jsonLd, undefined, 'application/ld+json');
    expect(parsed.performs).toBe(request.transformation);
    expect(serviceMatchesRequest(parsed, request)).toBe(true);
  });
});
