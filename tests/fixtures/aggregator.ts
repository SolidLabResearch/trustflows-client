/* eslint-disable @typescript-eslint/naming-convention */
export const serverUrl = 'https://aggregator.example/';
export const managementEndpoint = 'https://aggregator.example/registration';
export const instanceUrl = 'https://aggregator.example/aggregators/agg-1/';

export const aggregatorServerDescription = {
  management_endpoint: managementEndpoint,
  supported_management_flows: [ 'provision', 'authorization_code', 'device_code' ],
  supported_management_request_formats: [ 'application/json' ],
  version: '1.0.0',
  client_identifier: 'https://aggregator.example/client.jsonld',
  transformation_catalog: 'https://aggregator.example/transformations',
};

export const aggregatorDescription = {
  aggregator_base_url: instanceUrl,
  created_at: '2026-01-01T12:00:00Z',
  login_status: true,
  token_expiry: '2099-01-01T12:00:00Z',
  transformation_catalog: `${instanceUrl}transformations`,
  service_collection_endpoint: `${instanceUrl}services`,
};

export const serviceCollectionEndpoint = `${instanceUrl}services`;
export const serviceUrl = `${instanceUrl}services/s1`;

export const transformation =
  'https://aggregator.example/transformations#QueryView';
export const queryParameter =
  'https://aggregator.example/transformations#Query';
export const outputIri = 'https://aggregator.example/transformations#Result';
export const outputAccessUrl = `${serviceUrl}/output`;

export const serviceRequest = {
  transformation,
  parameters: { [queryParameter]: 'SELECT * WHERE { ?s ?p ?o }' },
};

export const serviceDescriptionTurtle = `
@prefix aggr: <https://w3id.org/aggregator#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix fnoc: <https://fno.io/vocabulary/composition/0.1.0/> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .

<${serviceUrl}>
  a aggr:Service ;
  aggr:performs <${transformation}> ;
  aggr:applies [
    a fno:AppliedFunction ;
    fnoc:applies <${transformation}> ;
    fnoc:parameterBindings (
      [ fnoc:boundParameter <${queryParameter}> ;
        fnoc:boundToTerm "SELECT * WHERE { ?s ?p ?o }" ]
    )
  ] ;
  aggr:provenanceLog <${serviceUrl}/provenance> ;
  dcat:servesDataset <${serviceUrl}#dataset> .

<${serviceUrl}#dataset>
  a dcat:Dataset ;
  aggr:forOutput <${outputIri}> ;
  dcat:distribution <${serviceUrl}#dist> .

<${serviceUrl}#dist>
  a dcat:Distribution ;
  dcat:accessURL <${outputAccessUrl}> .
`;

export const emptyCollectionTurtle = `
@prefix aggr: <https://w3id.org/aggregator#> .
<${serviceCollectionEndpoint}> a aggr:ServiceCollection .
`;

export const collectionWithServiceTurtle = `
@prefix aggr: <https://w3id.org/aggregator#> .
<${serviceCollectionEndpoint}>
  a aggr:ServiceCollection ;
  aggr:hasService <${serviceUrl}> .
`;
