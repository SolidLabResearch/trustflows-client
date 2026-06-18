/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Aggregator, Auth } from '../src';
import { AggregatorCache } from '../src/aggregator/cache';
import { RDF_ACCEPT, serviceRequestKey } from '../src/aggregator/rdf';
import { createMockFetch, type MockFetchStep } from './helpers/mockFetch';
import { MemoryStorage } from './helpers/storage';
import { oidcToken, webId } from './fixtures/servers';
import {
  aggregatorDescription,
  aggregatorServerDescription,
  collectionWithServiceTurtle,
  emptyCollectionTurtle,
  instanceUrl,
  managementEndpoint,
  outputAccessUrl,
  outputIri,
  serverUrl,
  serviceCollectionEndpoint,
  serviceDescriptionTurtle,
  serviceRequest,
  serviceUrl,
} from './fixtures/aggregator';

function createAuth(fetchMock: typeof fetch, storage: MemoryStorage): Auth {
  const auth = new Auth({ fetch: fetchMock, storage });
  auth.oidcToken = oidcToken.id_token;
  auth.oidcAccessToken = oidcToken.access_token;
  auth.webId = webId;
  return auth;
}

function cachedInstanceStorage(): MemoryStorage {
  const storage = new MemoryStorage();
  new AggregatorCache({ storage, enabled: true }).setInstance(serverUrl, webId, {
    aggregator: instanceUrl,
    flow: 'provision',
  });
  return storage;
}

const initSteps: MockFetchStep[] = [
  {
    request: { url: serverUrl, method: 'GET' },
    response: { status: 200, body: aggregatorServerDescription },
  },
  {
    request: { url: instanceUrl, method: 'GET' },
    response: { status: 200, body: aggregatorDescription },
  },
];

function turtle(body: string): MockFetchStep['response'] {
  return {
    status: 200,
    headers: { 'content-type': 'text/turtle' },
    body,
  };
}

describe('Aggregator services', (): void => {
  it('deploys a service on a cache and collection miss', async(): Promise<void> => {
    const storage = cachedInstanceStorage();
    const fetchMock = createMockFetch([
      ...initSteps,
      {
        request: { url: serviceCollectionEndpoint, method: 'GET' },
        response: {
          status: 200,
          headers: { 'content-type': 'text/turtle', 'accept-post': 'text/turtle' },
          body: emptyCollectionTurtle,
        },
      },
      {
        request: { url: serviceCollectionEndpoint, method: 'POST' },
        response: {
          status: 201,
          headers: { 'content-type': 'text/turtle', location: serviceUrl },
          body: serviceDescriptionTurtle,
        },
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();
    const info = await aggregator.getService(serviceRequest);

    expect(info.service).toBe(serviceUrl);
    expect(info.outputs).toEqual({ [outputIri]: [ outputAccessUrl ]});
    expect(info.provenanceLog).toBe(`${serviceUrl}/provenance`);
  });

  it('returns a matching service found in the collection without deploying', async(): Promise<void> => {
    const storage = cachedInstanceStorage();
    const fetchMock = createMockFetch([
      ...initSteps,
      {
        request: {
          url: serviceCollectionEndpoint,
          method: 'GET',
          headers: { accept: RDF_ACCEPT },
        },
        response: turtle(collectionWithServiceTurtle),
      },
      {
        request: {
          url: serviceUrl,
          method: 'GET',
          headers: { accept: RDF_ACCEPT },
        },
        response: turtle(serviceDescriptionTurtle),
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();
    const info = await aggregator.getService(serviceRequest);

    expect(info.service).toBe(serviceUrl);
    expect(info.outputs).toEqual({ [outputIri]: [ outputAccessUrl ]});
  });

  it('checks a cached service exists before returning it', async(): Promise<void> => {
    const storage = cachedInstanceStorage();
    const fetchMock = createMockFetch([
      ...initSteps,
      {
        request: { url: serviceCollectionEndpoint, method: 'GET' },
        response: turtle(collectionWithServiceTurtle),
      },
      {
        request: { url: serviceUrl, method: 'GET' },
        response: turtle(serviceDescriptionTurtle),
      },
      {
        request: { url: serviceUrl, method: 'GET' },
        response: turtle(serviceDescriptionTurtle),
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();
    await aggregator.getService(serviceRequest);
    const info = await aggregator.getService(serviceRequest);

    expect(info.service).toBe(serviceUrl);
  });

  it('clears a cached service that no longer exists and resolves it again', async(): Promise<void> => {
    const storage = cachedInstanceStorage();
    new AggregatorCache({ storage, enabled: true }).setService(
      instanceUrl,
      serviceRequestKey(serviceRequest),
      { service: serviceUrl, outputs: {}},
    );
    const fetchMock = createMockFetch([
      ...initSteps,
      {
        request: { url: serviceUrl, method: 'GET' },
        response: { status: 404 },
      },
      {
        request: { url: serviceCollectionEndpoint, method: 'GET' },
        response: {
          status: 200,
          headers: { 'content-type': 'text/turtle', 'accept-post': 'text/turtle' },
          body: emptyCollectionTurtle,
        },
      },
      {
        request: { url: serviceCollectionEndpoint, method: 'POST' },
        response: {
          status: 201,
          headers: { 'content-type': 'text/turtle', location: serviceUrl },
          body: serviceDescriptionTurtle,
        },
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();
    const info = await aggregator.getService(serviceRequest);

    expect(info.service).toBe(serviceUrl);
    expect(info.outputs).toEqual({ [outputIri]: [ outputAccessUrl ]});
  });

  it('recreates a destroyed instance and deploys the service', async(): Promise<void> => {
    const storage = cachedInstanceStorage();
    const fetchMock = createMockFetch([
      ...initSteps,
      // The instance was destroyed: its service collection endpoint is gone.
      {
        request: { url: serviceCollectionEndpoint, method: 'GET' },
        response: { status: 404 },
      },
      // Recovery rediscovers an instance from the management collection...
      {
        request: { url: managementEndpoint, method: 'GET' },
        response: { status: 200, body: [ instanceUrl ]},
      },
      {
        request: { url: instanceUrl, method: 'GET' },
        response: { status: 200, body: aggregatorDescription },
      },
      // ...then resolution retries against the live instance and deploys.
      {
        request: { url: serviceCollectionEndpoint, method: 'GET' },
        response: {
          status: 200,
          headers: { 'content-type': 'text/turtle', 'accept-post': 'text/turtle' },
          body: emptyCollectionTurtle,
        },
      },
      {
        request: { url: serviceCollectionEndpoint, method: 'POST' },
        response: {
          status: 201,
          headers: { 'content-type': 'text/turtle', location: serviceUrl },
          body: serviceDescriptionTurtle,
        },
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();
    const info = await aggregator.getService(serviceRequest);

    expect(info.service).toBe(serviceUrl);
    expect(aggregator.instanceUrl).toBe(instanceUrl);
  });

  it('lists the whole service collection', async(): Promise<void> => {
    const storage = cachedInstanceStorage();
    const fetchMock = createMockFetch([
      ...initSteps,
      {
        request: { url: serviceCollectionEndpoint, method: 'GET' },
        response: turtle(collectionWithServiceTurtle),
      },
      {
        request: { url: serviceUrl, method: 'GET' },
        response: turtle(serviceDescriptionTurtle),
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();
    const services = await aggregator.getServiceCollection();

    expect(services).toHaveLength(1);
    expect(services[0].service).toBe(serviceUrl);
  });

  it('deletes a service and clears it from the cache', async(): Promise<void> => {
    const storage = cachedInstanceStorage();
    const fetchMock = createMockFetch([
      ...initSteps,
      {
        request: { url: serviceCollectionEndpoint, method: 'GET' },
        response: turtle(collectionWithServiceTurtle),
      },
      {
        request: { url: serviceUrl, method: 'GET' },
        response: turtle(serviceDescriptionTurtle),
      },
      {
        request: { url: serviceUrl, method: 'DELETE' },
        response: { status: 204 },
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();
    await aggregator.getService(serviceRequest);
    await aggregator.deleteService(serviceUrl);

    expect(new AggregatorCache({ storage, enabled: true })
      .getService(instanceUrl, serviceRequestKey(serviceRequest))).toBeUndefined();
  });
});
