/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Aggregator, AggregatorAuthorizationRequiredError, Auth } from '../src';
import { AggregatorCache } from '../src/aggregator/cache';
import { createMockFetch } from './helpers/mockFetch';
import { MemoryStorage } from './helpers/storage';
import { oidcToken, webId } from './fixtures/servers';
import {
  aggregatorDescription,
  aggregatorServerDescription,
  instanceUrl,
  managementEndpoint,
  serverUrl,
} from './fixtures/aggregator';

function createAuth(fetchMock: typeof fetch, storage: MemoryStorage): Auth {
  const auth = new Auth({ fetch: fetchMock, storage });
  auth.oidcToken = oidcToken.id_token;
  auth.oidcAccessToken = oidcToken.access_token;
  auth.webId = webId;
  return auth;
}

const serverStep = {
  request: { url: serverUrl, method: 'GET' },
  response: {
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: aggregatorServerDescription,
  },
};

const descriptionStep = {
  request: { url: instanceUrl, method: 'GET' },
  response: {
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: aggregatorDescription,
  },
};

describe('Aggregator.init', (): void => {
  it('creates an instance with the provision flow when none exist', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([
      serverStep,
      {
        request: { url: managementEndpoint, method: 'GET' },
        response: { status: 200, body: []},
      },
      {
        request: {
          url: managementEndpoint,
          method: 'POST',
          body: /"management_flow":"provision"/u,
        },
        response: { status: 201, body: { aggregator: instanceUrl }},
      },
      descriptionStep,
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();

    expect(aggregator.instanceUrl).toBe(instanceUrl);
    expect(aggregator.description?.login_status).toBe(true);
    // Cached for next time.
    expect(new AggregatorCache({ storage, enabled: true }).getInstance(serverUrl, webId))
      .toEqual({ aggregator: instanceUrl, flow: 'provision' });
  });

  it('uses the first existing instance from the management list', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([
      serverStep,
      {
        request: { url: managementEndpoint, method: 'GET' },
        response: {
          status: 200,
          body: [ instanceUrl, 'https://aggregator.example/aggregators/agg-2/' ],
        },
      },
      descriptionStep,
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();

    expect(aggregator.instanceUrl).toBe(instanceUrl);
  });

  it('reuses a cached instance without listing or creating', async(): Promise<void> => {
    const storage = new MemoryStorage();
    new AggregatorCache({ storage, enabled: true }).setInstance(serverUrl, webId, {
      aggregator: instanceUrl,
      flow: 'provision',
    });

    const fetchMock = createMockFetch([ serverStep, descriptionStep ]);
    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();

    expect(aggregator.instanceUrl).toBe(instanceUrl);
  });

  it('rediscovers the instance when the cached one was destroyed (404)', async(): Promise<void> => {
    const storage = new MemoryStorage();
    new AggregatorCache({ storage, enabled: true }).setInstance(serverUrl, webId, {
      aggregator: instanceUrl,
      flow: 'provision',
    });

    const fetchMock = createMockFetch([
      serverStep,
      // The cached instance no longer exists server-side.
      {
        request: { url: instanceUrl, method: 'GET' },
        response: { status: 404 },
      },
      {
        request: { url: managementEndpoint, method: 'GET' },
        response: { status: 200, body: []},
      },
      {
        request: { url: managementEndpoint, method: 'POST' },
        response: { status: 201, body: { aggregator: instanceUrl }},
      },
      descriptionStep,
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();

    expect(aggregator.instanceUrl).toBe(instanceUrl);
    expect(aggregator.description?.login_status).toBe(true);
  });

  it('throws when an interactive flow is required to create an instance', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([
      serverStep,
      {
        request: { url: managementEndpoint, method: 'GET' },
        response: { status: 200, body: []},
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      creationFlow: 'authorization_code',
      storage,
    });

    await expect(aggregator.init()).rejects.toBeInstanceOf(
      AggregatorAuthorizationRequiredError,
    );
  });

  it('deletes the instance and clears the cache', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([
      serverStep,
      {
        request: { url: managementEndpoint, method: 'GET' },
        response: { status: 200, body: []},
      },
      {
        request: { url: managementEndpoint, method: 'POST' },
        response: { status: 201, body: { aggregator: instanceUrl }},
      },
      descriptionStep,
      {
        request: {
          url: managementEndpoint,
          method: 'DELETE',
          body: new RegExp(`"aggregator":"${instanceUrl}"`, 'u'),
        },
        response: { status: 204 },
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      storage,
    });
    await aggregator.init();
    await aggregator.delete();

    expect(aggregator.instanceUrl).toBeUndefined();
    expect(new AggregatorCache({ storage, enabled: true }).getInstance(serverUrl, webId))
      .toBeUndefined();
  });
});
