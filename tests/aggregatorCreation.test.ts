/* eslint-disable @typescript-eslint/naming-convention */
import { describe, expect, it } from 'vitest';
import { Aggregator, Auth } from '../src';
import { AggregatorCache } from '../src/aggregator/cache';
import { createMockFetch, type MockFetchStep } from './helpers/mockFetch';
import { MemoryStorage } from './helpers/storage';
import { oidcToken, webId } from './fixtures/servers';
import {
  aggregatorDescription,
  aggregatorServerDescription,
  instanceUrl,
  managementEndpoint,
  serverUrl,
} from './fixtures/aggregator';

const authorizationServer = 'https://as.example';

function createAuth(fetchMock: typeof fetch, storage: MemoryStorage): Auth {
  const auth = new Auth({ fetch: fetchMock, storage });
  auth.oidcToken = oidcToken.id_token;
  auth.oidcAccessToken = oidcToken.access_token;
  auth.webId = webId;
  return auth;
}

const serverStep: MockFetchStep = {
  request: { url: serverUrl, method: 'GET' },
  response: { status: 200, body: aggregatorServerDescription },
};

const descriptionStep: MockFetchStep = {
  request: { url: instanceUrl, method: 'GET' },
  response: { status: 200, body: aggregatorDescription },
};

describe('Aggregator interactive creation', (): void => {
  it('checks a cached instance exists before reusing it in startCreation', async(): Promise<void> => {
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

    const step = await aggregator.startCreation();

    expect(step).toEqual({ type: 'done', aggregator: instanceUrl });
  });

  it('runs the authorization_code flow', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([
      serverStep,
      {
        request: {
          url: managementEndpoint,
          method: 'POST',
          body: /"management_flow":"authorization_code"/u,
        },
        response: {
          status: 201,
          body: {
            aggregator_client_id: 'https://aggregator.example/client.jsonld',
            code_challenge: 'challenge-123',
            code_challenge_method: 'S256',
            state: 'state-abc',
            authorization_endpoint: 'https://idp.example/authorize',
          },
        },
      },
      {
        request: {
          url: managementEndpoint,
          method: 'POST',
          body: /"code":"auth-code-xyz"/u,
        },
        response: { status: 201, body: { aggregator: instanceUrl }},
      },
      descriptionStep,
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      creationFlow: 'authorization_code',
      authorizationServer,
      storage,
    });

    const step = await aggregator.startCreation({
      redirectUri: 'https://app.example/callback',
    });

    expect(step.type).toBe('redirect');
    if (step.type === 'redirect') {
      const url = new URL(step.authorizationUrl);
      expect(url.origin + url.pathname).toBe('https://idp.example/authorize');
      expect(url.searchParams.get('client_id')).toBe(
        'https://aggregator.example/client.jsonld',
      );
      expect(url.searchParams.get('code_challenge')).toBe('challenge-123');
      expect(url.searchParams.get('redirect_uri')).toBe('https://app.example/callback');
      expect(url.searchParams.get('state')).toBe('state-abc');
    }

    await aggregator.finishCreation({ code: 'auth-code-xyz', state: 'state-abc' });

    expect(aggregator.instanceUrl).toBe(instanceUrl);
    expect(aggregator.description?.login_status).toBe(true);
  });

  it('runs the device_code flow, polling until complete', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([
      serverStep,
      {
        request: {
          url: managementEndpoint,
          method: 'POST',
          body: /"management_flow":"device_code"/u,
        },
        response: {
          status: 201,
          body: {
            state: 'device-state',
            user_code: 'WDJB-MJHT',
            verification_uri: 'https://idp.example/activate',
            expires_in: 600,
            interval: 0,
          },
        },
      },
      {
        request: { url: managementEndpoint, method: 'POST', body: /"state":"device-state"/u },
        response: { status: 202 },
      },
      {
        request: { url: managementEndpoint, method: 'POST', body: /"state":"device-state"/u },
        response: { status: 201, body: { aggregator: instanceUrl }},
      },
      descriptionStep,
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      creationFlow: 'device_code',
      authorizationServer,
      storage,
    });

    const step = await aggregator.startCreation();
    expect(step.type).toBe('device');
    if (step.type === 'device') {
      expect(step.user_code).toBe('WDJB-MJHT');
      expect(step.verification_uri).toBe('https://idp.example/activate');
    }

    await aggregator.finishCreation();

    expect(aggregator.instanceUrl).toBe(instanceUrl);
    expect(aggregator.description?.login_status).toBe(true);
  });

  it('starts a token update when an instance already exists', async(): Promise<void> => {
    const storage = new MemoryStorage();
    const fetchMock = createMockFetch([
      serverStep,
      {
        request: {
          url: managementEndpoint,
          method: 'POST',
          body: new RegExp(`"aggregator":"${instanceUrl}"`, 'u'),
        },
        response: {
          status: 201,
          body: {
            aggregator_client_id: 'https://aggregator.example/client.jsonld',
            code_challenge: 'challenge-123',
            code_challenge_method: 'S256',
            state: 'state-upd',
            authorization_endpoint: 'https://idp.example/authorize',
          },
        },
      },
    ]);

    const aggregator = new Aggregator({
      auth: createAuth(fetchMock, storage),
      serverUrl,
      creationFlow: 'authorization_code',
      authorizationServer,
      storage,
    });
    // Pretend init() previously resolved an instance whose token is invalid.
    (aggregator as unknown as { internalInstanceUrl: string }).internalInstanceUrl =
      instanceUrl;

    const step = await aggregator.startCreation({
      redirectUri: 'https://app.example/callback',
    });

    expect(step.type).toBe('redirect');
  });
});
