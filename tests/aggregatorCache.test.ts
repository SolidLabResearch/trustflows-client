import { describe, expect, it } from 'vitest';
import { AggregatorCache } from '../src/aggregator/cache';
import { MemoryStorage } from './helpers/storage';

const serverUrl = 'https://aggregator.example/';
const webId = 'https://user.example/profile/card#me';
const instanceUrl = 'https://aggregator.example/aggregators/agg-1/';

describe('AggregatorCache', (): void => {
  it('persists instances to storage and rehydrates them', (): void => {
    const storage = new MemoryStorage();
    const cache = new AggregatorCache({ storage, enabled: true });
    cache.setInstance(serverUrl, webId, { aggregator: instanceUrl, flow: 'provision' });

    const rehydrated = new AggregatorCache({ storage, enabled: true });
    expect(rehydrated.getInstance(serverUrl, webId)).toEqual({
      aggregator: instanceUrl,
      flow: 'provision',
    });
  });

  it('does not persist when disabled', (): void => {
    const storage = new MemoryStorage();
    const cache = new AggregatorCache({ storage, enabled: false });
    cache.setInstance(serverUrl, webId, { aggregator: instanceUrl, flow: 'none' });

    expect(cache.getInstance(serverUrl, webId)).toBeDefined();
    expect(new AggregatorCache({ storage, enabled: true }).getInstance(serverUrl, webId))
      .toBeUndefined();
  });

  it('stores and clears services, including by URL', (): void => {
    const cache = new AggregatorCache({ storage: new MemoryStorage(), enabled: true });
    const info = { service: 'https://aggregator.example/agg1/services/s1', outputs: {}};
    cache.setService(instanceUrl, 'key-1', info);
    expect(cache.getService(instanceUrl, 'key-1')).toEqual(info);

    cache.clearServiceByUrl(info.service);
    expect(cache.getService(instanceUrl, 'key-1')).toBeUndefined();
  });

  it('clears instances', (): void => {
    const cache = new AggregatorCache({ storage: new MemoryStorage(), enabled: true });
    cache.setInstance(serverUrl, webId, { aggregator: instanceUrl, flow: 'provision' });
    cache.clearInstance(serverUrl, webId);
    expect(cache.getInstance(serverUrl, webId)).toBeUndefined();
  });
});
