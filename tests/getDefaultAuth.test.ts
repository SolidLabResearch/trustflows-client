import { describe, expect, it } from 'vitest';
import { configureDefaultAuth, getDefaultAuth } from '../src';
import { MemoryStorage } from './helpers/storage';

async function customFetch(): Promise<Response> {
  return new Response('', { status: 204 });
}

describe('getDefaultAuth', (): void => {
  it('returns the same instance across calls', (): void => {
    configureDefaultAuth({ fetch: customFetch, storage: new MemoryStorage() });
    const first = getDefaultAuth();
    const second = getDefaultAuth();

    expect(first).toBe(second);
    expect(second.getFetch()).toBe(customFetch);
  });
});
