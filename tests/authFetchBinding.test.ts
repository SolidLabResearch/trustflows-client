import { describe, expect, it } from 'vitest';
import { Auth } from '../src';
import { MemoryStorage } from './helpers/storage';

describe('Auth fetch binding', (): void => {
  it('binds provided fetch to globalThis', async(): Promise<void> => {
    let observedThis: unknown;
    const customFetch = async function(
      this: unknown,
    ): Promise<Response> {
      // eslint-disable-next-line @typescript-eslint/no-this-alias,consistent-this
      observedThis = this;
      return new Response(JSON.stringify({}), {
        status: 200,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        headers: { 'content-type': 'application/json' },
      });
    } as typeof fetch;

    const auth = new Auth({
      fetch: customFetch,
      storage: new MemoryStorage(),
    });

    await auth.getOidcConfig('https://issuer.example');

    expect(observedThis).toBe(globalThis);
  });
});
