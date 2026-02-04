/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
export interface MockFetchRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string | RegExp | ((body: string) => boolean);
}

export interface MockFetchResponse {
  status: number;
  headers?: Record<string, string>;
  body?: string | Record<string, unknown>;
}

export interface MockFetchStep {
  request: MockFetchRequest;
  response: MockFetchResponse;
}

function normalizeHeaders(
  headers: HeadersInit | undefined,
): Record<string, string> {
  const result: Record<string, string> = {};
  if (!headers) {
    return result;
  }
  const normalized = new Headers(headers);
  for (const [ key, value ] of normalized) {
    result[key.toLowerCase()] = value;
  }
  return result;
}

function extractBody(init: RequestInit | undefined): string {
  if (!init?.body) {
    return '';
  }
  if (typeof init.body === 'string') {
    return init.body;
  }
  if (init.body instanceof URLSearchParams) {
    return init.body.toString();
  }
  if (init.body instanceof Blob) {
    return `[blob:${init.body.type}]`;
  }
  return '';
}

export function createMockFetch(steps: MockFetchStep[]): typeof fetch {
  let index = 0;
  const queue = [ ...steps ];

  return async(input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const step = queue[index];
    if (!step) {
      throw new Error(`Unexpected fetch call at index ${index}.`);
    }

    let url: string;
    if (typeof input === 'string') {
      url = input;
    } else if (input instanceof URL) {
      url = input.toString();
    } else {
      url = input.url;
    }
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const headers = normalizeHeaders(
      init?.headers ?? (input instanceof Request ? input.headers : undefined),
    );
    const body = extractBody(init);

    const expectedMethod = (step.request.method ?? 'GET').toUpperCase();
    if (url !== step.request.url || method !== expectedMethod) {
      throw new Error(
        `Unexpected request at index ${index}. ` +
        `Expected ${expectedMethod} ${step.request.url}, got ${method} ${url}.`,
      );
    }

    if (step.request.headers) {
      for (const [ key, value ] of Object.entries(step.request.headers)) {
        const actual = headers[key.toLowerCase()];
        if (actual !== value) {
          throw new Error(
            `Unexpected header "${key}" at index ${index}. ` +
            `Expected "${value}", got "${actual ?? ''}".`,
          );
        }
      }
    }

    if (step.request.body) {
      let ok = false;
      if (typeof step.request.body === 'string') {
        ok = body === step.request.body;
      } else if (step.request.body instanceof RegExp) {
        ok = step.request.body.test(body);
      } else {
        ok = step.request.body(body);
      }
      if (!ok) {
        throw new Error(
          `Unexpected body at index ${index}. ` +
          `Got: ${body}`,
        );
      }
    }

    index += 1;

    const responseHeaders = new Headers(step.response.headers ?? {});
    let responseBody = step.response.body;
    if (responseBody && typeof responseBody !== 'string') {
      if (!responseHeaders.has('content-type')) {
        responseHeaders.set('content-type', 'application/json');
      }
      responseBody = JSON.stringify(responseBody);
    }

    return new Response(responseBody ?? '', {
      status: step.response.status,
      headers: responseHeaders,
    });
  };
}
