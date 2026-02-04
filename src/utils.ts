export type FetchLike = typeof fetch;

export function ensureTrailingSlash(url: string): string {
  return url.endsWith('/') ? url : `${url}/`;
}

export function withoutTrailingSlash(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

export function joinUrl(base: string, path: string): string {
  return new URL(path, ensureTrailingSlash(base)).toString();
}

export async function safeJson<T>(res: Response): Promise<T | undefined> {
  const text = await res.text();
  if (!text) {
    return undefined;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}

export function mergeHeaders(
  base?: HeadersInit,
  extra?: HeadersInit,
): HeadersInit | undefined {
  if (!base && !extra) {
    return undefined;
  }
  const headers = new Headers(base);
  if (extra) {
    const extraHeaders = new Headers(extra);
    // eslint-disable-next-line unicorn/no-array-for-each
    extraHeaders.forEach((value, key): void => {
      headers.set(key, value);
    });
  }
  return headers;
}

export function withBearer(token: string, headers?: HeadersInit): HeadersInit {
  const authHeaderKey = 'Authorization';
  return mergeHeaders(headers, { [authHeaderKey]: `Bearer ${token}` }) ?? {
    [authHeaderKey]: `Bearer ${token}`,
  };
}

export function normalizeBaseUrl(url: string): string {
  return withoutTrailingSlash(url.trim());
}
