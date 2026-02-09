export interface BrowserGlobals {
  location: { href: string };
}

export interface BrowserGlobalsOptions {
  url: string;
  documentTitle?: string;
}

export function installBrowserGlobals({
  url,
  documentTitle = 'Temp client tests',
}: BrowserGlobalsOptions): BrowserGlobals {
  const hasDom = typeof window !== 'undefined' && typeof window.document !== 'undefined';

  if (!hasDom) {
    const location = { href: url };
    const history = {
      replaceState: (...args: unknown[]): void => {
        void args;
      },
    };

    globalThis.window = { location, history } as unknown as Window;
    globalThis.document = { title: documentTitle } as Document;

    if (typeof globalThis.atob === 'undefined') {
      globalThis.atob = (value: string): string =>
        Buffer.from(value, 'base64').toString('binary');
    }
    if (typeof globalThis.btoa === 'undefined') {
      globalThis.btoa = (value: string): string =>
        Buffer.from(value, 'binary').toString('base64');
    }

    return { location };
  }

  const resolvedUrl = new URL(url, window.location.href);
  const nextUrl = resolvedUrl.origin === window.location.origin ?
    resolvedUrl.href :
    `${resolvedUrl.pathname}${resolvedUrl.search}${resolvedUrl.hash}`;

  try {
    window.history.replaceState({}, documentTitle, nextUrl);
  } catch {
    // Best-effort in real browsers without triggering navigation.
  }

  document.title = documentTitle;

  return { location: window.location as { href: string }};
}
