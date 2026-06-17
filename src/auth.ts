/* eslint-disable @typescript-eslint/naming-convention */
import type {
  ClaimResolver,
  ClaimResolverDefinition,
  ClaimResolverRegistry,
} from './uma/claims/types';
import { createDefaultClaimResolvers } from './uma/claims/registry';
import {
  fetchWithUma,
  parseUmaAuthenticateHeader,
} from './uma/utils';
import { discoverOidcIssuer } from './utils';

export interface AuthOptions {
  fetch?: typeof fetch;
  redirect?: (url: string) => void;
  storage?: Storage;
  claimResolvers?: ClaimResolverRegistry;
  persistTokens?: boolean;
}

/**
 * Per-request options for the fetch function returned by
 * {@link Auth.createAuthFetch}.
 */
export interface AuthFetchOptions {
  /**
   * When `true`, and the UMA authorization server denies access with a 4xx
   * error (i.e. the requesting party does not currently have access), an access
   * request is sent to the authorization server's `/requests` endpoint so the
   * requesting party can ask for access. The access request's response is then
   * returned from the fetch call.
   *
   * Defaults to `false`, in which case a denial rejects the returned promise.
   */
  accessRequest?: boolean;
}

interface OidcConfiguration {
  authorization_endpoint?: string;
  token_endpoint?: string;
  end_session_endpoint?: string;
  [key: string]: unknown;
}

interface UmaTokenCacheEntry {
  token_type: string;
  access_token: string;
  expires_at?: number;
}

interface TokenResponse {
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
}

interface ClientCredentials {
  id: string;
  secret: string;
  scope: string;
}

interface AccountControls {
  controls?: {
    password?: { login?: string };
    account?: { clientCredentials?: string };
  };
}

export class Auth {
  public oidcAccessToken?: string;
  public oidcToken?: string;
  public oidcRefreshToken?: string;
  public oidcTokenExpiry?: number;
  public webId?: string;
  public umaPermissionTokens = new Map<string, UmaTokenCacheEntry>();

  private readonly fetchFn: typeof fetch;
  private readonly redirectFn: (url: string) => void;
  private readonly storage?: Storage;
  private readonly claimResolvers: ClaimResolverRegistry;
  private readonly persistTokens: boolean;
  private oidcIssuer?: string;
  private clientCredentials?: ClientCredentials;
  private handleRedirectPromise?: Promise<boolean>;

  public constructor(options: AuthOptions = {}) {
    const rawFetch = options.fetch ?? fetch;
    this.fetchFn = rawFetch === fetch ? rawFetch.bind(globalThis) : rawFetch;
    this.redirectFn = options.redirect ?? ((url: string): void => {
      window.location.href = url;
    });
    this.storage =
      options.storage ??
      (typeof sessionStorage === 'undefined' ? undefined : sessionStorage);
    this.persistTokens = options.persistTokens ?? true;
    this.claimResolvers = [
      ...createDefaultClaimResolvers(),
      ...options.claimResolvers ?? [],
    ];
    this.hydrateOidcTokens();
    this.hydrateUmaTokens();
    this.hydrateClientCredentials();
  }

  public addClaimResolver(
    format: string | ClaimResolverDefinition,
    resolver?: ClaimResolver,
  ): void {
    if (typeof format === 'string') {
      if (!resolver) {
        throw new Error('Claim resolver function is required.');
      }
      this.claimResolvers.push({
        id: `custom:${format}`,
        match: { claim_token_format: format },
        resolve: resolver,
      });
      return;
    }
    this.claimResolvers.push(format);
  }

  public get accessToken(): string | undefined {
    return this.oidcAccessToken;
  }

  public set accessToken(value: string | undefined) {
    this.oidcAccessToken = value;
  }

  /**
   * The OIDC issuer the user logged in with, if known.
   */
  public get issuer(): string | undefined {
    return this.oidcIssuer ?? this.storage?.getItem('oidc_issuer') ?? undefined;
  }

  public async login(
    issuer: string,
    clientId: string,
    redirectUri: string,
    scope = 'openid webid offline_access',
  ): Promise<void> {
    const config = await this.getOidcConfig(issuer);
    if (!config.authorization_endpoint) {
      throw new Error('Missing authorization_endpoint in OIDC configuration');
    }

    const state = this.generateRandomString();
    const codeVerifier = this.generateRandomString();
    const codeChallenge = await this.pkceChallenge(codeVerifier);

    const storage = this.getStorage();
    storage.setItem('oidc_state', state);
    storage.setItem('oidc_code_verifier', codeVerifier);
    storage.setItem('oidc_issuer', issuer);
    storage.setItem('oidc_client_id', clientId);
    storage.setItem('oidc_redirect_uri', redirectUri);
    this.oidcIssuer = issuer;

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      prompt: 'consent',
      response_mode: 'query',
    });

    this.redirectFn(`${config.authorization_endpoint}?${params.toString()}`);
  }

  public async logout(postLogoutRedirectUri: string): Promise<void> {
    const resolvedIssuer = this.oidcIssuer ?? this.storage?.getItem('oidc_issuer') ?? undefined;
    const idTokenHint = this.oidcToken;

    this.clearCache();

    if (!resolvedIssuer) {
      return;
    }

    let config: OidcConfiguration;
    try {
      config = await this.getOidcConfig(resolvedIssuer);
    } catch {
      return;
    }

    if (!config.end_session_endpoint) {
      return;
    }

    const params = new URLSearchParams();
    if (idTokenHint) {
      params.set('id_token_hint', idTokenHint);
    }
    params.set('post_logout_redirect_uri', postLogoutRedirectUri);

    const logoutUrl = params.toString() ?
      `${config.end_session_endpoint}?${params.toString()}` :
      config.end_session_endpoint;

    this.redirectFn(logoutUrl);
  }

  public async handleIncomingRedirect(): Promise<boolean> {
    if (this.handleRedirectPromise) {
      return this.handleRedirectPromise;
    }

    this.handleRedirectPromise = (async(): Promise<boolean> => {
      const url = new URL(window.location.href);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code) {
        return false;
      }

      const storage = this.getStorage();
      const storedState = storage.getItem('oidc_state');
      if (!state || state !== storedState) {
        throw new Error('OIDC state mismatch');
      }

      const issuer = storage.getItem('oidc_issuer');
      const clientId = storage.getItem('oidc_client_id');
      const redirectUri = storage.getItem('oidc_redirect_uri');
      const codeVerifier = storage.getItem('oidc_code_verifier');
      if (!issuer || !clientId || !redirectUri || !codeVerifier) {
        throw new Error('Missing stored OIDC parameters');
      }
      this.oidcIssuer = issuer;

      const config = await this.getOidcConfig(issuer);
      if (!config.token_endpoint) {
        throw new Error('Missing token_endpoint in OIDC configuration');
      }

      const bodyParams = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: codeVerifier,
      });

      const tokenResp = await this.fetchFn(config.token_endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: bodyParams.toString(),
      });

      if (!tokenResp.ok) {
        throw new Error(`Token endpoint error ${tokenResp.status}`);
      }

      const tokenJson = (await tokenResp.json()) as TokenResponse;
      this.applyTokenResponse(tokenJson);

      window.history.replaceState({}, document.title, redirectUri);
      return true;
    })();

    try {
      return await this.handleRedirectPromise;
    } finally {
      this.handleRedirectPromise = undefined;
    }
  }

  public async isLoggedIn(): Promise<boolean> {
    if (this.handleRedirectPromise) {
      await this.handleRedirectPromise;
    }
    try {
      await this.ensureValidToken();
    } catch {
      return false;
    }
    return Boolean(this.oidcAccessToken ?? this.oidcToken);
  }

  public async refreshTokens(tokenEndpoint: string, clientId: string): Promise<void> {
    if (!this.oidcRefreshToken) {
      return;
    }
    const bodyParams = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: this.oidcRefreshToken,
      client_id: clientId,
    });
    const resp = await this.fetchFn(tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: bodyParams.toString(),
    });
    if (!resp.ok) {
      throw new Error(`Refresh token endpoint error ${resp.status}`);
    }
    const json = (await resp.json()) as TokenResponse;
    this.applyTokenResponse(json);
  }

  public async ensureValidToken(): Promise<void> {
    if (!this.oidcTokenExpiry) {
      return;
    }
    if (Date.now() < this.oidcTokenExpiry - 60_000) {
      return;
    }

    const issuer = this.oidcIssuer ?? this.storage?.getItem('oidc_issuer') ?? undefined;
    if (!issuer) {
      return;
    }

    if (this.clientCredentials) {
      const config = await this.getOidcConfig(issuer);
      if (!config.token_endpoint) {
        return;
      }
      await this.requestClientCredentialsToken(config.token_endpoint);
      return;
    }

    if (!this.oidcRefreshToken) {
      return;
    }

    const clientId = this.storage?.getItem('oidc_client_id');
    if (!clientId) {
      return;
    }

    const config = await this.getOidcConfig(issuer);
    if (!config.token_endpoint) {
      return;
    }
    await this.refreshTokens(config.token_endpoint, clientId);
  }

  /**
   * Logs in with client credentials using only a WebID and the account's
   * email/password. The Solid-OIDC issuer is discovered from the WebID profile,
   * a fresh client credentials token is minted on that server (via the Community
   * Solid Server account API) and immediately exchanged for an access token,
   * which then auto-renews through {@link ensureValidToken}.
   *
   * ⚠️ **Security warning:** this sends the account's email/password and stores
   * a long-lived secret on the client. Use it for testing and demos only —
   * prefer the interactive {@link login} flow in production.
   */
  public async loginClientCredentials(
    webId: string,
    email: string,
    password: string,
  ): Promise<void> {
    // eslint-disable-next-line no-console
    console.warn(
      'Auth.loginClientCredentials uses an email/password and stores a ' +
      'long-lived secret on the client. This is insecure and meant for ' +
      'testing and demos only.',
    );
    const issuer = await discoverOidcIssuer(this.fetchFn, webId);
    const { id, secret } = await this.createClientCredentials(
      issuer,
      email,
      password,
      { name: `trustflows-client-${Date.now()}`, webId },
    );
    await this.loginWithClientCredentials(issuer, id, secret);
  }

  /**
   * Mints a long-lived client credentials token through the Community Solid
   * Server account API. Logs in with the account's email/password to obtain an
   * account token, then asks the server to generate credentials for the given
   * WebID. The secret cannot be retrieved again, so it is used immediately by
   * {@link loginClientCredentials}.
   */
  private async createClientCredentials(
    server: string,
    email: string,
    password: string,
    options: { name?: string; webId?: string } = {},
  ): Promise<{ id: string; secret: string; resource: string }> {
    const accountUrl = `${server.replace(/\/$/u, '')}/.account/`;

    const indexResponse = await this.fetchFn(accountUrl);
    if (!indexResponse.ok) {
      throw await this.describeHttpError('Account API error', indexResponse);
    }
    const loginUrl = ((await indexResponse.json()) as AccountControls)
      .controls?.password?.login;
    if (!loginUrl) {
      throw new Error('Account API does not expose a password login control.');
    }

    const loginResponse = await this.fetchFn(loginUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!loginResponse.ok) {
      throw await this.describeHttpError('Account login error', loginResponse);
    }
    const { authorization } = (await loginResponse.json()) as {
      authorization?: string;
    };
    if (!authorization) {
      throw new Error('Account login did not return an authorization value.');
    }

    const authHeader = { authorization: `CSS-Account-Token ${authorization}` };
    const authedIndexResponse = await this.fetchFn(accountUrl, {
      headers: authHeader,
    });
    if (!authedIndexResponse.ok) {
      throw await this.describeHttpError('Account API error', authedIndexResponse);
    }
    const credentialsUrl = ((await authedIndexResponse.json()) as AccountControls)
      .controls?.account?.clientCredentials;
    if (!credentialsUrl) {
      throw new Error('Account API does not expose a client credentials control.');
    }

    const credentialsResponse = await this.fetchFn(credentialsUrl, {
      method: 'POST',
      headers: { ...authHeader, 'content-type': 'application/json' },
      body: JSON.stringify({
        name: options.name ?? `trustflows-${Date.now()}`,
        webId: options.webId,
      }),
    });
    if (!credentialsResponse.ok) {
      throw await this.describeHttpError('Client credentials error', credentialsResponse);
    }
    return (await credentialsResponse.json()) as {
      id: string;
      secret: string;
      resource: string;
    };
  }

  private async describeHttpError(prefix: string, response: Response): Promise<Error> {
    let detail = '';
    try {
      detail = (await response.text()).trim();
    } catch {
      /* Ignore */
    }
    return new Error(
      detail ?
        `${prefix} ${response.status}: ${detail}` :
        `${prefix} ${response.status}`,
    );
  }

  /**
   * Requests an access token from the issuer's token endpoint using a client
   * credentials `id`/`secret` pair. The pair is retained so
   * {@link ensureValidToken} can transparently request a fresh access token
   * when the current one expires (there is no refresh token).
   */
  private async loginWithClientCredentials(
    issuer: string,
    id: string,
    secret: string,
  ): Promise<void> {
    const config = await this.getOidcConfig(issuer);
    if (!config.token_endpoint) {
      throw new Error('Missing token_endpoint in OIDC configuration');
    }

    this.oidcIssuer = issuer;
    this.clientCredentials = { id, secret, scope: 'webid' };
    this.storage?.setItem('oidc_issuer', issuer);

    await this.requestClientCredentialsToken(config.token_endpoint);
    this.persistClientCredentials();
  }

  private async requestClientCredentialsToken(tokenEndpoint: string): Promise<void> {
    if (!this.clientCredentials) {
      throw new Error('No client credentials available.');
    }
    const { id, secret, scope } = this.clientCredentials;
    const authString = `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;
    const resp = await this.fetchFn(tokenEndpoint, {
      method: 'POST',
      headers: {
        authorization: `Basic ${btoa(authString)}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope,
      }).toString(),
    });
    if (!resp.ok) {
      throw new Error(`Token endpoint error ${resp.status}`);
    }
    const json = (await resp.json()) as TokenResponse;

    const token = json.id_token ?? json.access_token;
    this.applyTokenResponse({
      access_token: json.access_token ?? token,
      id_token: token,
      refresh_token: json.refresh_token,
      expires_in: json.expires_in,
      token_type: json.token_type,
    });
  }

  private applyTokenResponse(json: TokenResponse): void {
    if (json.access_token !== undefined) {
      this.oidcAccessToken = json.access_token;
    }
    if (json.id_token !== undefined) {
      this.oidcToken = json.id_token;
      this.webId = this.extractWebId(json.id_token);
    } else if (json.access_token !== undefined) {
      const webId = this.extractWebId(json.access_token);
      if (webId) {
        this.webId = webId;
      }
    }
    if (json.refresh_token !== undefined) {
      this.oidcRefreshToken = json.refresh_token;
    }
    if (json.expires_in !== undefined) {
      this.oidcTokenExpiry = Date.now() + json.expires_in * 1000;
    }
    this.persistOidcTokens();
  }

  public async getOidcConfig(issuer: string): Promise<OidcConfiguration> {
    const url = `${issuer.replace(/\/$/u, '')}/.well-known/openid-configuration`;
    const res = await this.fetchFn(url);
    if (!res.ok) {
      throw new Error('Failed fetching OIDC configuration');
    }
    return (await res.json()) as OidcConfiguration;
  }

  public generateRandomString(bytes = 64): string {
    const cryptoObj = this.getCrypto();
    const arr = new Uint8Array(bytes);
    cryptoObj.getRandomValues(arr);
    return [ ...arr ]
      .map((b): string => `0${b.toString(16)}`.slice(-2))
      .join('');
  }

  public async pkceChallenge(verifier: string): Promise<string> {
    const data = new TextEncoder().encode(verifier);
    const digest = await this.getCrypto().subtle.digest('SHA-256', data);
    const arr = new Uint8Array(digest);
    const base64 = btoa(String.fromCodePoint(...arr));
    return base64.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
  }

  public async createClaimToken(): Promise<string> {
    await this.ensureValidToken();
    if (!this.oidcToken) {
      throw new Error('No OIDC ID token available for UMA claims.');
    }
    return this.oidcToken;
  }

  /**
   * Creates a `fetch`-compatible function that transparently handles
   * authentication. It first tries the request unauthenticated and, only on a
   * `401`, inspects the `WWW-Authenticate` header: a `UMA` challenge is
   * satisfied through the UMA flow, otherwise the request is retried with the
   * OIDC bearer token.
   *
   * The returned function accepts an optional third {@link AuthFetchOptions}
   * argument so behaviour can be tuned **per request**:
   *
   * ```ts
   * const authFetch = auth.createAuthFetch();
   *
   * // Standard authenticated request.
   * await authFetch('https://pod.example/private.txt');
   *
   * // Same request, but ask for access if it is denied.
   * await authFetch('https://pod.example/private.txt', undefined, {
   *   accessRequest: true,
   * });
   * ```
   *
   * @returns A `fetch`-like function `(input, init?, options?) => Promise<Response>`.
   */
  public createAuthFetch(): (
    input: RequestInfo | URL,
    init?: RequestInit,
    options?: AuthFetchOptions,
  ) => Promise<Response> {
    return async(
      input: RequestInfo | URL,
      init: RequestInit = {},
      options: AuthFetchOptions = {},
    ): Promise<Response> => {
      const { accessRequest = false } = options;
      const noTokenResponse = await this.fetchFn(input, init);
      if (noTokenResponse.ok) {
        return noTokenResponse;
      }

      if (noTokenResponse.status !== 401) {
        return noTokenResponse;
      }

      const wwwAuthenticateHeader =
        noTokenResponse.headers.get('WWW-Authenticate');
      const isUmaChallenge = wwwAuthenticateHeader
        ?.trim()
        .toLowerCase()
        .startsWith('uma');

      if (isUmaChallenge) {
        const challenge = parseUmaAuthenticateHeader(
          noTokenResponse.headers,
        );
        if (!challenge) {
          return noTokenResponse;
        }
        return fetchWithUma(
          input,
          init,
          {
            auth: this,
            challenge,
            accessRequest,
          },
        );
      }

      await this.ensureValidToken();
      if (!this.oidcAccessToken) {
        return noTokenResponse;
      }

      const headers = new Headers(init.headers);
      headers.set('Authorization', `Bearer ${this.oidcAccessToken}`);
      return this.fetchFn(input, { ...init, headers });
    };
  }

  public clearUmaCache(): void {
    try {
      this.umaPermissionTokens.clear();
      this.storage?.removeItem('uma_permission_tokens');
    } catch {
      /* Ignore */
    }
  }

  public clearOidcTokens(): void {
    try {
      this.oidcAccessToken = undefined;
      this.oidcToken = undefined;
      this.oidcRefreshToken = undefined;
      this.oidcTokenExpiry = undefined;
      this.webId = undefined;
      this.oidcIssuer = undefined;
      this.clientCredentials = undefined;
    } catch {
      /* Ignore */
    }
    try {
      const storage = this.storage;
      storage?.removeItem('oidc_state');
      storage?.removeItem('oidc_code_verifier');
      storage?.removeItem('oidc_issuer');
      storage?.removeItem('oidc_client_id');
      storage?.removeItem('oidc_redirect_uri');
      storage?.removeItem('oidc_tokens');
      storage?.removeItem('client_credentials');
    } catch {
      /* Ignore */
    }
  }

  public clearCache(): void {
    this.clearUmaCache();
    this.clearOidcTokens();
  }

  public extractWebId(idToken: string): string | undefined {
    try {
      const [ , payload ] = idToken.split('.');
      if (!payload) {
        return undefined;
      }
      const decoded = JSON.parse(
        atob(payload.replaceAll('-', '+').replaceAll('_', '/')),
      ) as { webid?: string; sub?: string };
      return decoded.webid ?? decoded.sub;
    } catch {
      return undefined;
    }
  }

  private buildUmaTokenKey(resourceUrl: string, method = 'GET'): string {
    return `${method.toUpperCase()} ${resourceUrl}`;
  }

  private hydrateOidcTokens(): void {
    if (!this.persistTokens || !this.storage) {
      return;
    }
    try {
      const raw = this.storage.getItem('oidc_tokens');
      if (!raw) {
        return;
      }
      const data = JSON.parse(raw) as {
        access_token?: string;
        id_token?: string;
        refresh_token?: string;
        expires_at?: number;
        web_id?: string;
      };
      this.oidcAccessToken = data.access_token;
      this.oidcToken = data.id_token;
      this.oidcRefreshToken = data.refresh_token;
      this.oidcTokenExpiry = data.expires_at;
      this.webId = data.web_id ?? (data.id_token ? this.extractWebId(data.id_token) : undefined);
      this.oidcIssuer = this.storage.getItem('oidc_issuer') ?? undefined;
    } catch {
      /* Ignore */
    }
  }

  private persistOidcTokens(): void {
    if (!this.persistTokens || !this.storage) {
      return;
    }
    try {
      const payload = {
        access_token: this.oidcAccessToken,
        id_token: this.oidcToken,
        refresh_token: this.oidcRefreshToken,
        expires_at: this.oidcTokenExpiry,
        web_id: this.webId,
      };
      this.storage.setItem('oidc_tokens', JSON.stringify(payload));
    } catch {
      /* Ignore */
    }
  }

  private hydrateClientCredentials(): void {
    if (!this.persistTokens || !this.storage) {
      return;
    }
    try {
      const raw = this.storage.getItem('client_credentials');
      if (!raw) {
        return;
      }
      const data = JSON.parse(raw) as Partial<ClientCredentials>;
      if (data.id && data.secret) {
        this.clientCredentials = {
          id: data.id,
          secret: data.secret,
          scope: data.scope ?? 'webid',
        };
      }
    } catch {
      /* Ignore */
    }
  }

  private persistClientCredentials(): void {
    if (!this.persistTokens || !this.storage) {
      return;
    }
    try {
      if (this.clientCredentials) {
        this.storage.setItem(
          'client_credentials',
          JSON.stringify(this.clientCredentials),
        );
      } else {
        this.storage.removeItem('client_credentials');
      }
    } catch {
      /* Ignore */
    }
  }

  private hydrateUmaTokens(): void {
    try {
      const raw = this.storage?.getItem('uma_permission_tokens');
      if (!raw) {
        return;
      }
      const parsed = JSON.parse(raw) as Record<string, UmaTokenCacheEntry>;
      const now = Date.now();
      for (const [ key, entry ] of Object.entries(parsed)) {
        if (!entry?.access_token) {
          continue;
        }
        if (entry.expires_at && now > entry.expires_at) {
          continue;
        }
        this.umaPermissionTokens.set(key, entry);
      }
      this.persistUmaTokens();
    } catch {
      /* Ignore */
    }
  }

  private persistUmaTokens(): void {
    const obj: Record<string, UmaTokenCacheEntry> = {};
    for (const [ key, entry ] of this.umaPermissionTokens.entries()) {
      obj[key] = entry;
    }
    try {
      this.storage?.setItem('uma_permission_tokens', JSON.stringify(obj));
    } catch {
      /* Ignore */
    }
  }

  public getStoredUmaToken(
    resourceUrl: string,
    method = 'GET',
  ): UmaTokenCacheEntry | undefined {
    const key = this.buildUmaTokenKey(resourceUrl, method);
    const entry = this.umaPermissionTokens.get(key);
    if (!entry) {
      return undefined;
    }
    if (entry.expires_at && Date.now() > entry.expires_at) {
      this.umaPermissionTokens.delete(key);
      this.persistUmaTokens();
      return undefined;
    }
    return entry;
  }

  public storeUmaToken(
    resourceUrl: string,
    method: string,
    token: { token_type: string; access_token: string; expires_in?: number },
  ): void {
    const key = this.buildUmaTokenKey(resourceUrl, method);
    const expires_at = token.expires_in ?
      Date.now() + token.expires_in * 1000 :
      undefined;
    this.umaPermissionTokens.set(key, {
      token_type: token.token_type,
      access_token: token.access_token,
      expires_at,
    });
    this.persistUmaTokens();
  }

  public getClaimResolvers(): ClaimResolverRegistry {
    return [ ...this.claimResolvers ];
  }

  public getFetch(): typeof fetch {
    return this.fetchFn;
  }

  private getStorage(): Storage {
    if (!this.storage) {
      throw new Error('Session storage is not available in this environment.');
    }
    return this.storage;
  }

  private getCrypto(): Crypto {
    if (!globalThis.crypto) {
      throw new Error('Web Crypto is not available in this environment.');
    }
    return globalThis.crypto;
  }
}

let defaultAuth: Auth | undefined;

let defaultAuthOptions: AuthOptions | undefined;

export function configureDefaultAuth(options: AuthOptions): void {
  if (defaultAuth) {
    throw new Error('Default Auth has already been created.');
  }
  defaultAuthOptions = options;
}

export function getDefaultAuth(): Auth {
  if (!defaultAuth) {
    defaultAuth = new Auth(defaultAuthOptions);
  }
  return defaultAuth;
}
