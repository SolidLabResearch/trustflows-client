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

export interface AuthOptions {
  fetch?: typeof fetch;
  storage?: Storage;
  claimResolvers?: ClaimResolverRegistry;
  persistTokens?: boolean;
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

export class Auth {
  public oidcAccessToken?: string;
  public oidcToken?: string;
  public oidcRefreshToken?: string;
  public oidcTokenExpiry?: number;
  public webId?: string;
  public umaPermissionTokens = new Map<string, UmaTokenCacheEntry>();

  private readonly fetchFn: typeof fetch;
  private readonly storage?: Storage;
  private readonly claimResolvers: ClaimResolverRegistry;
  private readonly persistTokens: boolean;
  private oidcIssuer?: string;

  public constructor(options: AuthOptions = {}) {
    this.fetchFn = options.fetch ?? fetch;
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

    window.location.href = `${config.authorization_endpoint}?${params.toString()}`;
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

    window.location.href = logoutUrl;
  }

  public async handleIncomingRedirect(): Promise<boolean> {
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

    const tokenJson = (await tokenResp.json()) as {
      access_token?: string;
      id_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };

    this.oidcAccessToken = tokenJson.access_token;
    this.oidcToken = tokenJson.id_token;
    this.oidcRefreshToken = tokenJson.refresh_token;
    if (tokenJson.expires_in) {
      this.oidcTokenExpiry = Date.now() + tokenJson.expires_in * 1000;
    }
    if (tokenJson.id_token) {
      this.webId = this.extractWebId(tokenJson.id_token);
    }
    this.persistOidcTokens();

    window.history.replaceState({}, document.title, redirectUri);
    return true;
  }

  public async isLoggedIn(): Promise<boolean> {
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
    const json = (await resp.json()) as {
      access_token?: string;
      id_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };
    if (json.access_token) {
      this.oidcAccessToken = json.access_token;
    }
    if (json.id_token) {
      this.oidcToken = json.id_token;
      this.webId = this.extractWebId(json.id_token);
    }
    if (json.refresh_token) {
      this.oidcRefreshToken = json.refresh_token;
    }
    if (json.expires_in) {
      this.oidcTokenExpiry = Date.now() + json.expires_in * 1000;
    }
    this.persistOidcTokens();
  }

  public async ensureValidToken(): Promise<void> {
    if (!this.oidcTokenExpiry || !this.oidcRefreshToken) {
      return;
    }
    if (Date.now() < this.oidcTokenExpiry - 60_000) {
      return;
    }

    const storage = this.getStorage();
    const issuer = storage.getItem('oidc_issuer');
    const clientId = storage.getItem('oidc_client_id');
    if (!issuer || !clientId) {
      return;
    }

    const config = await this.getOidcConfig(issuer);
    if (!config.token_endpoint) {
      return;
    }
    await this.refreshTokens(config.token_endpoint, clientId);
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

  public createAuthFetch(): (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => Promise<Response> {
    return async(
      input: RequestInfo | URL,
      init: RequestInit = {},
    ): Promise<Response> => {
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
