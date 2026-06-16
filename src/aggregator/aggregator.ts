/* eslint-disable @typescript-eslint/naming-convention */
import type { Auth } from '../auth';
import { AggregatorCache } from './cache';
import {
  AggregatorAuthorizationRequiredError,
  AggregatorManagementError,
  AggregatorNotInitializedError,
  AggregatorServiceError,
} from './errors';
import {
  type AggregatorFetch,
  createInstance,
  type CreateInstanceResult,
  deleteInstance,
  fetchAggregatorDescription,
  fetchServerDescription,
  finishAuthorizationCode,
  listInstances,
  pollDeviceCode,
  selectRequestFormat,
  startAuthorizationCode,
  startDeviceCode,
} from './management';
import {
  serviceMatchesRequest,
  serviceRequestKey,
  toServiceInfo,
} from './rdf';
import {
  deleteService,
  deployService,
  fetchServiceCollection,
  loadServiceDescription,
} from './services';
import type {
  AggregatorCreationStep,
  AggregatorDescription,
  AggregatorManagementFlow,
  AggregatorOptions,
  AggregatorServerDescription,
  FinishCreationParams,
  ServiceInfo,
  ServiceRequest,
  StartCreationOptions,
} from './types';

const DEFAULT_SCOPE = 'openid webid offline_access';
const PENDING_KEY = 'aggregator_pending_creation';

interface PendingCreation {
  serverUrl: string;
  flow: AggregatorManagementFlow;
  state: string;
  redirectUri?: string;
  aggregator?: string;
  interval?: number;
  expiresAt?: number;
}

/**
 * Manages a single Aggregator Instance: it discovers, creates, and deletes the
 * instance for the authenticated user, and manages the services deployed on it.
 * Call `init()` before using the service methods. Interactive creation flows
 * (`authorization_code` / `device_code`) are driven with `startCreation()` and
 * `finishCreation()`.
 */
export class Aggregator {
  public serverDescription?: AggregatorServerDescription;
  public description?: AggregatorDescription;

  private readonly auth: Auth;
  private readonly serverUrl: string;
  private readonly creationFlow?: AggregatorManagementFlow;
  private readonly authorizationServer?: string;
  private readonly authFetch: AggregatorFetch;
  private readonly cache: AggregatorCache;
  private readonly stateStorage?: Storage;

  private internalInstanceUrl?: string;
  private flow?: AggregatorManagementFlow;
  private requestFormat?: string;
  private webId?: string;
  private initialized = false;
  private initPromise?: Promise<void>;
  private instanceFromCache = false;

  public constructor(options: AggregatorOptions) {
    this.auth = options.auth;
    this.serverUrl = options.serverUrl;
    this.creationFlow = options.creationFlow;
    this.authorizationServer = options.authorizationServer;
    this.authFetch = options.auth.createAuthFetch();
    this.cache = new AggregatorCache({
      storage: options.storage,
      enabled: options.cache ?? true,
    });
    this.stateStorage =
      options.storage ??
      (typeof localStorage === 'undefined' ? undefined : localStorage);
  }

  /**
   * The Aggregator Instance (Aggregator Description) URL, once initialized.
   */
  public get instanceUrl(): string | undefined {
    return this.internalInstanceUrl;
  }

  /**
   * Discovers or creates the Aggregator Instance for the authenticated user:
   * it reuses a cached instance, otherwise lists the user's instances (using
   * the first), otherwise creates one with a non-interactive flow. Interactive
   * flows throw {@link AggregatorAuthorizationRequiredError}. After resolving
   * the instance, the token validity is checked.
   */
  public async init(): Promise<void> {
    if (this.initialized) {
      return;
    }
    this.initPromise ??= this.runInit();
    try {
      await this.initPromise;
      this.initialized = true;
    } finally {
      this.initPromise = undefined;
    }
  }

  /**
   * Deletes the Aggregator Instance and clears it from the cache.
   */
  public async delete(): Promise<void> {
    this.ensureInitialized();
    await deleteInstance(
      this.authFetch,
      this.serverDescription!.management_endpoint,
      this.internalInstanceUrl!,
      this.requestFormat!,
    );
    if (this.webId) {
      this.cache.clearInstance(this.serverUrl, this.webId);
    }
    this.initialized = false;
    this.internalInstanceUrl = undefined;
    this.description = undefined;
  }

  /**
   * Starts creating (or re-authenticating) an Aggregator Instance. For the
   * non-interactive flows (`none` / `provision`) the instance is created
   * immediately and `{ type: 'done' }` is returned. For interactive flows it
   * returns a `redirect` or `device` step the caller must act on, then call
   * {@link Aggregator.finishCreation}. When an instance already exists, the
   * flow performs a token update instead of creating a new instance.
   */
  public async startCreation(
    options: StartCreationOptions = {},
  ): Promise<AggregatorCreationStep> {
    const { webId, serverDescription, flow, format } = await this.ensureServerContext();
    const endpoint = serverDescription.management_endpoint;
    const existing =
      this.internalInstanceUrl ?? this.cache.getInstance(this.serverUrl, webId)?.aggregator;

    if (flow === 'none' || flow === 'provision') {
      if (existing) {
        return { type: 'done', aggregator: existing };
      }
      const created = await createInstance(this.authFetch, endpoint, flow, format);
      this.cacheInstance(webId, created, flow);
      return { type: 'done', aggregator: created.aggregator };
    }

    const authorizationServer = options.authorizationServer ?? this.authorizationServer;
    if (!authorizationServer) {
      throw new Error(
        `The "${flow}" flow requires an authorizationServer.`,
      );
    }

    if (flow === 'authorization_code') {
      if (!options.redirectUri) {
        throw new Error('The authorization_code flow requires a redirectUri.');
      }
      const start = await startAuthorizationCode(
        this.authFetch,
        endpoint,
        format,
        authorizationServer,
        existing,
      );
      const authorizationEndpoint =
        start.authorization_endpoint ??
        await this.discoverAuthorizationEndpoint(start.issuer);
      const authorizationUrl = this.buildAuthorizationUrl(authorizationEndpoint, {
        clientId: start.aggregator_client_id,
        redirectUri: options.redirectUri,
        scope: options.scope ?? DEFAULT_SCOPE,
        state: start.state,
        codeChallenge: start.code_challenge,
        codeChallengeMethod: start.code_challenge_method,
      });
      this.savePending({
        serverUrl: this.serverUrl,
        flow,
        state: start.state,
        redirectUri: options.redirectUri,
        aggregator: existing,
      });
      return { type: 'redirect', authorizationUrl, state: start.state };
    }

    const start = await startDeviceCode(
      this.authFetch,
      endpoint,
      format,
      authorizationServer,
      existing,
    );
    this.savePending({
      serverUrl: this.serverUrl,
      flow,
      state: start.state,
      aggregator: existing,
      interval: start.interval,
      expiresAt: Date.now() + start.expires_in * 1000,
    });
    return {
      type: 'device',
      user_code: start.user_code,
      verification_uri: start.verification_uri,
      ...start.verification_uri_complete ?
          { verification_uri_complete: start.verification_uri_complete } :
          {},
      expires_in: start.expires_in,
      interval: start.interval ?? 5,
      state: start.state,
    };
  }

  /**
   * Finishes an interactive creation flow started by
   * {@link Aggregator.startCreation}: it redeems the authorization code
   * (authorization_code) or polls until the device flow completes (device_code),
   * then loads the instance and marks the aggregator initialized.
   */
  public async finishCreation(params: FinishCreationParams = {}): Promise<void> {
    const { webId, serverDescription, format } = await this.ensureServerContext();
    const pending = this.readPending();
    if (!pending) {
      throw new Error('No pending Aggregator creation to finish.');
    }
    const endpoint = serverDescription.management_endpoint;

    let result: CreateInstanceResult;
    if (pending.flow === 'authorization_code') {
      const code = params.code ?? readQueryParam('code');
      const state = params.state ?? readQueryParam('state') ?? pending.state;
      if (!code) {
        throw new Error('An authorization code is required to finish the flow.');
      }
      if (state !== pending.state) {
        throw new Error('State mismatch while finishing the authorization_code flow.');
      }
      if (!pending.redirectUri) {
        throw new Error('Missing redirect URI for the authorization_code flow.');
      }
      result = await finishAuthorizationCode(this.authFetch, endpoint, format, {
        code,
        redirectUri: pending.redirectUri,
        state,
        aggregator: pending.aggregator,
      });
    } else if (pending.flow === 'device_code') {
      result = await this.pollUntilComplete(endpoint, format, pending, params.signal);
    } else {
      throw new Error(`Cannot finish the non-interactive "${pending.flow}" flow.`);
    }

    this.clearPending();
    this.cacheInstance(webId, result, pending.flow);
    await this.loadAndFinalize(result.aggregator, pending.flow);
  }

  /**
   * Finds an existing service that satisfies the request or deploys a new one.
   * Resolution order: cache, then a scan of the Service Collection (following
   * each Service Description and matching the transformation, implementation,
   * and parameter bindings), then deployment. The result is cached.
   */
  public async getService(request: ServiceRequest): Promise<ServiceInfo> {
    this.ensureInitialized();
    const key = serviceRequestKey(request);

    const cached = this.cache.getService(this.internalInstanceUrl!, key);
    if (cached) {
      return cached;
    }

    return this.resolveService(request, key, true);
  }

  /**
   * Resolves a service against the live instance: scans the Service Collection
   * for a match and deploys it otherwise. If the instance was destroyed (its
   * collection endpoint 404s), it is rediscovered or recreated once, then the
   * resolution is retried against the new instance.
   */
  private async resolveService(
    request: ServiceRequest,
    key: string,
    allowInstanceRecovery: boolean,
  ): Promise<ServiceInfo> {
    const collectionUrl = this.serviceCollectionEndpoint();
    let services: string[];
    let acceptPost: string | undefined;
    try {
      ({ services, acceptPost } = await fetchServiceCollection(
        this.authFetch,
        collectionUrl,
      ));
    } catch (error: unknown) {
      if (!allowInstanceRecovery || !isNotFound(error)) {
        throw error;
      }
      await this.recoverInstance();
      return this.resolveService(request, key, false);
    }

    for (const serviceUrl of services) {
      // Sequential so the scan can stop at the first matching service.

      const parsed = await loadServiceDescription(this.authFetch, serviceUrl);
      if (serviceMatchesRequest(parsed, request)) {
        const info = toServiceInfo(parsed);
        this.cache.setService(this.internalInstanceUrl!, key, info);
        return info;
      }
    }

    const deployed = await deployService(
      this.authFetch,
      collectionUrl,
      request,
      acceptPost,
    );
    const info = toServiceInfo(deployed);
    this.cache.setService(this.internalInstanceUrl!, key, info);
    return info;
  }

  /**
   * Returns every service currently in the Service Collection.
   */
  public async getServiceCollection(): Promise<ServiceInfo[]> {
    this.ensureInitialized();
    const { services } = await fetchServiceCollection(
      this.authFetch,
      this.serviceCollectionEndpoint(),
    );
    return Promise.all(
      services.map(async(serviceUrl): Promise<ServiceInfo> =>
        toServiceInfo(await loadServiceDescription(this.authFetch, serviceUrl))),
    );
  }

  /**
   * Deletes a service by its Service Description URL and clears it from the
   * cache.
   */
  public async deleteService(serviceUrl: string): Promise<void> {
    this.ensureInitialized();
    await deleteService(this.authFetch, serviceUrl);
    this.cache.clearServiceByUrl(serviceUrl);
  }

  private serviceCollectionEndpoint(): string {
    const endpoint = this.description?.service_collection_endpoint;
    if (!endpoint) {
      throw new Error('Aggregator Description has no service_collection_endpoint.');
    }
    return endpoint;
  }

  private async ensureServerContext(): Promise<{
    webId: string;
    serverDescription: AggregatorServerDescription;
    flow: AggregatorManagementFlow;
    format: string;
  }> {
    if (!this.auth.webId) {
      await this.auth.isLoggedIn();
    }
    const webId = this.auth.webId;
    if (!webId) {
      throw new Error('Aggregator requires a logged-in user (no WebID).');
    }
    this.webId = webId;

    const serverDescription =
      this.serverDescription ??
      await fetchServerDescription(this.authFetch, this.serverUrl);
    this.serverDescription = serverDescription;

    const format =
      this.requestFormat ??
      selectRequestFormat(serverDescription.supported_management_request_formats);
    this.requestFormat = format;

    const flow =
      this.creationFlow ??
      this.cache.getInstance(this.serverUrl, webId)?.flow ??
      serverDescription.supported_management_flows[0];
    if (!flow) {
      throw new Error('Aggregator Server advertises no management flows.');
    }
    this.flow = flow;

    return { webId, serverDescription, flow, format };
  }

  private cacheInstance(
    webId: string,
    result: { aggregator: string; subject?: string; idp?: string },
    flow: AggregatorManagementFlow,
  ): void {
    this.cache.setInstance(this.serverUrl, webId, {
      aggregator: result.aggregator,
      flow,
      ...result.subject ? { subject: result.subject } : {},
      ...result.idp ? { idp: result.idp } : {},
    });
  }

  private async loadAndFinalize(
    instanceUrl: string,
    flow: AggregatorManagementFlow,
  ): Promise<void> {
    this.flow = flow;
    this.internalInstanceUrl = instanceUrl;
    this.description = await fetchAggregatorDescription(this.authFetch, instanceUrl);
    this.initialized = true;
  }

  private async pollUntilComplete(
    endpoint: string,
    format: string,
    pending: PendingCreation,
    signal?: AbortSignal,
  ): Promise<CreateInstanceResult> {
    const intervalMs = Math.max(pending.interval ?? 5, 1) * 1000;
    while (true) {
      if (signal?.aborted) {
        throw new Error('Device authorization polling was aborted.');
      }
      if (pending.expiresAt && Date.now() > pending.expiresAt) {
        throw new Error('Device authorization session expired.');
      }

      const result = await pollDeviceCode(
        this.authFetch,
        endpoint,
        format,
        pending.state,
        pending.aggregator,
      );
      if (result.status !== 202 && result.aggregator) {
        return { aggregator: result.aggregator };
      }

      await delay(intervalMs, signal);
    }
  }

  private async discoverAuthorizationEndpoint(issuerHint?: string): Promise<string> {
    const issuer = issuerHint ?? this.auth.issuer;
    if (!issuer) {
      throw new Error('Cannot determine the IdP issuer for the authorization_code flow.');
    }
    const config = await this.auth.getOidcConfig(issuer);
    if (!config.authorization_endpoint) {
      throw new Error('IdP configuration is missing an authorization_endpoint.');
    }
    return config.authorization_endpoint;
  }

  private buildAuthorizationUrl(
    authorizationEndpoint: string,
    params: {
      clientId: string;
      redirectUri: string;
      scope: string;
      state: string;
      codeChallenge: string;
      codeChallengeMethod: string;
    },
  ): string {
    const search = new URLSearchParams({
      response_type: 'code',
      client_id: params.clientId,
      redirect_uri: params.redirectUri,
      scope: params.scope,
      state: params.state,
      code_challenge: params.codeChallenge,
      code_challenge_method: params.codeChallengeMethod,
    });
    return `${authorizationEndpoint}?${search.toString()}`;
  }

  private savePending(pending: PendingCreation): void {
    this.stateStorage?.setItem(PENDING_KEY, JSON.stringify(pending));
  }

  private readPending(): PendingCreation | undefined {
    try {
      const raw = this.stateStorage?.getItem(PENDING_KEY);
      if (!raw) {
        return undefined;
      }
      const pending = JSON.parse(raw) as PendingCreation;
      return pending.serverUrl === this.serverUrl ? pending : undefined;
    } catch {
      return undefined;
    }
  }

  private clearPending(): void {
    this.stateStorage?.removeItem(PENDING_KEY);
  }

  private async runInit(): Promise<void> {
    if (!this.auth.webId) {
      await this.auth.isLoggedIn();
    }
    const webId = this.auth.webId;
    if (!webId) {
      throw new Error('Aggregator requires a logged-in user (no WebID).');
    }
    this.webId = webId;

    const serverDescription = await fetchServerDescription(this.authFetch, this.serverUrl);
    this.serverDescription = serverDescription;
    this.requestFormat = selectRequestFormat(
      serverDescription.supported_management_request_formats,
    );

    const instanceUrl = await this.resolveInstance(webId, serverDescription);
    this.internalInstanceUrl = instanceUrl;

    const description = await this.loadInstanceDescription(webId, serverDescription);
    this.description = description;

    if (this.isTokenInvalid(description) && this.isInteractiveFlow()) {
      throw new AggregatorAuthorizationRequiredError(
        this.flow!,
        'token-update',
        this.internalInstanceUrl,
      );
    }
  }

  /**
   * Fetches the description of the resolved instance. When the instance came
   * from the cache but the server reports it is gone (404), the stale entry is
   * dropped and the instance is rediscovered (or recreated) before retrying.
   */
  private async loadInstanceDescription(
    webId: string,
    serverDescription: AggregatorServerDescription,
  ): Promise<AggregatorDescription> {
    try {
      return await fetchAggregatorDescription(this.authFetch, this.internalInstanceUrl!);
    } catch (error: unknown) {
      if (!this.instanceFromCache || !isNotFound(error)) {
        throw error;
      }
      this.cache.clearInstance(this.serverUrl, webId);
      this.internalInstanceUrl =
        await this.resolveInstance(webId, serverDescription, true);
      return fetchAggregatorDescription(this.authFetch, this.internalInstanceUrl);
    }
  }

  /**
   * Re-resolves the Aggregator Instance after the cached one was found to be
   * destroyed, forcing rediscovery (and creation when none exist) and
   * refreshing the cached description so the service endpoints point at it.
   */
  private async recoverInstance(): Promise<void> {
    this.cache.clearInstance(this.serverUrl, this.webId!);
    this.internalInstanceUrl =
      await this.resolveInstance(this.webId!, this.serverDescription!, true);
    this.description =
      await fetchAggregatorDescription(this.authFetch, this.internalInstanceUrl);
  }

  private async resolveInstance(
    webId: string,
    serverDescription: AggregatorServerDescription,
    forceDiscovery = false,
  ): Promise<string> {
    if (!forceDiscovery) {
      const cached = this.cache.getInstance(this.serverUrl, webId);
      if (cached) {
        this.flow = cached.flow;
        this.instanceFromCache = true;
        return cached.aggregator;
      }
    }
    this.instanceFromCache = false;

    this.flow = this.creationFlow ?? serverDescription.supported_management_flows[0];
    if (!this.flow) {
      throw new Error('Aggregator Server advertises no management flows.');
    }

    const existing = await listInstances(
      this.authFetch,
      serverDescription.management_endpoint,
    );
    if (existing.length > 0) {
      this.cacheInstance(webId, { aggregator: existing[0] }, this.flow);
      return existing[0];
    }

    if (this.isInteractiveFlow()) {
      throw new AggregatorAuthorizationRequiredError(this.flow, 'create');
    }

    const created = await createInstance(
      this.authFetch,
      serverDescription.management_endpoint,
      this.flow,
      this.requestFormat!,
    );
    this.cacheInstance(webId, created, this.flow);
    return created.aggregator;
  }

  private isInteractiveFlow(): boolean {
    return this.flow === 'authorization_code' || this.flow === 'device_code';
  }

  private isTokenInvalid(description: AggregatorDescription): boolean {
    if (!description.login_status) {
      return true;
    }
    if (description.token_expiry) {
      const expiry = Date.parse(description.token_expiry);
      if (!Number.isNaN(expiry) && expiry <= Date.now()) {
        return true;
      }
    }
    return false;
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new AggregatorNotInitializedError();
    }
  }
}

async function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject): void => {
    let timer: ReturnType<typeof setTimeout>;
    function onAbort(): void {
      clearTimeout(timer);
      reject(new Error('Device authorization polling was aborted.'));
    }
    if (signal?.aborted) {
      onAbort();
      return;
    }
    timer = setTimeout((): void => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function readQueryParam(name: string): string | undefined {
  if (typeof window === 'undefined') {
    return undefined;
  }
  return new URL(window.location.href).searchParams.get(name) ?? undefined;
}

/**
 * Whether an Aggregator error represents a missing (404) resource, used to
 * detect that a cached instance or service was destroyed server-side.
 */
function isNotFound(error: unknown): boolean {
  return (
    (error instanceof AggregatorManagementError ||
      error instanceof AggregatorServiceError) &&
      error.status === 404
  );
}
