import type { AggregatorManagementFlow, ServiceInfo } from './types';

const INSTANCES_KEY = 'aggregator_instances';
const SERVICES_KEY = 'aggregator_services';

/**
 * A cached Aggregator Instance, keyed by server URL and user WebID.
 */
export interface CachedInstance {
  aggregator: string;
  flow: AggregatorManagementFlow;
  subject?: string;
  idp?: string;
}

function instanceKey(serverUrl: string, webId: string): string {
  return `${serverUrl}::${webId}`;
}

function serviceKey(instanceUrl: string, requestKey: string): string {
  return `${instanceUrl}::${requestKey}`;
}

/**
 * A small cache for discovered Aggregator Instances and Services. It always
 * keeps an in-memory mirror and, when enabled, persists JSON blobs to `storage`
 * so discovery can be skipped across sessions.
 */
export class AggregatorCache {
  private readonly storage?: Storage;
  private readonly enabled: boolean;
  private readonly instances = new Map<string, CachedInstance>();
  private readonly services = new Map<string, ServiceInfo>();

  public constructor(options: { storage?: Storage; enabled: boolean }) {
    this.enabled = options.enabled;
    this.storage = this.enabled ?
      options.storage ??
      (typeof localStorage === 'undefined' ? undefined : localStorage) :
      undefined;
    this.hydrate(INSTANCES_KEY, this.instances);
    this.hydrate(SERVICES_KEY, this.services);
  }

  public getInstance(serverUrl: string, webId: string): CachedInstance | undefined {
    return this.instances.get(instanceKey(serverUrl, webId));
  }

  public setInstance(
    serverUrl: string,
    webId: string,
    instance: CachedInstance,
  ): void {
    this.instances.set(instanceKey(serverUrl, webId), instance);
    this.persist(INSTANCES_KEY, this.instances);
  }

  public clearInstance(serverUrl: string, webId: string): void {
    this.instances.delete(instanceKey(serverUrl, webId));
    this.persist(INSTANCES_KEY, this.instances);
  }

  public getService(instanceUrl: string, requestKey: string): ServiceInfo | undefined {
    return this.services.get(serviceKey(instanceUrl, requestKey));
  }

  public setService(
    instanceUrl: string,
    requestKey: string,
    info: ServiceInfo,
  ): void {
    this.services.set(serviceKey(instanceUrl, requestKey), info);
    this.persist(SERVICES_KEY, this.services);
  }

  public clearService(instanceUrl: string, requestKey: string): void {
    this.services.delete(serviceKey(instanceUrl, requestKey));
    this.persist(SERVICES_KEY, this.services);
  }

  /**
   * Removes any cached service entries that point at the given Service
   * Description URL (used after a service is deleted).
   */
  public clearServiceByUrl(serviceUrl: string): void {
    let changed = false;
    for (const [ key, info ] of this.services) {
      if (info.service === serviceUrl) {
        this.services.delete(key);
        changed = true;
      }
    }
    if (changed) {
      this.persist(SERVICES_KEY, this.services);
    }
  }

  private hydrate<T>(key: string, target: Map<string, T>): void {
    if (!this.storage) {
      return;
    }
    try {
      const raw = this.storage.getItem(key);
      if (!raw) {
        return;
      }
      const parsed = JSON.parse(raw) as Record<string, T>;
      for (const [ entryKey, value ] of Object.entries(parsed)) {
        target.set(entryKey, value);
      }
    } catch {
      /* Ignore */
    }
  }

  private persist<T>(key: string, source: Map<string, T>): void {
    if (!this.storage) {
      return;
    }
    try {
      const obj: Record<string, T> = {};
      for (const [ entryKey, value ] of source) {
        obj[entryKey] = value;
      }
      this.storage.setItem(key, JSON.stringify(obj));
    } catch {
      /* Ignore */
    }
  }
}
