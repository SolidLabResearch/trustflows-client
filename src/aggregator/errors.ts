import type { AggregatorManagementFlow } from './types';

/**
 * Thrown when a request to the Aggregator management API fails.
 */
export class AggregatorManagementError extends Error {
  public readonly status: number;
  public readonly payload?: unknown;

  public constructor(message: string, status: number, payload?: unknown) {
    super(message);
    this.name = 'AggregatorManagementError';
    this.status = status;
    this.payload = payload;
  }
}

/**
 * Thrown when a request to an Aggregator service resource fails.
 */
export class AggregatorServiceError extends Error {
  public readonly status: number;
  public readonly payload?: unknown;

  public constructor(message: string, status: number, payload?: unknown) {
    super(message);
    this.name = 'AggregatorServiceError';
    this.status = status;
    this.payload = payload;
  }
}

/**
 * Thrown when an {@link Aggregator} method is used before `init()` completed.
 */
export class AggregatorNotInitializedError extends Error {
  public constructor() {
    super('Aggregator is not initialized; call init() first.');
    this.name = 'AggregatorNotInitializedError';
  }
}

/**
 * Thrown by `init()` when an interactive management flow
 * (`authorization_code` / `device_code`) needs the user to act before an
 * instance can be created or its tokens refreshed. Resolve it by driving the
 * creation flow, then call `init()` again.
 */
export class AggregatorAuthorizationRequiredError extends Error {
  public readonly flow: AggregatorManagementFlow;
  public readonly reason: 'create' | 'token-update';
  public readonly aggregator?: string;

  public constructor(
    flow: AggregatorManagementFlow,
    reason: 'create' | 'token-update',
    aggregator?: string,
  ) {
    super(
      `Aggregator ${reason === 'create' ? 'creation' : 'token update'} ` +
      `requires the interactive "${flow}" flow.`,
    );
    this.name = 'AggregatorAuthorizationRequiredError';
    this.flow = flow;
    this.reason = reason;
    this.aggregator = aggregator;
  }
}
