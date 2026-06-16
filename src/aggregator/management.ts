/* eslint-disable @typescript-eslint/naming-convention */
import { safeJson } from '../utils';
import { AggregatorManagementError } from './errors';
import type {
  AggregatorDescription,
  AggregatorManagementFlow,
  AggregatorServerDescription,
} from './types';

/**
 * A `fetch`-compatible function (typically `Auth.createAuthFetch()`), which
 * transparently handles both OIDC and UMA authentication.
 */
export type AggregatorFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const JSON_FORMAT = 'application/json';
const FORM_FORMAT = 'application/x-www-form-urlencoded';

/**
 * Picks a request format the client can encode, preferring JSON.
 */
export function selectRequestFormat(formats: string[]): string {
  if (formats.includes(JSON_FORMAT)) {
    return JSON_FORMAT;
  }
  if (formats.includes(FORM_FORMAT)) {
    return FORM_FORMAT;
  }
  throw new Error(
    `No supported management request format in: ${formats.join(', ')}.`,
  );
}

function encodeBody(
  body: Record<string, string>,
  format: string,
): { body: string; contentType: string } {
  if (format === FORM_FORMAT) {
    return { body: new URLSearchParams(body).toString(), contentType: FORM_FORMAT };
  }
  return { body: JSON.stringify(body), contentType: JSON_FORMAT };
}

/**
 * Fetches the Aggregator Server Description from the server base URL.
 */
export async function fetchServerDescription(
  authFetch: AggregatorFetch,
  serverUrl: string,
): Promise<AggregatorServerDescription> {
  const res = await authFetch(serverUrl, { headers: { accept: JSON_FORMAT }});
  if (!res.ok) {
    throw new AggregatorManagementError(
      `Failed to fetch Aggregator Server Description (${res.status}).`,
      res.status,
    );
  }
  const data = await safeJson<AggregatorServerDescription>(res);
  if (!data?.management_endpoint) {
    throw new AggregatorManagementError(
      'Aggregator Server Description is missing a management_endpoint.',
      res.status,
      data,
    );
  }
  return data;
}

/**
 * Lists the Aggregator Description URLs created by the authenticated user.
 */
export async function listInstances(
  authFetch: AggregatorFetch,
  managementEndpoint: string,
): Promise<string[]> {
  const res = await authFetch(managementEndpoint, { headers: { accept: JSON_FORMAT }});
  if (!res.ok) {
    throw new AggregatorManagementError(
      `Failed to list Aggregator Instances (${res.status}).`,
      res.status,
    );
  }
  return await safeJson<string[]>(res) ?? [];
}

/**
 * The result of creating (or re-authenticating) an Aggregator Instance.
 */
export interface CreateInstanceResult {
  aggregator: string;
  subject?: string;
  idp?: string;
}

/**
 * Creates an Aggregator Instance using a non-interactive flow (`none` or
 * `provision`).
 */
export async function createInstance(
  authFetch: AggregatorFetch,
  managementEndpoint: string,
  flow: AggregatorManagementFlow,
  format: string,
): Promise<CreateInstanceResult> {
  const { body, contentType } = encodeBody({ management_flow: flow }, format);
  const res = await authFetch(managementEndpoint, {
    method: 'POST',
    headers: { 'content-type': contentType, accept: JSON_FORMAT },
    body,
  });
  if (res.status !== 201) {
    throw new AggregatorManagementError(
      `Failed to create Aggregator Instance (${res.status}).`,
      res.status,
      await safeJson(res),
    );
  }
  const data = await safeJson<CreateInstanceResult>(res);
  if (!data?.aggregator) {
    throw new AggregatorManagementError(
      'Aggregator creation response is missing the "aggregator" member.',
      res.status,
      data,
    );
  }
  return data;
}

/**
 * Deletes an Aggregator Instance.
 */
export async function deleteInstance(
  authFetch: AggregatorFetch,
  managementEndpoint: string,
  instanceUrl: string,
  format: string,
): Promise<void> {
  const { body, contentType } = encodeBody({ aggregator: instanceUrl }, format);
  const res = await authFetch(managementEndpoint, {
    method: 'DELETE',
    headers: { 'content-type': contentType },
    body,
  });
  if (res.status !== 204 && !res.ok) {
    throw new AggregatorManagementError(
      `Failed to delete Aggregator Instance (${res.status}).`,
      res.status,
      await safeJson(res),
    );
  }
}

/**
 * Fetches the Aggregator Instance Description (JSON).
 */
export async function fetchAggregatorDescription(
  authFetch: AggregatorFetch,
  instanceUrl: string,
): Promise<AggregatorDescription> {
  const res = await authFetch(instanceUrl, { headers: { accept: JSON_FORMAT }});
  if (!res.ok) {
    throw new AggregatorManagementError(
      `Failed to fetch Aggregator Description (${res.status}).`,
      res.status,
    );
  }
  const data = await safeJson<AggregatorDescription>(res);
  if (!data) {
    throw new AggregatorManagementError(
      'Aggregator Description response was empty.',
      res.status,
    );
  }
  return data;
}

async function postManagement(
  authFetch: AggregatorFetch,
  endpoint: string,
  fields: Record<string, string>,
  format: string,
): Promise<Response> {
  const { body, contentType } = encodeBody(fields, format);
  return authFetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': contentType, accept: JSON_FORMAT },
    body,
  });
}

/**
 * The public parameters returned when starting an `authorization_code` flow.
 */
export interface AuthorizationCodeStart {
  aggregator_client_id: string;
  code_challenge: string;
  code_challenge_method: string;
  state: string;
  issuer?: string;
  authorization_endpoint?: string;
}

/**
 * Starts an `authorization_code` management flow.
 */
export async function startAuthorizationCode(
  authFetch: AggregatorFetch,
  endpoint: string,
  format: string,
  authorizationServer: string,
  aggregator?: string,
): Promise<AuthorizationCodeStart> {
  const res = await postManagement(authFetch, endpoint, {
    management_flow: 'authorization_code',
    authorization_server: authorizationServer,
    ...aggregator ? { aggregator } : {},
  }, format);
  if (res.status !== 201) {
    throw new AggregatorManagementError(
      `Failed to start authorization_code flow (${res.status}).`,
      res.status,
      await safeJson(res),
    );
  }
  const data = await safeJson<AuthorizationCodeStart>(res);
  if (!data?.aggregator_client_id || !data.state) {
    throw new AggregatorManagementError(
      'authorization_code start response is missing required members.',
      res.status,
      data,
    );
  }
  return data;
}

/**
 * Finishes an `authorization_code` management flow by redeeming the code.
 */
export async function finishAuthorizationCode(
  authFetch: AggregatorFetch,
  endpoint: string,
  format: string,
  params: { code: string; redirectUri: string; state: string; aggregator?: string },
): Promise<CreateInstanceResult> {
  const res = await postManagement(authFetch, endpoint, {
    management_flow: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    state: params.state,
    ...params.aggregator ? { aggregator: params.aggregator } : {},
  }, format);
  if (res.status !== 201 && res.status !== 200) {
    throw new AggregatorManagementError(
      `Failed to finish authorization_code flow (${res.status}).`,
      res.status,
      await safeJson(res),
    );
  }
  const data = await safeJson<CreateInstanceResult>(res);
  if (!data?.aggregator) {
    throw new AggregatorManagementError(
      'authorization_code finish response is missing the "aggregator" member.',
      res.status,
      data,
    );
  }
  return data;
}

/**
 * The parameters returned when starting a `device_code` flow.
 */
export interface DeviceCodeStart {
  state: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval?: number;
}

/**
 * Starts a `device_code` management flow.
 */
export async function startDeviceCode(
  authFetch: AggregatorFetch,
  endpoint: string,
  format: string,
  authorizationServer: string,
  aggregator?: string,
): Promise<DeviceCodeStart> {
  const res = await postManagement(authFetch, endpoint, {
    management_flow: 'device_code',
    authorization_server: authorizationServer,
    ...aggregator ? { aggregator } : {},
  }, format);
  if (res.status !== 201) {
    throw new AggregatorManagementError(
      `Failed to start device_code flow (${res.status}).`,
      res.status,
      await safeJson(res),
    );
  }
  const data = await safeJson<DeviceCodeStart>(res);
  if (!data?.state || !data.user_code || !data.verification_uri) {
    throw new AggregatorManagementError(
      'device_code start response is missing required members.',
      res.status,
      data,
    );
  }
  return data;
}

/**
 * The result of a single `device_code` poll: `202` means pending, otherwise the
 * Aggregator Instance was created/updated.
 */
export interface DevicePollResult {
  status: number;
  aggregator?: string;
}

/**
 * Polls a `device_code` management flow once.
 */
export async function pollDeviceCode(
  authFetch: AggregatorFetch,
  endpoint: string,
  format: string,
  state: string,
  aggregator?: string,
): Promise<DevicePollResult> {
  const res = await postManagement(authFetch, endpoint, {
    management_flow: 'device_code',
    state,
    ...aggregator ? { aggregator } : {},
  }, format);
  if (res.status === 202) {
    return { status: 202 };
  }
  if (res.status === 201 || res.status === 200) {
    const data = await safeJson<CreateInstanceResult>(res);
    if (!data?.aggregator) {
      throw new AggregatorManagementError(
        'device_code poll response is missing the "aggregator" member.',
        res.status,
        data,
      );
    }
    return { status: res.status, aggregator: data.aggregator };
  }
  throw new AggregatorManagementError(
    `device_code flow failed (${res.status}).`,
    res.status,
    await safeJson(res),
  );
}
