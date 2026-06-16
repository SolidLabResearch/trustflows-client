# trustflows-client

Trustflows client helpers for Solid applications. This package provides a lightweight browser-first auth helper plus 
UMA utilities for Trustflows-compatible services.

## Install

```bash
npm install trustflows-client
```

## Auth basics

Make sure a dereferenceable Client ID exists for this application. Make sure the resource server can get this JSON-LD
file, and that client_id is the same as the URL where this file is hosted.

```json
{
  "@context": "https://www.w3.org/ns/solid/oidc-context.jsonld",
  "client_id": "http://localhost:8080/app/client-id.jsonld",
  "client_name": "App Name",
  "redirect_uris": [ "http://localhost:8080/app/logged-in-screen" ],
  "post_logout_redirect_uris": [ "http://localhost:8080/app/logged-out-screen" ]
}
```

This client ID file can then be used to log in a user, make sure to use the same redirect URI as in the file.

```ts
import {
  getDefaultAuth,
  configureDefaultAuth
} from "trustflows-client";

configureDefaultAuth({
  persistTokens: false,
});
const auth = getDefaultAuth();
await auth.login(
  "https://idp.example",
  "http://localhost:8080/app/client-id.jsonld",
  "http://localhost:8080/app/logged-in-screen"
);

```

`configureDefaultAuth()` and the `Auth` constructor accept these options:

- `fetch`: custom `fetch` implementation (useful for tests or custom networking).
- `storage`: storage provider (defaults to `sessionStorage` in the browser).
- `claimResolvers`: add or override UMA claim resolvers.
- `persistTokens`: whether to persist OIDC tokens in storage. Defaults to `true`.

Notes:
- `configureDefaultAuth()` must be called **before** `getDefaultAuth()`; after the default instance is created,
  calling `configureDefaultAuth()` will throw.
- Token persistence stores an `oidc_tokens` JSON blob in `storage` and hydrates it on startup. Set
  `persistTokens: false` to opt out.

After redirecting back to your application, you can handle the incoming redirect and create an authenticated fetch
function.

```ts
import {
  getDefaultAuth,
  configureDefaultAuth
} from "trustflows-client";

configureDefaultAuth({
  persistTokens: false,
});

const auth = getDefaultAuth();

await auth.handleIncomingRedirect();

const authFetch = auth.createAuthFetch();

const loggedIn = await auth.isLoggedIn();
```

## Authenticated fetch

`auth.createAuthFetch()` returns a `fetch`-compatible function. It first tries the request
unauthenticated and, only on a `401`, inspects the `WWW-Authenticate` header: a `UMA` challenge is
satisfied through the UMA flow, otherwise the request is retried with the OIDC bearer token. Use it
exactly like the global `fetch`:

```ts
const authFetch = auth.createAuthFetch();

const response = await authFetch("https://pod.example/private.txt");
```

### Requesting access (per request)

The returned function accepts an optional third `AuthFetchOptions` argument so behaviour can be tuned
**per request**. Set `accessRequest: true` to ask for access when the authorization server denies the
request (i.e. the requesting party does not currently have access and the token endpoint responds
with a 4xx error). When enabled, the client POSTs a `sotw:EvaluationRequest` to the authorization
server's `/requests` endpoint and the access request's response is returned from the fetch call.

```ts
const authFetch = auth.createAuthFetch();

// Standard authenticated request — rejects if access is denied.
await authFetch("https://pod.example/private.txt");

// Same request, but ask for access if it is denied.
const response = await authFetch("https://pod.example/private.txt", undefined, {
  accessRequest: true,
});

// The HTTP method of the request determines the requested action:
//   GET (and anything else) -> odrl:read
//   PUT / POST / PATCH       -> odrl:write
//   DELETE                   -> odrl:delete
await authFetch("https://pod.example/private.txt", { method: "PUT" }, {
  accessRequest: true,
});
```

The access request is sent on behalf of the logged-in user's WebID, so make sure the user is logged
in (`auth.webId` is set) before using `accessRequest: true`. Because the access request only *asks*
for access, the resource is not returned; inspect the returned response (for example a `201 Created`)
to confirm the request was accepted.

## Custom UMA claim resolvers

You can add custom UMA claim resolvers in your application without modifying this package.

```ts
import {
  Auth,
  type ClaimResolverDefinition,
} from "trustflows-client";

const myResolver: ClaimResolverDefinition = {
  id: "custom-claim",
  match: {
    claim_type: "my-custom-claim",
    issuer: "https://idp.example",
  },
  priority: 10,
  resolve: async (requiredClaim, auth) => {
    // Custom logic to resolve the claim
    return {
      claim_token: "custom-token",
      claim_token_format: "custom-format",
    };
  },
};

auth.addClaimResolver(myResolver);
```

The `id` field must be unique among all registered claim resolvers and is used for logging and debugging purposes. 
`match` can use any of: `claim_token_format`, `claim_type`, `issuer`, `name`, `friendly_name`. Each field can be a
string, RegExp, or a predicate function. The `priority` field is used to determine the order in which resolvers are
tried (higher priority first). The `resolve` function is called when the resolver matches a claim request. It receives
the required claim and the auth entry that can be used to create the claim.

## Aggregators

The `Aggregator` class manages a single Aggregator Instance on an Aggregator Server: it discovers or
creates the instance for the logged-in user, keeps it cached, and lets you find, deploy, and delete the
services that run on it. It builds on the authenticated fetch, so all instance and service requests are
authorized automatically.

### Creating and initializing

Pass the **Aggregator Server base URL** (where the Server Description is served) and an authenticated
`Auth` instance. `init()` resolves the instance to use:

1. a previously cached instance for this server and user, otherwise
2. the first instance returned by the server's management endpoint, otherwise
3. a newly created instance.

```ts
import { Aggregator, getDefaultAuth } from "trustflows-client";

const auth = getDefaultAuth();
await auth.handleIncomingRedirect();

const aggregator = new Aggregator({
  serverUrl: "https://aggregator.example/",
  auth,
});

await aggregator.init();
console.log(aggregator.instanceUrl); // the resolved Aggregator Instance URL
```

Constructor options:

- `serverUrl` (required): the Aggregator Server base URL.
- `auth` (required): an authenticated `Auth` instance (the user must be logged in).
- `creationFlow`: which management flow to use when an instance has to be created — `"none"`,
  `"provision"`, `"authorization_code"`, or `"device_code"`. Defaults to the first flow advertised by
  the server.
- `authorizationServer`: the UMA Authorization Server governing the Aggregator's resources. Required for
  the interactive creation flows (can also be passed to `startCreation`).
- `cache`: whether to persist the discovered instance and services. Defaults to `true`.
- `storage`: the storage used for the cache and pending interactive-flow state. Defaults to
  `localStorage`.

Use `delete()` to remove the instance (and clear it from the cache):

```ts
await aggregator.delete();
```

### Creation flows

`none` and `provision` complete automatically inside `init()`. The interactive flows
(`authorization_code` and `device_code`) need user interaction, so `init()` throws an
`AggregatorAuthorizationRequiredError` and you drive the flow with the generic `startCreation()` /
`finishCreation()` pair. `startCreation()` returns a discriminated step describing what to do next.

```ts
import { Aggregator, AggregatorAuthorizationRequiredError } from "trustflows-client";

const aggregator = new Aggregator({
  serverUrl: "https://aggregator.example/",
  auth,
  creationFlow: "authorization_code",
  authorizationServer: "https://as.example",
});

try {
  await aggregator.init();
} catch (error) {
  if (error instanceof AggregatorAuthorizationRequiredError) {
    const step = await aggregator.startCreation({
      redirectUri: "https://app.example/callback",
    });

    if (step.type === "redirect") {
      // authorization_code: send the user to the IdP.
      window.location.href = step.authorizationUrl;
    } else if (step.type === "device") {
      // device_code: show the verification details to the user.
      console.log(step.user_code, step.verification_uri);
    }
  }
}
```

After the user returns (authorization_code) or while the device flow is pending (device_code), call
`finishCreation()` to complete it. For `device_code` this polls until the user authorizes; for
`authorization_code` the `code` and `state` are read from the current URL when omitted.

```ts
// authorization_code, after the redirect back to your app:
await aggregator.finishCreation();

// device_code:
await aggregator.finishCreation(); // resolves once the user has authorized
```

The same `startCreation()` / `finishCreation()` pair also performs a **token update** when the instance
already exists but its tokens are no longer valid (`init()` throws an
`AggregatorAuthorizationRequiredError` with `reason: "token-update"` in that case).

### Managing services

`getService()` returns information about a service that performs a given transformation, creating it if
it does not exist yet. It resolves in order: the cache, a scan of the Service Collection (matching the
transformation, optional implementation, and parameter bindings), then deployment.

```ts
const service = await aggregator.getService({
  transformation: "https://aggregator.example/transformations#QueryView",
  // Optional implementation:
  // implementation: "https://aggregator.example/transformations#QueryViewImpl",
  parameters: {
    // A string is treated as a literal term:
    "https://aggregator.example/transformations#Query": "SELECT * WHERE { ?s ?p ?o }",
    // Use an object with `type: "iri"` for an IRI term:
    "https://aggregator.example/transformations#Source": {
      value: "http://example.org/source1",
      type: "iri",
    },
  },
});

console.log(service.service);       // the Service Description Endpoint URL
console.log(service.outputs);       // { "<fno:Output IRI>": ["<dcat:accessURL>", ...] }
console.log(service.provenanceLog); // the provenance log URL, if the service exposes one
```

`outputs` maps each `fno:Output` IRI to the list of its distribution access URLs. When an output has
multiple distributions (for example different formats), all of their access URLs are returned and you
can fetch the Service Description yourself to decide which one to use.

List every service currently deployed, or delete one by its Service Description URL:

```ts
const services = await aggregator.getServiceCollection();

await aggregator.deleteService(service.service);
```

All service methods require `init()` to have completed; calling them earlier throws an
`AggregatorNotInitializedError`.


