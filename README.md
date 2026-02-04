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
