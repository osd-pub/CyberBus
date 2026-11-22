# `@cyberbus/web`

Browser SDK for outbound CyberBus overlay TCP connectivity. It signs in to
Logto as a public SPA client, verifies the resource JWT and CyberBus credential
claim, derives the same network material as the Rust SDK with Web Crypto, and
runs `@easytier/browser` WebAssembly in the page.

Status: source implementation and mocked end-to-end tests. Real Logto SPA
issuance and refresh have been verified against the isolated test deployment.
A real Chrome page has also passed a JSPI/WebAssembly overlay TCP smoke through
a local Wrangler relay to a peer that exposed the target port. Production
`wss://` relay and remote-target verification is still required.

## Scope

The browser can open outbound overlay IPv4 TCP streams:

```text
page -> @easytier/browser (WebAssembly) -> WSS relay -> overlay peer:port
```

It cannot create a TUN device, accept inbound overlay connections, use STUN or
hole punching, or become a general inbound EasyTier node. `listenTcp` is not
exposed by this SDK. "Port connectivity" means the page can connect to a port
published by another EasyTier peer.

This package is not a drop-in replacement for the Rust Protobuf `Client`
facade. Device discovery, application data, RPC, public profiles and the local
Protobuf command/event state machine remain in the native SDK. The Web SDK
provides authenticated EasyTier overlay transport plus raw TCP streams. It does
not implement the CyberBus Noise application handshake, device-directory
authentication, or the Protobuf Data/RPC facade.

## Install

```sh
pnpm add @cyberbus/web @easytier/browser
```

`@easytier/browser` is currently not on the public npm registry. Install it from
your private registry or build it from the upstream `EasyTier/easytier-js`
workspace. The browser must support WebAssembly JSPI; upstream's published
bundle also decodes its embedded WASM with `Uint8Array.fromBase64`. Upstream's
`dist/index.js` imports `@easytier/runtime` as an external package, so let your
application bundler resolve both packages; a directly served single file must
be a self-contained bundle.

## Configure

```ts
import { CyberBusWeb } from "@cyberbus/web";

const client = CyberBusWeb.create({
  issuer: "https://auth.example.com/oidc",
  clientId: "your-logto-spa-client-id",
  resource: "https://cyberbus.example.com/api",
  productId: "my-product",
  redirectUri: `${location.origin}/auth/callback.html`,
  peers: ["wss://relay.example.com/"],
  offlineAccess: true,
});
```

The configuration is public. Never put a token, refresh token, seed, network
secret, app PSK, PKCE verifier, or client secret in it.

The redirect URI must be registered exactly on the Logto SPA client. The
callback page must send the complete callback URL back to the opener:

```html
<script>
  // Replace with the application origin when the callback is hosted elsewhere.
  const appOrigin = location.origin;
  const message = {
    type: "cyberbus-web-auth-callback/v1",
    url: location.href,
  };
  window.opener?.postMessage(message, appOrigin);
  window.close();
</script>
```

The target origin must be the application origin when the callback page is on a
different origin. The SDK accepts the message only from the configured redirect
origin and the popup window it opened.

## Login

```ts
await client.login();

console.log(client.authState.phase); // "authenticated"
console.log(client.authState.account?.productId);
```

`login()` opens a popup, uses Authorization Code + PKCE S256, validates state,
nonce, issuer, audience, client, signature, time, `network:join`, ID token, and
the complete versioned CyberBus claim. Tokens and derived secrets stay in page
memory.

For a host-managed popup:

```ts
const handle = await client.beginLogin("login");
window.open(handle.authorizationUrl, "cyberbus-auth");
// When the callback page posts the URL back:
await client.completeLogin(callbackUri);
```

Reloading the page loses the in-memory session. The SDK deliberately does not
write tokens to `localStorage`, `sessionStorage`, IndexedDB, cookies, or
ordinary configuration.

## Start the network

```ts
await client.startNetwork();
console.log(client.networkState.ipv4);
```

The default overlay address is derived inside `10.144.0.0/20`. A fixed address
can be supplied with `ipv4: "10.144.1.20/20"`. Only `wss://` relay peers are
accepted in production; `ws://` is restricted to loopback development.

Without an explicit `ipv4`, the address is derived from an installation ID that
exists only in page memory. Reloading the page or creating a new client can
therefore produce a different overlay address. Supply a fixed `ipv4` when other
peers must reach a stable address.

## Open a port

```ts
const stream = await client.openPort("10.144.0.20", 8080, {
  timeoutMs: 10_000,
});

await stream.writeAll(new TextEncoder().encode("ping\n"));

const result = await stream.read();
if (result.data.length > 0) {
  console.log(new TextDecoder().decode(result.data));
}
if (result.eof) {
  await stream.close();
}
```

`write()` may write fewer bytes than requested. `writeAll()` handles partial
writes. A `TcpConnection` can also be consumed as an async iterable of byte
chunks until EOF.

## Refresh and lifecycle

```ts
await client.refresh();       // force a real Logto refresh and re-verify
await client.stopNetwork();
await client.logout();        // best-effort revoke + local clear
await client.close();
```

With `offlineAccess: true`, the SDK requests a refresh token and keeps it in
memory. While the network is running it performs a real refresh every 4–6
minutes, re-verifies the complete token and claim, and enforces a 10-minute
validation lease. A credential epoch/material change stops the old network and
moves auth state to `reauth-required`; the caller must log in again and
explicitly restart.

Subscribe to sanitized lifecycle events with `onEvent`. Event payloads never
contain tokens, seeds, network secrets, or EasyTier event message bodies.

## Logto deployment

Create a Logto **SPA** application and register the exact redirect URI. Add the
SPA client to the CyberBus product's explicit `browserClientIds` list in
`ET_PRODUCTS_JSON`:

```json
[
  {
    "productId": "my-product",
    "nativeClientIds": ["native-client-id"],
    "browserClientIds": ["spa-client-id"]
  }
]
```

The Custom JWT hook accepts a client only when its application type matches its
allowlist: `Native` clients in `nativeClientIds`, `SPA` clients in
`browserClientIds`. Do not add an SPA client to the Native list or weaken the
application-type check.

Enable CORS for the browser origin on the SPA application. The token and JWKS
endpoints must allow that origin.

## Build and test

```sh
cd packages/cyberbus-web
pnpm install
pnpm check
pnpm test
pnpm build
```

The tests cover strict JSON/JWT parsing, ES256 and ES384 verification, PKCE URL
construction, state/nonce/claim rejection, the Rust cross-language derivation
fixture, network startup, refresh, credential changes, and mocked TCP streams.

The demo is in `examples/web-demo`.
