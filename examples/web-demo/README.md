# CyberBus Web demo

This demo uses the public `@cyberbus/web` package to sign in with Logto in a
popup, start an EasyTier WebAssembly instance, and open outbound TCP streams to
overlay IPv4 services.

The browser is not an inbound EasyTier node. It cannot accept overlay
connections or create a TUN interface. "Port connectivity" here means the page
can connect to a port exposed by another EasyTier peer.

## Prerequisites

- A Logto SPA client registered for `http://127.0.0.1:5173/callback.html`.
- The SPA client allowed by the CyberBus custom JWT hook for the same product.
- A browser-compatible EasyTier `wss://` relay.
- A built or published `@easytier/browser` ESM bundle.

`@easytier/browser` is not currently published on the public npm registry. Build
it from the upstream `EasyTier/easytier-js` workspace, or install it from the
registry where your organization publishes it.

The upstream package's `dist/index.js` imports `@easytier/runtime` as an
external dependency. Do not copy that file by itself into `public/`: a browser
loading it directly cannot resolve the bare package specifier. Produce one
self-contained ESM file (including runtime and the WASM-bearing browser entry),
for example with esbuild after installing the package:

```sh
pnpm add -D esbuild
pnpm exec esbuild node_modules/@easytier/browser/dist/index.js \
  --bundle --format=esm --platform=browser --loader:.wasm=binary \
  --outfile=public/easytier-browser.js
```

Serve that file at `/easytier-browser.js`, or enter another same-origin
self-contained ESM URL in the demo form.

## Run

```sh
cd examples/web-demo
pnpm install
pnpm dev
```

Open `http://127.0.0.1:5173/`. Fill in the public client configuration, click
Login, start the network, then connect to an overlay `IPv4:port`.

Do not put a token, seed, network secret, PKCE verifier, or private key in this
form or in any source file. The SDK keeps those values in page memory.

## Browser limits

- The page must support WebAssembly JSPI.
- Only outbound `ws://` (loopback development) and `wss://` EasyTier peers work.
- Only overlay IPv4 TCP is exposed.
- Reloading the page loses the in-memory login and requires a new popup login.
- Without an explicit `ipv4`, the overlay address can change after a reload.
- The popup flow requires the callback page to be served from the same origin as
  the demo and to post the callback URL to `window.opener`.
