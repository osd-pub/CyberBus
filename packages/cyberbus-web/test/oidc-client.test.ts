import { afterEach, describe, expect, it, vi } from "vitest";
import fixture from "../../../crates/cyberbus-auth/tests/fixtures/derivation.json";
import {
  base64UrlEncode,
  utf8,
} from "../src/base64.js";
import { CyberBusWeb } from "../src/client.js";
import type {
  EasyTierFactory,
  EasyTierInstance,
  EasyTierTcpStream,
} from "../src/easytier.js";
import { CREDENTIAL_CLAIM } from "../src/oidc.js";

const ISSUER = fixture.issuer;
const RESOURCE = "https://resource.example.test/cyberbus";
const CLIENT_ID = "cyberbus-web-test";
const REDIRECT = "https://app.example.test/auth/callback.html";
const NOW = 1_000;

interface Signer {
  readonly kid: string;
  readonly jwk: Record<string, unknown>;
  sign(claims: Record<string, unknown>): Promise<string>;
}

async function signer(alg: "ES256" | "ES384" = "ES256"): Promise<Signer> {
  const namedCurve = alg === "ES384" ? "P-384" : "P-256";
  const hash = alg === "ES384" ? "SHA-384" : "SHA-256";
  const pair = (await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await globalThis.crypto.subtle.exportKey(
    "jwk",
    pair.publicKey,
  )) as Record<string, unknown>;
  const kid = `test-${alg.toLowerCase()}`;
  jwk.kid = kid;
  jwk.alg = alg;
  jwk.use = "sig";
  return {
    kid,
    jwk,
    async sign(claims) {
      const header = base64UrlEncode(
        utf8(JSON.stringify({ alg, kid, typ: "JWT" })),
      );
      const payload = base64UrlEncode(utf8(JSON.stringify(claims)));
      const input = utf8(`${header}.${payload}`);
      const signature = new Uint8Array(
        await globalThis.crypto.subtle.sign(
          { name: "ECDSA", hash },
          pair.privateKey,
          input,
        ),
      );
      return `${header}.${payload}.${base64UrlEncode(signature)}`;
    },
  };
}

function credentialClaim(seed = fixture.seed) {
  return {
    version: 1,
    product_id: fixture.product_id,
    credential_epoch: fixture.epoch,
    account_seed_secret_hex: seed,
    max_devices: 256,
    virtual_cidr: "10.144.0.0/20",
    control_port: 11_000,
    config_version: "1",
  };
}

function accessClaims(overrides: Record<string, unknown> = {}) {
  return {
    iss: ISSUER,
    sub: fixture.subject,
    aud: RESOURCE,
    client_id: CLIENT_ID,
    scope: "openid network:join",
    gty: "authorization_code",
    kind: "AccessToken",
    iat: NOW,
    exp: NOW + 600,
    [CREDENTIAL_CLAIM]: credentialClaim(),
    ...overrides,
  };
}

function idClaims(nonce: string, overrides: Record<string, unknown> = {}) {
  return {
    iss: ISSUER,
    sub: fixture.subject,
    aud: CLIENT_ID,
    iat: NOW,
    exp: NOW + 600,
    auth_time: NOW,
    nonce,
    ...overrides,
  };
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface HarnessOptions {
  readonly alg?: "ES256" | "ES384";
  readonly mutateAccess?: (
    claims: Record<string, unknown>,
    call: number,
  ) => void;
  readonly mutateId?: (claims: Record<string, unknown>) => void;
  readonly tokenError?: string;
  readonly tokenStatus?: number;
  readonly failTokenAfterLogin?: boolean;
  readonly deferFactory?: boolean;
  readonly deferTokenAfterLogin?: boolean;
  readonly discoveryBody?: string;
}

async function harness(options: HarnessOptions = {}) {
  const keys = await signer(options.alg);
  const events: unknown[] = [];
  let seenConfig: Record<string, unknown> | undefined;
  let tokenCalls = 0;
  let nonce = "";
  let releaseDeferredToken: (() => Promise<void>) | undefined;
  let deferredTokenPending = false;
  const nativeStream: EasyTierTcpStream = {
    localAddress: { ipv4: "10.144.0.10", port: 40000 },
    peerAddress: { ipv4: "10.144.0.20", port: 8080 },
    read: vi.fn(async () => ({ data: new Uint8Array([1, 2, 3]), eof: false })),
    write: vi.fn(async (data) => data.length),
    shutdownWrite: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
  };
  const instance: EasyTierInstance = {
    connectTcp: vi.fn(async () => nativeStream),
    status: vi.fn(async () => ({ state: "running", connections: 1 })),
    close: vi.fn(async () => {}),
  };
  let resolveFactory: ((value: EasyTierInstance) => void) | undefined;
  const factory: EasyTierFactory = {
    create: vi.fn(async (config, eventOptions) => {
      seenConfig = config as unknown as Record<string, unknown>;
      eventOptions?.onEvent?.({ kind: "peer_added", message: "peer" });
      if (options.deferFactory === true) {
        return new Promise<EasyTierInstance>((resolve) => {
          resolveFactory = resolve;
        });
      }
      return instance;
    }),
  };
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      if (options.discoveryBody !== undefined) {
        return new Response(options.discoveryBody);
      }
      return response({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/auth`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        revocation_endpoint: `${ISSUER}/revoke`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: [options.alg ?? "ES256"],
      });
    }
    if (url === `${ISSUER}/jwks`) {
      return response({ keys: [keys.jwk] });
    }
    if (url === `${ISSUER}/revoke`) {
      return response({});
    }
    if (url === `${ISSUER}/token`) {
      tokenCalls += 1;
      if (options.tokenStatus !== undefined && options.tokenStatus >= 400) {
        if (!options.failTokenAfterLogin || tokenCalls > 1) {
          return response(
            { error: options.tokenError ?? "invalid_request" },
            options.tokenStatus,
          );
        }
      }
      const access = accessClaims();
      const id = idClaims(nonce);
      options.mutateAccess?.(access, tokenCalls);
      options.mutateId?.(id);
      const tokenResponse = async (): Promise<Response> =>
        response({
          access_token: await keys.sign(access),
          id_token: await keys.sign(id),
          refresh_token: `refresh-${tokenCalls}`,
          token_type: "Bearer",
          expires_in: 3_600,
        });
      if (options.deferTokenAfterLogin === true && tokenCalls > 1) {
        deferredTokenPending = true;
        return new Promise<Response>((resolve, reject) => {
          releaseDeferredToken = async () => {
            try {
              resolve(await tokenResponse());
            } catch (error) {
              reject(error);
            } finally {
              deferredTokenPending = false;
            }
          };
        });
      }
      return tokenResponse();
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  const client = CyberBusWeb.create(
    {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      resource: RESOURCE,
      productId: fixture.product_id,
      redirectUri: REDIRECT,
      peers: "wss://relay.example.test/",
    },
    {
      fetch: fetchImpl as typeof fetch,
      createEasyTier: factory,
      now: () => NOW,
      onEvent: (event) => events.push(event),
    },
  );
  return {
    client,
    keys,
    fetchImpl,
    factory,
    instance,
    nativeStream,
    events,
    seenConfig: () => seenConfig,
    setNonce(value: string) {
      nonce = value;
    },
    releaseFactory() {
      resolveFactory?.(instance);
    },
    async releaseDeferredToken() {
      await releaseDeferredToken?.();
    },
    deferredTokenPending: () => deferredTokenPending,
    tokenCalls: () => tokenCalls,
  };
}

async function login(
  client: CyberBusWeb,
  setNonce?: (value: string) => void,
): Promise<void> {
  const started = await client.beginLogin();
  const url = new URL(started.authorizationUrl);
  const state = url.searchParams.get("state");
  const nonce = url.searchParams.get("nonce");
  expect(state).not.toBeNull();
  expect(nonce).not.toBeNull();
  setNonce?.(nonce ?? "");
  await client.completeLogin(
    `${REDIRECT}?code=authorization-code&state=${encodeURIComponent(state ?? "")}`,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("CyberBus web client", () => {
  it("uses PKCE S256 and a resource-scoped authorization request", async () => {
    const h = await harness();
    const started = await h.client.beginLogin();
    const url = new URL(started.authorizationUrl);
    expect(url.origin).toBe(new URL(ISSUER).origin);
    expect(url.pathname).toBe("/oidc/auth");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("resource")).toBe(RESOURCE);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(url.searchParams.get("state")).toMatch(/^[0-9a-f]{64}$/u);
    expect(url.searchParams.get("nonce")).toMatch(/^[0-9a-f]{64}$/u);
    expect(url.searchParams.get("prompt")).toBe("login consent");
    await h.client.close();
  });

  it("rejects an oversized discovery response before parsing", async () => {
    const h = await harness({
      discoveryBody: `{"padding":"${"x".repeat(1_048_576)}"}`,
    });
    await expect(h.client.beginLogin()).rejects.toMatchObject({
      code: "INVALID_CLAIMS",
    });
    await h.client.close();
  });

  it("authenticates, derives the fixture material, and opens a TCP stream", async () => {
    const h = await harness();
    await login(h.client, h.setNonce);
    expect(h.client.authState.phase).toBe("authenticated");
    expect(h.client.authState.account?.subject).toBe(fixture.subject);
    expect(h.client.authState.refreshSupported).toBe(true);

    const network = await h.client.startNetwork();
    expect(network.phase).toBe("running");
    expect(network.ipv4).toMatch(/^10\.144\./u);
    expect(h.seenConfig()).toMatchObject({
      networkName: fixture.network_name,
      networkSecret: fixture.network_secret,
      ipv4: expect.stringMatching(/^10\.144\.\d+\.\d+\/20$/u),
      peers: ["wss://relay.example.test/"],
      encryption: true,
    });
    expect(JSON.stringify(h.events)).not.toContain(fixture.network_secret);

    const stream = await h.client.openPort("10.144.0.20", 8080);
    expect(stream.remoteAddress).toEqual({ ipv4: "10.144.0.20", port: 8080 });
    await stream.writeAll(new Uint8Array([9, 8]));
    expect(h.nativeStream.write).toHaveBeenCalled();
    expect(await stream.read()).toEqual({
      data: new Uint8Array([1, 2, 3]),
      eof: false,
    });
    await stream.close();
    expect(h.nativeStream.close).toHaveBeenCalled();

    expect((await h.client.status()).connections).toBe(1);
    await h.client.logout();
    expect(h.instance.close).toHaveBeenCalled();
    expect(h.client.authState.phase).toBe("logged-out");
    await h.client.close();
  });

  it("verifies the ES384 signing algorithm used by the test Logto deployment", async () => {
    const h = await harness({ alg: "ES384" });
    await login(h.client, h.setNonce);
    expect(h.client.authState.phase).toBe("authenticated");
    await h.client.close();
  });

  it("requires azp for a multi-audience ID token", async () => {
    const missing = await harness({
      mutateId(claims) {
        claims.aud = [CLIENT_ID, "other-client"];
      },
    });
    await expect(login(missing.client, missing.setNonce)).rejects.toMatchObject({
      code: "INVALID_CLAIMS",
    });
    await missing.client.close();

    const present = await harness({
      mutateId(claims) {
        claims.aud = [CLIENT_ID, "other-client"];
        claims.azp = CLIENT_ID;
      },
    });
    await login(present.client, present.setNonce);
    expect(present.client.authState.phase).toBe("authenticated");
    await present.client.close();
  });

  it("rejects a callback state mismatch without exchanging the code", async () => {
    const h = await harness();
    await h.client.beginLogin();
    await expect(
      h.client.completeLogin(`${REDIRECT}?code=x&state=wrong`),
    ).rejects.toMatchObject({ code: "AUTH_CANCELLED" });
    expect(
      h.fetchImpl.mock.calls.some(([url]) => String(url) === `${ISSUER}/token`),
    ).toBe(false);
    await h.client.close();
  });

  it("rejects duplicate callback parameters and invalid claims", async () => {
    const duplicate = await harness();
    const started = await duplicate.client.beginLogin();
    const state = new URL(started.authorizationUrl).searchParams.get("state") ?? "";
    await expect(
      duplicate.client.completeLogin(
        `${REDIRECT}?code=a&code=b&state=${encodeURIComponent(state)}`,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CLAIMS" });
    await duplicate.client.close();

    const invalid = await harness({
      mutateAccess(claims) {
        claims.scope = "openid";
      },
    });
    const login = await invalid.client.beginLogin();
    const validState =
      new URL(login.authorizationUrl).searchParams.get("state") ?? "";
    await expect(
      invalid.client.completeLogin(
        `${REDIRECT}?code=ok&state=${encodeURIComponent(validState)}`,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CLAIMS" });
    expect(invalid.client.authState.phase).toBe("logged-out");
    await invalid.client.close();
  });

  it("rejects a nonce mismatch and an unknown credential field", async () => {
    const nonce = await harness({
      mutateId(claims) {
        claims.nonce = "wrong";
      },
    });
    const started = await nonce.client.beginLogin();
    const state = new URL(started.authorizationUrl).searchParams.get("state") ?? "";
    await expect(
      nonce.client.completeLogin(
        `${REDIRECT}?code=ok&state=${encodeURIComponent(state)}`,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CLAIMS" });
    await nonce.client.close();

    const extra = await harness({
      mutateAccess(claims) {
        const claim = claims[CREDENTIAL_CLAIM] as Record<string, unknown>;
        claim.extra = true;
      },
    });
    const extraLogin = await extra.client.beginLogin();
    const extraState =
      new URL(extraLogin.authorizationUrl).searchParams.get("state") ?? "";
    await expect(
      extra.client.completeLogin(
        `${REDIRECT}?code=ok&state=${encodeURIComponent(extraState)}`,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CLAIMS" });
    await extra.client.close();
  });

  it("maps an invalid refresh grant to a terminal session error", async () => {
    const h = await harness();
    await login(h.client, h.setNonce);
    const failing = await harness({
      tokenStatus: 400,
      tokenError: "invalid_grant",
      failTokenAfterLogin: true,
    });
    await login(failing.client, failing.setNonce);
    await failing.client.startNetwork();
    await expect(failing.client.refresh()).rejects.toMatchObject({
      code: "SESSION_EXPIRED",
    });
    await failing.client.close();
    await h.client.close();
  });

  it("reports a credential epoch change and stops the old network", async () => {
    const h = await harness({
      mutateAccess(claims, call) {
        if (call > 1) {
          const claim = claims[CREDENTIAL_CLAIM] as Record<string, unknown>;
          claim.account_seed_secret_hex = "22".repeat(32);
        }
      },
    });
    await login(h.client, h.setNonce);
    await h.client.startNetwork();
    const original = h.seenConfig();
    expect(original).toBeDefined();
    const changed = await h.client.refresh();
    expect(changed.phase).toBe("reauth-required");
    expect(h.events).toContainEqual(
      expect.objectContaining({ type: "credentials-changed" }),
    );
    expect(h.instance.close).toHaveBeenCalled();
    await expect(h.client.refresh()).rejects.toMatchObject({
      code: "CREDENTIALS_CHANGED",
    });
    await expect(h.client.startNetwork()).rejects.toMatchObject({
      code: "CREDENTIALS_CHANGED",
    });
    await h.client.close();
  });

  it("cancels an in-flight network start when stopped", async () => {
    const h = await harness({ deferFactory: true });
    await login(h.client, h.setNonce);
    const starting = h.client.startNetwork();
    await vi.waitFor(() => {
      expect(h.factory.create).toHaveBeenCalledTimes(1);
    });
    await h.client.stopNetwork();
    h.releaseFactory();
    const stopped = await starting;
    expect(stopped.phase).toBe("stopped");
    expect(h.instance.close).toHaveBeenCalledTimes(1);
    expect(h.client.networkState.phase).toBe("stopped");
    await h.client.close();
  });

  it("does not restore a session when logout wins a refresh race", async () => {
    const h = await harness({ deferTokenAfterLogin: true });
    await login(h.client, h.setNonce);
    const refreshing = h.client.refresh();
    await vi.waitFor(() => {
      expect(h.deferredTokenPending()).toBe(true);
    });
    await h.client.logout();
    await h.releaseDeferredToken();
    await expect(refreshing).resolves.toMatchObject({ phase: "logged-out" });
    expect(h.client.authState.phase).toBe("logged-out");
    await h.client.close();
  });

  it("deduplicates concurrent refresh requests", async () => {
    const h = await harness({ deferTokenAfterLogin: true });
    await login(h.client, h.setNonce);
    const first = h.client.refresh();
    const second = h.client.refresh();
    await vi.waitFor(() => {
      expect(h.deferredTokenPending()).toBe(true);
    });
    expect(h.tokenCalls()).toBe(2);
    await h.releaseDeferredToken();
    await expect(first).resolves.toMatchObject({ phase: "authenticated" });
    await expect(second).resolves.toMatchObject({ phase: "authenticated" });
    expect(h.tokenCalls()).toBe(2);
    await h.client.close();
  });
});
