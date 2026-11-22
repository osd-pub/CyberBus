import { describe, expect, it } from "vitest";
import { credentialConstants, resolveConfig } from "../src/config.js";

function config(overrides: Record<string, unknown> = {}) {
  return {
    issuer: "https://auth.example.test/oidc",
    clientId: "spa-client",
    resource: "https://resource.example.test/cyberbus",
    productId: "product",
    redirectUri: "https://app.example.test/auth/callback.html",
    peers: ["wss://relay.example.test/"],
    ...overrides,
  };
}

describe("web SDK configuration", () => {
  it("normalizes the public configuration and credential constants", () => {
    const resolved = resolveConfig(config({ ipv4: "10.144.1.20/20" }));
    expect(resolved.redirectOrigin).toBe("https://app.example.test");
    expect(resolved.peers).toEqual(["wss://relay.example.test/"]);
    expect(resolved.ipv4).toBe("10.144.1.20/20");
    expect(resolved.encryption).toBe(true);
    expect(resolved.offlineAccess).toBe(true);
    expect(credentialConstants.virtualCidr).toBe("10.144.0.0/20");
  });

  it("allows ws only for loopback development", () => {
    expect(() =>
      resolveConfig(config({ peers: "ws://127.0.0.1:8787/" })),
    ).not.toThrow();
    expect(() =>
      resolveConfig(config({ peers: "ws://relay.example.test/" })),
    ).toThrow("peers");
  });

  it("rejects insecure issuers and non-loopback HTTP callbacks", () => {
    expect(() =>
      resolveConfig(config({ issuer: "http://auth.example.test/oidc" })),
    ).toThrow("issuer");
    expect(() =>
      resolveConfig(config({ issuer: "https://auth.example.test/oidc/" })),
    ).toThrow("issuer");
    expect(() =>
      resolveConfig(
        config({ redirectUri: "http://app.example.test/callback.html" }),
      ),
    ).toThrow("redirectUri");
    expect(() =>
      resolveConfig(
        config({ redirectUri: "http://127.0.0.1:5173/callback.html" }),
      ),
    ).not.toThrow();
  });

  it("rejects addresses outside the fixed /20 pool and invalid limits", () => {
    expect(() =>
      resolveConfig(config({ ipv4: "10.144.0.0/20" })),
    ).toThrow("ipv4");
    expect(() =>
      resolveConfig(config({ ipv4: "10.145.0.2/20" })),
    ).toThrow("ipv4");
    expect(() =>
      resolveConfig(config({ ipv4: "10.144.0.2/24" })),
    ).toThrow("ipv4");
    expect(() =>
      resolveConfig(config({ resource: "spa-client" })),
    ).toThrow("resource");
    expect(() =>
      resolveConfig(config({ authTimeoutMs: 1_000 })),
    ).toThrow("authTimeoutMs");
  });
});
