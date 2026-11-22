import { describe, expect, it } from "vitest";
import fixture from "../../../crates/cyberbus-auth/tests/fixtures/derivation.json";
import { hex } from "../src/base64.js";
import {
  deriveNetworkMaterial,
  parseCredentialClaim,
  sameNetworkMaterial,
} from "../src/credentials.js";

const claim = {
  version: 1,
  product_id: fixture.product_id,
  credential_epoch: fixture.epoch,
  account_seed_secret_hex: fixture.seed,
  max_devices: 256,
  virtual_cidr: "10.144.0.0/20",
  control_port: 11_000,
  config_version: "1",
};

describe("credential derivation", () => {
  it("matches the Rust and Python cross-language fixture", async () => {
    const parsed = parseCredentialClaim(claim, fixture.product_id);
    const material = await deriveNetworkMaterial(
      globalThis.crypto,
      {
        issuer: fixture.issuer,
        subject: fixture.subject,
        productId: fixture.product_id,
      },
      parsed,
    );
    expect(material.networkName).toBe(fixture.network_name);
    expect(material.networkSecret).toBe(fixture.network_secret);
    expect(hex(material.appPsk)).toBe(fixture.app_psk);
    expect(hex(material.bindingId)).toBe(fixture.binding_id);
    expect(material.credentialEpoch).toBe(9_007_199_254_740_993n);
  });

  it("compares every derived material field", async () => {
    const parsed = parseCredentialClaim(claim, fixture.product_id);
    const account = {
      issuer: fixture.issuer,
      subject: fixture.subject,
      productId: fixture.product_id,
    };
    const left = await deriveNetworkMaterial(globalThis.crypto, account, parsed);
    const right = await deriveNetworkMaterial(globalThis.crypto, account, parsed);
    expect(sameNetworkMaterial(left, right)).toBe(true);
    expect(
      sameNetworkMaterial(left, {
        ...right,
        bindingId: new Uint8Array(32),
      }),
    ).toBe(false);
  });

  it("rejects unknown, uppercase, and noncanonical claim fields", () => {
    expect(() =>
      parseCredentialClaim({ ...claim, extra: true }, fixture.product_id),
    ).toThrow("credential claim");
    expect(() =>
      parseCredentialClaim(
        { ...claim, account_seed_secret_hex: fixture.seed.toUpperCase() },
        fixture.product_id,
      ),
    ).toThrow("credential claim");
    expect(() =>
      parseCredentialClaim(
        { ...claim, credential_epoch: "01" },
        fixture.product_id,
      ),
    ).toThrow("credential claim");
    expect(() =>
      parseCredentialClaim({ ...claim, max_devices: 255 }, fixture.product_id),
    ).toThrow("credential claim");
  });
});
