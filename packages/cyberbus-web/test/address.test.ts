import { describe, expect, it } from "vitest";
import fixture from "../../../crates/cyberbus-auth/tests/fixtures/derivation.json";
import { candidateIpv4 } from "../src/address.js";

const INSTALLATION_ID = Uint8Array.from({ length: 32 }, (_, index) => index);

describe("overlay address candidate", () => {
  it("matches the Rust AddressPool fixture for the /20 pool", async () => {
    expect(
      await candidateIpv4(
        globalThis.crypto,
        fixture.network_name,
        INSTALLATION_ID,
      ),
    ).toBe("10.144.0.117");
    expect(
      await candidateIpv4(
        globalThis.crypto,
        fixture.network_name,
        INSTALLATION_ID,
        1,
      ),
    ).toBe("10.144.0.118");
    expect(
      await candidateIpv4(
        globalThis.crypto,
        fixture.network_name,
        INSTALLATION_ID,
        4_093,
      ),
    ).toBe("10.144.0.116");
    expect(
      await candidateIpv4(
        globalThis.crypto,
        fixture.network_name,
        INSTALLATION_ID,
        4_094,
      ),
    ).toBe("10.144.0.117");
  });

  it("rejects an installation ID that is not 32 bytes", async () => {
    await expect(
      candidateIpv4(globalThis.crypto, fixture.network_name, new Uint8Array(31)),
    ).rejects.toThrow("installation ID");
  });
});
