import { concatBytes, u64, utf8 } from "./base64.js";
import { ipv4Number, ipv4String } from "./config.js";

const POOL = ipv4Number("10.144.0.0");
const USABLE = 4094;

/** Mirrors cyberbus-transport AddressPool::candidate for the v1 /20 pool. */
export async function candidateIpv4(
  crypto: Crypto,
  networkName: string,
  installationId: Uint8Array,
  offset = 0,
): Promise<string> {
  if (installationId.length !== 32) {
    throw new Error("installation ID must be 32 bytes");
  }
  const network = new Uint8Array(4);
  new DataView(network.buffer).setUint32(0, POOL, false);
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concatBytes(
        utf8("cyberbus/address/v1"),
        u64(utf8(networkName).length),
        utf8(networkName),
        network,
        new Uint8Array([20]),
        installationId,
      ),
    ),
  );
  const base = new DataView(
    digest.buffer,
    digest.byteOffset,
    8,
  ).getBigUint64(0, false);
  const host = Number((base % BigInt(USABLE) + BigInt(offset)) % BigInt(USABLE));
  return ipv4String(POOL + 1 + host);
}
