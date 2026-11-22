import {
  base64UrlEncode,
  encodeByteFields,
  encodeFields,
  fromHex,
  hex,
  utf8,
} from "./base64.js";
import { credentialConstants } from "./config.js";
import { fail } from "./errors.js";
import { integer, parseStrictJsonBytes, record, string } from "./json.js";

export interface Account {
  readonly issuer: string;
  readonly subject: string;
  readonly productId: string;
}

export interface CredentialClaim {
  readonly version: 1;
  readonly productId: string;
  readonly credentialEpoch: string;
  readonly accountSeedSecretHex: string;
  readonly maxDevices: 256;
  readonly virtualCidr: "10.144.0.0/20";
  readonly controlPort: 11_000;
  readonly configVersion: "1";
}

export interface NetworkMaterial {
  readonly networkName: string;
  readonly networkSecret: string;
  readonly appPsk: Uint8Array;
  readonly bindingId: Uint8Array;
  readonly credentialEpoch: bigint;
}

const CLAIM_KEYS = new Set([
  "version",
  "product_id",
  "credential_epoch",
  "account_seed_secret_hex",
  "max_devices",
  "virtual_cidr",
  "control_port",
  "config_version",
]);

export function parseCredentialClaim(
  value: unknown,
  productId: string,
): CredentialClaim {
  const object = record(value);
  if (object === undefined) {
    claimsError();
  }
  const keys = Object.keys(object);
  if (
    keys.length !== CLAIM_KEYS.size ||
    keys.some((key) => !CLAIM_KEYS.has(key))
  ) {
    claimsError();
  }
  const version = integer(object.version);
  const claimProduct = string(object.product_id);
  const epoch = string(object.credential_epoch);
  const seed = string(object.account_seed_secret_hex);
  const maxDevices = integer(object.max_devices);
  const cidr = string(object.virtual_cidr);
  const controlPort = integer(object.control_port);
  const configVersion = string(object.config_version);
  if (
    version !== 1 ||
    claimProduct !== productId ||
    epoch === undefined ||
    !/^(?:0|[1-9][0-9]*)$/u.test(epoch) ||
    BigInt(epoch) > 18_446_744_073_709_551_615n ||
    seed === undefined ||
    !/^[0-9a-f]{64}$/u.test(seed) ||
    maxDevices !== credentialConstants.maxDevices ||
    cidr !== credentialConstants.virtualCidr ||
    controlPort !== credentialConstants.controlPort ||
    configVersion !== credentialConstants.configVersion
  ) {
    claimsError();
  }
  return {
    version: 1,
    productId: claimProduct,
    credentialEpoch: epoch,
    accountSeedSecretHex: seed,
    maxDevices: 256,
    virtualCidr: "10.144.0.0/20",
    controlPort: 11_000,
    configVersion: "1",
  };
}

export async function deriveNetworkMaterial(
  crypto: Crypto,
  account: Account,
  claim: CredentialClaim,
): Promise<NetworkMaterial> {
  const seed = fromHex(claim.accountSeedSecretHex);
  try {
    const scope = encodeFields([
      "cyberbus/seed/v1",
      account.issuer,
      account.subject,
      account.productId,
      claim.credentialEpoch,
    ]);
    const salt = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        encodeByteFields([utf8("cyberbus/v1"), scope]),
      ),
    );
    const key = await crypto.subtle.importKey(
      "raw",
      seed,
      "HKDF",
      false,
      ["deriveBits"],
    );
    const expand = async (info: string, length: number): Promise<Uint8Array> =>
      new Uint8Array(
        await crypto.subtle.deriveBits(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt,
            info: utf8(info),
          },
          key,
          length * 8,
        ),
      );
    const nameBytes = await expand("network-name", 16);
    const secretBytes = await expand("network-secret", 32);
    const appPsk = await expand("app-handshake-psk", 32);
    const bindingId = await expand("session-binding-id/v1", 32);
    return {
      networkName: `cg-et-mvp-${hex(nameBytes)}`,
      networkSecret: base64UrlEncode(secretBytes),
      appPsk,
      bindingId,
      credentialEpoch: BigInt(claim.credentialEpoch),
    };
  } finally {
    seed.fill(0);
  }
}

export function sameNetworkMaterial(
  left: NetworkMaterial,
  right: NetworkMaterial,
): boolean {
  return (
    left.credentialEpoch === right.credentialEpoch &&
    constantTimeEqual(utf8(left.networkName), utf8(right.networkName)) &&
    constantTimeEqual(utf8(left.networkSecret), utf8(right.networkSecret)) &&
    constantTimeEqual(left.appPsk, right.appPsk) &&
    constantTimeEqual(left.bindingId, right.bindingId)
  );
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function claimsError(): never {
  return fail("INVALID_CLAIMS", "CyberBus credential claim is invalid");
}
