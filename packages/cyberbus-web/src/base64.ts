const BASE64URL = /^[A-Za-z0-9_-]*$/u;

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_")
    .replace(/=+$/u, "");
}

export function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  if (!BASE64URL.test(value) || value.length % 4 === 1) {
    throw new Error("invalid base64url");
  }
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded.replace(/-/gu, "+").replace(/_/gu, "/"));
  } catch {
    throw new Error("invalid base64url");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(value);
  return new Uint8Array(encoded);
}

export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

export function fromHex(value: string): Uint8Array<ArrayBuffer> {
  if (!/^(?:[0-9a-f]{2})*$/u.test(value)) {
    throw new Error("invalid lowercase hex");
  }
  const out = new Uint8Array(value.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

export function concatBytes(
  ...parts: Uint8Array[]
): Uint8Array<ArrayBuffer> {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function u32(value: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function u64(value: bigint | number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

/** Length-prefix UTF-8 fields exactly as cyberbus-auth credentials.rs. */
export function encodeFields(
  fields: readonly string[],
): Uint8Array<ArrayBuffer> {
  const encoded = fields.map(utf8);
  return concatBytes(
    ...encoded.flatMap((field) => [u32(field.length), field]),
  );
}

/** Length-prefix arbitrary byte fields with the same u32 framing. */
export function encodeByteFields(
  fields: readonly Uint8Array[],
): Uint8Array<ArrayBuffer> {
  return concatBytes(
    ...fields.flatMap((field) => [u32(field.length), field]),
  );
}

export function randomBytes(
  length: number,
  cryptoApi: Crypto = globalThis.crypto,
): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(length);
  cryptoApi.getRandomValues(out);
  return out;
}

export function isWellFormed(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false;
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}
