import { fail } from "./errors.js";
import { isWellFormed } from "./base64.js";

export interface CyberBusWebConfig {
  /** Exact Logto issuer, normally `https://auth.example.com/oidc`. */
  issuer: string;
  /** Public SPA client ID registered for this redirect URI. */
  clientId: string;
  /** Exact Logto API resource used by the access token audience. */
  resource: string;
  /** Product namespace in the CyberBus credential claim. */
  productId: string;
  /** Registered callback page, for example `https://app.example.com/auth/callback.html`. */
  redirectUri: string;
  /** One or more browser-compatible EasyTier relay peers (`wss://`). */
  peers: string | readonly string[];
  /** EasyTier instance name shown in relay diagnostics. */
  instanceName?: string;
  /** Optional fixed overlay IPv4. Defaults to a deterministic /20 address. */
  ipv4?: string;
  /** EasyTier AES-GCM network encryption. Defaults to true. */
  encryption?: boolean;
  /** Request a refresh token held only in memory. Defaults to true. */
  offlineAccess?: boolean;
  /** Popup login budget in milliseconds. Defaults to 10 minutes. */
  authTimeoutMs?: number;
  /** Overlay TCP connect budget in milliseconds. Defaults to 10 seconds. */
  connectTimeoutMs?: number;
}

export interface ResolvedCyberBusWebConfig {
  issuer: string;
  clientId: string;
  resource: string;
  productId: string;
  redirectUri: string;
  redirectOrigin: string;
  peers: readonly string[];
  instanceName: string;
  ipv4?: string;
  encryption: boolean;
  offlineAccess: boolean;
  authTimeoutMs: number;
  connectTimeoutMs: number;
}

const VIRTUAL_CIDR = "10.144.0.0/20";
const MAX_DEVICES = 256;
const CONTROL_PORT = 11_000;
const CONFIG_VERSION = "1";

export function resolveConfig(config: CyberBusWebConfig): ResolvedCyberBusWebConfig {
  const issuer = validateIssuer(config.issuer);
  const resource = validateResource(config.resource);
  const clientId = nonempty(config.clientId, "clientId");
  const productId = nonempty(config.productId, "productId");
  if (resource === clientId) {
    invalid("resource must differ from clientId");
  }
  const redirect = validateRedirectUri(config.redirectUri);
  const peers = validatePeers(config.peers);
  const instanceName = config.instanceName ?? "cyberbus-web";
  if (
    instanceName.length === 0 ||
    instanceName.length > 128 ||
    !isWellFormed(instanceName)
  ) {
    invalid("instanceName must be 1..128 characters");
  }
  const ipv4 =
    config.ipv4 === undefined ? undefined : validateOverlayIpv4(config.ipv4);
  const authTimeoutMs = boundedInteger(
    config.authTimeoutMs ?? 600_000,
    30_000,
    900_000,
    "authTimeoutMs",
  );
  const connectTimeoutMs = boundedInteger(
    config.connectTimeoutMs ?? 10_000,
    1_000,
    120_000,
    "connectTimeoutMs",
  );
  return {
    issuer,
    clientId,
    resource,
    productId,
    redirectUri: redirect.href,
    redirectOrigin: redirect.origin,
    peers,
    instanceName,
    ...(ipv4 === undefined ? {} : { ipv4 }),
    encryption: config.encryption ?? true,
    offlineAccess: config.offlineAccess ?? true,
    authTimeoutMs,
    connectTimeoutMs,
  };
}

export const credentialConstants = Object.freeze({
  virtualCidr: VIRTUAL_CIDR,
  maxDevices: MAX_DEVICES,
  controlPort: CONTROL_PORT,
  configVersion: CONFIG_VERSION,
});

function validateIssuer(value: string): string {
  const url = parseUrl(value, "issuer");
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.pathname !== "/oidc" ||
    url.href !== value
  ) {
    invalid("issuer must be an exact HTTPS URL ending in /oidc");
  }
  return value;
}

function validateResource(value: string): string {
  const url = parseUrl(value, "resource");
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    value.length === 0
  ) {
    invalid("resource must be a nonempty HTTPS URL without userinfo or fragment");
  }
  return value;
}

function validateRedirectUri(value: string): URL {
  const url = parseUrl(value, "redirectUri");
  const loopback =
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]" ||
    url.hostname === "localhost";
  if (
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
  ) {
    invalid("redirectUri must be HTTPS or an HTTP loopback callback");
  }
  return url;
}

function validatePeers(value: string | readonly string[]): readonly string[] {
  const peers = typeof value === "string" ? [value] : [...value];
  if (peers.length === 0 || peers.length > 64) {
    invalid("peers must contain 1..64 WebSocket URLs");
  }
  for (const peer of peers) {
    const url = parseUrl(peer, "peer");
    const loopback =
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]" ||
      url.hostname === "localhost";
    if (
      (url.protocol !== "wss:" && !(url.protocol === "ws:" && loopback)) ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== ""
    ) {
      invalid("peers must be wss:// URLs (ws:// is allowed only on loopback)");
    }
  }
  return peers;
}

function validateOverlayIpv4(value: string): string {
  const [address, prefixText, extra] = value.split("/");
  if (address === undefined || extra !== undefined) {
    invalid("ipv4 must be an IPv4 address or CIDR");
  }
  const prefix = prefixText === undefined ? 20 : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix !== 20) {
    invalid("ipv4 prefix must be /20");
  }
  const numeric = ipv4Number(address);
  const pool = ipv4Number("10.144.0.0");
  const usable = 4094;
  if (numeric <= pool || numeric > pool + usable) {
    invalid("ipv4 must be inside 10.144.0.0/20");
  }
  return `${address}/${prefix}`;
}

function parseUrl(value: string, field: string): URL {
  try {
    return new URL(value);
  } catch {
    invalid(`${field} must be an absolute URL`);
  }
}

function nonempty(value: string, field: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !isWellFormed(value)
  ) {
    invalid(`${field} must be nonempty`);
  }
  return value;
}

function boundedInteger(
  value: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${field} must be an integer in ${minimum}..${maximum}`);
  }
  return value;
}

function invalid(message: string): never {
  return fail("INVALID_CONFIG", message);
}

export function ipv4Number(value: string): number {
  const parts = value.split(".");
  if (parts.length !== 4) {
    invalid("invalid IPv4 address");
  }
  let out = 0;
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(part)) {
      invalid("invalid IPv4 address");
    }
    const octet = Number(part);
    if (octet > 255) {
      invalid("invalid IPv4 address");
    }
    out = (out * 256 + octet) >>> 0;
  }
  return out;
}

export function ipv4String(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join(".");
}
