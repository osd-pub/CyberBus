import {
  base64UrlDecode,
  base64UrlEncode,
  concatBytes,
  hex,
  isWellFormed,
  randomBytes,
  utf8,
} from "./base64.js";
import type { ResolvedCyberBusWebConfig } from "./config.js";
import {
  deriveNetworkMaterial,
  parseCredentialClaim,
  type Account,
  type NetworkMaterial,
} from "./credentials.js";
import { CyberBusWebError, fail } from "./errors.js";
import {
  array,
  integer,
  parseStrictJson,
  parseStrictJsonBytes,
  record,
  string,
} from "./json.js";

export const CREDENTIAL_CLAIM =
  "https://cyberbus.x.aixgg.com/easytier/credentials/v1";

const MAX_JWT_LENGTH = 65_536;
const MAX_DOCUMENT_LENGTH = 1_048_576;
const CLOCK_SKEW_SECONDS = 60;
const JWKS_CACHE_SECONDS = 300;

export type AuthIntent = "login" | "register";

export interface OidcDiscovery {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly revocationEndpoint?: string;
}

export interface PendingAuth {
  readonly intent: AuthIntent;
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
  readonly challenge: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface Tokens {
  readonly accessToken: string;
  readonly idToken?: string;
  readonly refreshToken?: string;
  readonly expiresIn?: number;
}

export interface VerifiedAuth {
  readonly account: Account;
  readonly material: NetworkMaterial;
  readonly accessTokenExpiresAt: number;
  readonly tokens: Tokens;
}

interface ParsedJwt {
  readonly header: Record<string, unknown>;
  readonly claims: Record<string, unknown>;
  readonly signingInput: Uint8Array<ArrayBuffer>;
  readonly signature: Uint8Array<ArrayBuffer>;
}

interface JwksCache {
  readonly fetchedAt: number;
  readonly keys: readonly unknown[];
}

export class OidcClient {
  private discoveryPromise: Promise<OidcDiscovery> | undefined;
  private jwksCache: JwksCache | undefined;

  constructor(
    private readonly config: ResolvedCyberBusWebConfig,
    private readonly fetchImpl: typeof fetch,
    private readonly crypto: Crypto,
    private readonly now: () => number,
  ) {}

  async discover(): Promise<OidcDiscovery> {
    this.discoveryPromise ??= this.loadDiscovery().catch((error: unknown) => {
      this.discoveryPromise = undefined;
      throw error;
    });
    return this.discoveryPromise;
  }

  async createPending(intent: AuthIntent): Promise<PendingAuth> {
    const verifier = base64UrlEncode(randomBytes(32, this.crypto));
    const challenge = base64UrlEncode(
      new Uint8Array(
        await this.crypto.subtle.digest("SHA-256", utf8(verifier)),
      ),
    );
    const now = this.now();
    return {
      intent,
      state: hex(randomBytes(32, this.crypto)),
      nonce: hex(randomBytes(32, this.crypto)),
      verifier,
      challenge,
      createdAt: now,
      expiresAt: now + Math.floor(this.config.authTimeoutMs / 1000),
    };
  }

  async authorizationUrl(pending: PendingAuth): Promise<string> {
    const discovery = await this.discover();
    const url = new URL(discovery.authorizationEndpoint);
    const scope = ["openid", "network:join"];
    if (this.config.offlineAccess) {
      scope.push("offline_access");
    }
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("redirect_uri", this.config.redirectUri);
    url.searchParams.set("scope", scope.join(" "));
    url.searchParams.set("resource", this.config.resource);
    url.searchParams.set("state", pending.state);
    url.searchParams.set("nonce", pending.nonce);
    url.searchParams.set("code_challenge", pending.challenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("max_age", "0");
    url.searchParams.set(
      "prompt",
      this.config.offlineAccess ? "login consent" : "login",
    );
    if (pending.intent === "register") {
      url.searchParams.set("first_screen", "register");
    }
    return url.toString();
  }

  async exchangeCode(pending: PendingAuth, callbackUri: string): Promise<Tokens> {
    const callback = this.parseCallback(callbackUri, pending);
    const discovery = await this.discover();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: callback.code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: pending.verifier,
      resource: this.config.resource,
    });
    return this.tokenRequest(discovery.tokenEndpoint, body, false);
  }

  async refresh(refreshToken: string): Promise<Tokens> {
    const discovery = await this.discover();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.clientId,
      resource: this.config.resource,
    });
    return this.tokenRequest(discovery.tokenEndpoint, body, true);
  }

  async verify(
    tokens: Tokens,
    options: {
      readonly nonce?: string;
      readonly authTimeStartedAt?: number;
      readonly expectedAccount?: Account;
    } = {},
  ): Promise<VerifiedAuth> {
    const discovery = await this.discover();
    const access = parseJwt(tokens.accessToken);
    validateHeader(access.header);
    await this.verifySignature(access, discovery.jwksUri);
    const claims = access.claims;
    temporal(claims, this.now());
    if (
      string(claims.iss) !== this.config.issuer ||
      string(claims.aud) !== this.config.resource ||
      string(claims.client_id) !== this.config.clientId ||
      (claims.azp !== undefined && claims.azp !== this.config.clientId) ||
      !string(claims.scope)
        ?.split(/\s+/u)
        .some((scope) => scope === "network:join") ||
      (claims.gty !== undefined &&
        !string(claims.gty)
          ?.split(/\s+/u)
          .every((grant) => grant !== "client_credentials")) ||
      (claims.kind !== undefined && claims.kind !== "AccessToken")
    ) {
      claimsError();
    }
    const subject = string(claims.sub);
    if (
      subject === undefined ||
      subject.length === 0 ||
      subject.length > 4096 ||
      !isWellFormed(subject)
    ) {
      claimsError();
    }
    const account: Account = {
      issuer: this.config.issuer,
      subject,
      productId: this.config.productId,
    };
    if (
      options.expectedAccount !== undefined &&
      (options.expectedAccount.issuer !== account.issuer ||
        options.expectedAccount.subject !== account.subject ||
        options.expectedAccount.productId !== account.productId)
    ) {
      claimsError();
    }

    if (options.nonce !== undefined) {
      if (tokens.idToken === undefined) {
        claimsError();
      }
      await this.verifyIdToken(
        tokens,
        options.nonce,
        options.authTimeStartedAt ?? 0,
        subject,
        discovery.jwksUri,
      );
    } else if (tokens.idToken !== undefined) {
      await this.verifyIdToken(
        tokens,
        undefined,
        options.authTimeStartedAt ?? 0,
        subject,
        discovery.jwksUri,
      );
    }

    const claim = parseCredentialClaim(claims[CREDENTIAL_CLAIM], this.config.productId);
    const material = await deriveNetworkMaterial(this.crypto, account, claim);
    return {
      account,
      material,
      accessTokenExpiresAt: integer(claims.exp) ?? 0,
      tokens,
    };
  }

  async revoke(token: string): Promise<void> {
    const discovery = await this.discover();
    if (discovery.revocationEndpoint === undefined) {
      return;
    }
    const body = new URLSearchParams({
      token,
      token_type_hint: "refresh_token",
      client_id: this.config.clientId,
    });
    const response = await this.request(discovery.revocationEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!response.ok) {
      fail("AUTH_FAILED", "Logto token revocation failed", true);
    }
  }

  private async verifyIdToken(
    tokens: Tokens,
    nonce: string | undefined,
    authTimeStartedAt: number,
    subject: string,
    jwksUri: string,
  ): Promise<void> {
    if (tokens.idToken === undefined) {
      claimsError();
    }
    const id = parseJwt(tokens.idToken);
    validateHeader(id.header);
    await this.verifySignature(id, jwksUri);
    const claims = id.claims;
    const now = this.now();
    temporal(claims, now);
    const audience = claims.aud;
    const audienceMatches =
      audience === this.config.clientId ||
      (Array.isArray(audience) &&
        audience.length > 0 &&
        audience.every((item) => typeof item === "string") &&
        audience.includes(this.config.clientId));
    const multipleAudiences =
      Array.isArray(audience) && audience.length > 1;
    if (
      string(claims.iss) !== this.config.issuer ||
      !audienceMatches ||
      (multipleAudiences && claims.azp !== this.config.clientId) ||
      (claims.azp !== undefined && claims.azp !== this.config.clientId) ||
      string(claims.sub) !== subject ||
      (nonce !== undefined && claims.nonce !== nonce)
    ) {
      claimsError();
    }
    if (nonce !== undefined) {
      const authTime = integer(claims.auth_time);
      if (
        authTime === undefined ||
        authTime < authTimeStartedAt - CLOCK_SKEW_SECONDS ||
        authTime > now + CLOCK_SKEW_SECONDS
      ) {
        claimsError();
      }
    }
    if (claims.at_hash !== undefined) {
      const expected = string(claims.at_hash);
      if (expected === undefined) {
        claimsError();
      }
      const hash =
        id.header.alg === "ES384" ? "SHA-384" : "SHA-256";
      const length = hash === "SHA-384" ? 24 : 16;
      const digest = new Uint8Array(
        await this.crypto.subtle.digest(hash, utf8(tokens.accessToken)),
      );
      if (!constantTimeString(expected, base64UrlEncode(digest.subarray(0, length)))) {
        claimsError();
      }
    }
  }

  private async verifySignature(jwt: ParsedJwt, jwksUri: string): Promise<void> {
    const kid = string(jwt.header.kid);
    if (kid === undefined) {
      claimsError();
    }
    const alg = string(jwt.header.alg);
    if (alg === undefined) {
      claimsError();
    }
    let keys = await this.jwks(jwksUri, false);
    let candidates = keys.filter(
      (key) => string(record(key)?.kid) === kid,
    );
    if (candidates.length === 0) {
      keys = await this.jwks(jwksUri, true);
      candidates = keys.filter((key) => string(record(key)?.kid) === kid);
    }
    if (candidates.length !== 1) {
      claimsError();
    }
    const jwk = record(candidates[0]);
    if (jwk === undefined) {
      claimsError();
    }
    if (
      jwk.d !== undefined ||
      (jwk.use !== undefined && jwk.use !== "sig") ||
      (jwk.alg !== undefined && jwk.alg !== alg) ||
      (jwk.key_ops !== undefined &&
        (!Array.isArray(jwk.key_ops) ||
          !jwk.key_ops.includes("verify"))) ||
      (alg === "RS256" && jwk.kty !== "RSA") ||
      ((alg === "ES256" || alg === "ES384") && jwk.kty !== "EC") ||
      (alg === "ES256" && jwk.crv !== "P-256") ||
      (alg === "ES384" && jwk.crv !== "P-384")
    ) {
      claimsError();
    }
    const algorithm: RsaHashedImportParams | EcKeyImportParams =
      alg === "RS256"
        ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
        : alg === "ES256"
          ? { name: "ECDSA", namedCurve: "P-256" }
          : { name: "ECDSA", namedCurve: "P-384" };
    let key: CryptoKey;
    try {
      key = await this.crypto.subtle.importKey(
        "jwk",
        jwk as JsonWebKey,
        algorithm,
        false,
        ["verify"],
      );
    } catch {
      claimsError();
    }
    const verifyAlgorithm: Algorithm | EcdsaParams =
      alg === "RS256"
        ? { name: "RSASSA-PKCS1-v1_5" }
        : {
            name: "ECDSA",
            hash: alg === "ES256" ? "SHA-256" : "SHA-384",
          };
    let valid = false;
    try {
      valid = await this.crypto.subtle.verify(
        verifyAlgorithm,
        key,
        jwt.signature,
        jwt.signingInput,
      );
    } catch {
      claimsError();
    }
    if (!valid) {
      claimsError();
    }
  }

  private async jwks(
    jwksUri: string,
    force: boolean,
  ): Promise<readonly unknown[]> {
    const now = this.now();
    if (
      !force &&
      this.jwksCache !== undefined &&
      now - this.jwksCache.fetchedAt < JWKS_CACHE_SECONDS
    ) {
      return this.jwksCache.keys;
    }
    const response = await this.request(jwksUri, {
      method: "GET",
      headers: { accept: "application/json" },
    });
    if (!response.ok) {
      fail("AUTH_FAILED", "Logto JWKS request failed", true);
    }
    const document = parseStrictJson(await boundedText(response));
    const keys = array(record(document)?.keys);
    if (keys === undefined || keys.length === 0) {
      claimsError();
    }
    this.jwksCache = { fetchedAt: now, keys };
    return keys;
  }

  private async loadDiscovery(): Promise<OidcDiscovery> {
    const response = await this.request(
      `${this.config.issuer}/.well-known/openid-configuration`,
      {
        method: "GET",
        headers: { accept: "application/json" },
      },
    );
    if (!response.ok) {
      fail("AUTH_FAILED", "Logto discovery request failed", true);
    }
    const document = record(parseStrictJson(await boundedText(response)));
    if (
      document === undefined ||
      document.issuer !== this.config.issuer ||
      !array(document.response_types_supported)?.includes("code") ||
      !array(document.code_challenge_methods_supported)?.includes("S256") ||
      !array(document.id_token_signing_alg_values_supported)?.some(
        (algorithm) =>
          algorithm === "RS256" ||
          algorithm === "ES256" ||
          algorithm === "ES384",
      )
    ) {
      fail("AUTH_FAILED", "Logto discovery document is incompatible");
    }
    const issuer = new URL(this.config.issuer);
    const endpoint = (name: string, required: boolean): string | undefined => {
      const value = string(document[name]);
      if (value === undefined) {
        if (required) {
          fail("AUTH_FAILED", "Logto discovery is missing an endpoint");
        }
        return undefined;
      }
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        fail("AUTH_FAILED", "Logto discovery contains an invalid endpoint");
      }
      if (
        url.origin !== issuer.origin ||
        url.username !== "" ||
        url.password !== "" ||
        url.search !== "" ||
        url.hash !== ""
      ) {
        fail("AUTH_FAILED", "Logto discovery endpoint is not trusted");
      }
      return value;
    };
    const authorizationEndpoint = endpoint("authorization_endpoint", true);
    const tokenEndpoint = endpoint("token_endpoint", true);
    const jwksUri = endpoint("jwks_uri", true);
    if (
      authorizationEndpoint === undefined ||
      tokenEndpoint === undefined ||
      jwksUri === undefined
    ) {
      fail("AUTH_FAILED", "Logto discovery is incomplete");
    }
    const revocationEndpoint = endpoint("revocation_endpoint", false);
    return {
      issuer: this.config.issuer,
      authorizationEndpoint,
      tokenEndpoint,
      jwksUri,
      ...(revocationEndpoint === undefined ? {} : { revocationEndpoint }),
    };
  }

  private async tokenRequest(
    endpoint: string,
    body: URLSearchParams,
    refresh: boolean,
  ): Promise<Tokens> {
    const response = await this.request(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });
    if (!response.ok) {
      const error = await tokenError(response);
      if (refresh && error === "invalid_grant") {
        fail("SESSION_EXPIRED", "Logto session is no longer valid");
      }
      fail("AUTH_FAILED", "Logto token request failed");
    }
    const document = record(parseStrictJson(await boundedText(response)));
    if (document === undefined) {
      claimsError();
    }
    const accessToken = string(document.access_token);
    const idToken = document.id_token === undefined
      ? undefined
      : string(document.id_token);
    const refreshToken = document.refresh_token === undefined
      ? undefined
      : string(document.refresh_token);
    if (
      accessToken === undefined ||
      accessToken.length === 0 ||
      accessToken.length > MAX_JWT_LENGTH ||
      (document.id_token !== undefined &&
        (idToken === undefined ||
          idToken.length === 0 ||
          idToken.length > MAX_JWT_LENGTH)) ||
      (document.refresh_token !== undefined &&
        (refreshToken === undefined ||
          refreshToken.length === 0 ||
          refreshToken.length > MAX_JWT_LENGTH)) ||
      (document.token_type !== undefined &&
        string(document.token_type)?.toLowerCase() !== "bearer") ||
      (document.expires_in !== undefined &&
        (integer(document.expires_in) === undefined ||
          (integer(document.expires_in) ?? 0) <= 0))
    ) {
      claimsError();
    }
    const expiresIn = integer(document.expires_in);
    return {
      accessToken,
      ...(idToken === undefined ? {} : { idToken }),
      ...(refreshToken === undefined ? {} : { refreshToken }),
      ...(expiresIn === undefined ? {} : { expiresIn }),
    };
  }

  private parseCallback(
    callbackUri: string,
    pending: PendingAuth,
  ): { readonly code: string } {
    if (callbackUri.length === 0 || callbackUri.length > 16_384) {
      claimsError();
    }
    let callback: URL;
    try {
      callback = new URL(callbackUri);
    } catch {
      claimsError();
    }
    const redirect = new URL(this.config.redirectUri);
    if (
      callback.origin !== redirect.origin ||
      callback.pathname !== redirect.pathname ||
      callback.username !== "" ||
      callback.password !== "" ||
      callback.hash !== "" ||
      hasDuplicateQueryKeys(callback.search)
    ) {
      claimsError();
    }
    if (callback.searchParams.get("state") !== pending.state) {
      fail("AUTH_CANCELLED", "Logto callback state did not match");
    }
    const issuer = callback.searchParams.get("iss");
    if (issuer !== null && issuer !== this.config.issuer) {
      claimsError();
    }
    const error = callback.searchParams.get("error");
    if (error !== null) {
      if (error === "access_denied" || error === "login_required") {
        fail("AUTH_CANCELLED", "Logto login was cancelled");
      }
      fail("AUTH_FAILED", "Logto authorization failed");
    }
    const code = callback.searchParams.get("code");
    if (code === null || code.length === 0 || code.length > 16_384) {
      claimsError();
    }
    return { code };
  }

  private async request(input: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      return await this.fetchImpl(input, {
        ...init,
        signal: controller.signal,
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
      });
    } catch {
      fail("AUTH_FAILED", "Logto request failed", true);
    } finally {
      clearTimeout(timeout);
    }
  }
}

function parseJwt(token: string): ParsedJwt {
  if (token.length === 0 || token.length > MAX_JWT_LENGTH) {
    claimsError();
  }
  const parts = token.split(".");
  if (
    parts.length !== 3 ||
    parts.some((part) => part.length === 0)
  ) {
    claimsError();
  }
  let header: unknown = undefined;
  let claims: unknown = undefined;
  let signature = new Uint8Array();
  try {
    header = parseStrictJsonBytes(base64UrlDecode(parts[0] ?? ""));
    claims = parseStrictJsonBytes(base64UrlDecode(parts[1] ?? ""));
    signature = base64UrlDecode(parts[2] ?? "");
  } catch {
    claimsError();
  }
  const headerObject = record(header);
  const claimsObject = record(claims);
  if (headerObject === undefined || claimsObject === undefined) {
    claimsError();
  }
  return {
    header: headerObject,
    claims: claimsObject,
    signingInput: utf8(`${parts[0]}.${parts[1]}`),
    signature,
  };
}

function validateHeader(header: Record<string, unknown>): void {
  const alg = string(header.alg);
  const kid = string(header.kid);
  if (
    (alg !== "RS256" && alg !== "ES256" && alg !== "ES384") ||
    kid === undefined ||
    kid.length === 0 ||
    header.crit !== undefined ||
    header.b64 !== undefined ||
    header.jku !== undefined ||
    header.jwk !== undefined ||
    header.x5u !== undefined ||
    (header.typ !== undefined &&
      header.typ !== "JWT" &&
      header.typ !== "at+jwt")
  ) {
    claimsError();
  }
}

function temporal(claims: Record<string, unknown>, now: number): void {
  const iat = integer(claims.iat);
  const exp = integer(claims.exp);
  const nbf = claims.nbf === undefined ? undefined : integer(claims.nbf);
  if (
    iat === undefined ||
    exp === undefined ||
    iat > now + CLOCK_SKEW_SECONDS ||
    exp <= now - CLOCK_SKEW_SECONDS ||
    exp <= iat ||
    (claims.nbf !== undefined &&
      (nbf === undefined ||
        nbf > now + CLOCK_SKEW_SECONDS ||
        nbf >= exp))
  ) {
    claimsError();
  }
}

function hasDuplicateQueryKeys(search: string): boolean {
  const keys = new Set<string>();
  for (const pair of search.replace(/^\?/u, "").split("&")) {
    if (pair.length === 0) {
      continue;
    }
    let key: string;
    try {
      key = decodeURIComponent(pair.split("=", 1)[0] ?? "");
    } catch {
      return true;
    }
    if (keys.has(key)) {
      return true;
    }
    keys.add(key);
  }
  return false;
}

async function tokenError(response: Response): Promise<string | undefined> {
  try {
    const document = record(parseStrictJson(await boundedText(response)));
    return string(document?.error);
  } catch {
    return undefined;
  }
}

async function boundedText(response: Response): Promise<string> {
  let bytes: Uint8Array<ArrayBuffer>;
  const body = response.body;
  if (body === null) {
    bytes = new Uint8Array();
  } else {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) {
          break;
        }
        const value = chunk.value;
        total += value.byteLength;
        if (total > MAX_DOCUMENT_LENGTH) {
          await reader.cancel().catch(() => {});
          claimsError();
        }
        chunks.push(value);
      }
    } catch (error) {
      if (error instanceof CyberBusWebError) {
        throw error;
      }
      fail("AUTH_FAILED", "Logto response could not be read", true);
    } finally {
      reader.releaseLock();
    }
    bytes = concatBytes(...chunks);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    claimsError();
  }
}

function constantTimeString(left: string, right: string): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |=
      (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function claimsError(): never {
  return fail("INVALID_CLAIMS", "CyberBus token claims are invalid");
}
