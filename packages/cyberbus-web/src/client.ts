import { candidateIpv4 } from "./address.js";
import { randomBytes } from "./base64.js";
import {
  ipv4Number,
  resolveConfig,
  type CyberBusWebConfig,
  type ResolvedCyberBusWebConfig,
} from "./config.js";
import {
  sameNetworkMaterial,
} from "./credentials.js";
import { CyberBusWebError, fail } from "./errors.js";
import {
  loadEasyTierBrowser,
  type EasyTierFactory,
  type EasyTierInstance,
  type EasyTierTcpStream,
} from "./easytier.js";
import {
  OidcClient,
  type AuthIntent,
  type PendingAuth,
  type VerifiedAuth,
} from "./oidc.js";
import { TcpConnection } from "./stream.js";

export interface CyberBusWebOptions {
  /** Injection point for tests or a host-provided bundling wrapper. */
  createEasyTier?: EasyTierFactory;
  fetch?: typeof fetch;
  crypto?: Crypto;
  /** Unix seconds. */
  now?: () => number;
  openWindow?: (
    url: string,
    target: string,
    features?: string,
  ) => Window | null;
  onEvent?: (event: CyberBusWebEvent) => void;
}

export interface AuthSnapshot {
  readonly phase:
    | "logged-out"
    | "authorizing"
    | "authenticated"
    | "reauth-required"
    | "closed";
  readonly account?: {
    readonly issuer: string;
    readonly subject: string;
    readonly productId: string;
  };
  readonly accessTokenExpiresAt?: string;
  readonly validationLeaseExpiresAt?: string;
  readonly refreshSupported: boolean;
}

export interface NetworkSnapshot {
  readonly phase: "stopped" | "starting" | "running" | "stopping" | "failed";
  readonly ipv4?: string;
  readonly connections?: number;
}

export type CyberBusWebEvent =
  | { readonly type: "auth"; readonly state: AuthSnapshot }
  | { readonly type: "network"; readonly state: NetworkSnapshot }
  | {
      readonly type: "credentials-changed";
      readonly message: string;
    }
  | {
      readonly type: "error";
      readonly code: string;
      readonly message: string;
      readonly retryable: boolean;
    }
  | { readonly type: "easytier"; readonly kind: string };

export interface LoginHandle {
  readonly authorizationUrl: string;
  /** Unix seconds. */
  readonly expiresAt: number;
}

export interface LoginOptions {
  readonly intent?: AuthIntent;
  readonly popupName?: string;
  readonly windowFeatures?: string;
}

export interface ConnectOptions {
  readonly timeoutMs?: number;
}

const VALIDATION_LEASE_MS = 10 * 60 * 1000;
const VALIDATION_MIN_MS = 4 * 60 * 1000;
const VALIDATION_MAX_MS = 6 * 60 * 1000;
export const AUTH_CALLBACK_MESSAGE = "cyberbus-web-auth-callback/v1";

export class CyberBusWeb {
  readonly config: ResolvedCyberBusWebConfig;

  private readonly crypto: Crypto;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly openWindow: NonNullable<CyberBusWebOptions["openWindow"]>;
  private readonly onEvent: ((event: CyberBusWebEvent) => void) | undefined;
  private readonly installationId: Uint8Array;
  private readonly oidc: OidcClient;
  private readonly streams = new Set<TcpConnection>();
  private factory: EasyTierFactory | undefined;
  private instance: EasyTierInstance | undefined;
  private pending: PendingAuth | undefined;
  private session: VerifiedAuth | undefined;
  private sessionEpoch = 0;
  private networkPhase: NetworkSnapshot["phase"] = "stopped";
  private networkIpv4: string | undefined;
  private networkStart: Promise<void> | undefined;
  private networkEpoch = 0;
  private refreshInFlight: Promise<AuthSnapshot> | undefined;
  private validationTimer: ReturnType<typeof setTimeout> | undefined;
  private expiryTimer: ReturnType<typeof setTimeout> | undefined;
  private leaseStartedAt = 0;
  private leaseExpiresAt = 0;
  private closed = false;
  private reauthRequired = false;

  private constructor(
    config: CyberBusWebConfig,
    options: CyberBusWebOptions,
  ) {
    this.config = resolveConfig(config);
    const crypto = options.crypto ?? globalThis.crypto;
    if (crypto === undefined || crypto.subtle === undefined) {
      fail("UNSUPPORTED", "Web Crypto is required");
    }
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      fail("UNSUPPORTED", "fetch is required");
    }
    this.crypto = crypto;
    this.installationId = randomBytes(32, crypto);
    this.fetchImpl = options.fetch ?? fetchImpl.bind(globalThis);
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.openWindow =
      options.openWindow ??
      ((url, target, features) =>
        globalThis.window.open(url, target, features));
    this.onEvent = options.onEvent;
    this.factory = options.createEasyTier;
    this.oidc = new OidcClient(
      this.config,
      this.fetchImpl,
      this.crypto,
      this.now,
    );
  }

  static create(
    config: CyberBusWebConfig,
    options: CyberBusWebOptions = {},
  ): CyberBusWeb {
    return new CyberBusWeb(config, options);
  }

  get authState(): AuthSnapshot {
    return this.authSnapshot();
  }

  get networkState(): NetworkSnapshot {
    return this.networkSnapshot();
  }

  async beginLogin(intent: AuthIntent = "login"): Promise<LoginHandle> {
    this.requireOpen();
    if (this.pending !== undefined) {
      if (this.now() <= this.pending.expiresAt) {
        fail("AUTH_FAILED", "another login is already pending");
      }
      this.pending = undefined;
    }
    const pending = await this.oidc.createPending(intent);
    const authorizationUrl = await this.oidc.authorizationUrl(pending);
    this.pending = pending;
    this.emitAuth();
    return {
      authorizationUrl,
      expiresAt: pending.expiresAt,
    };
  }

  async completeLogin(callbackUri: string): Promise<AuthSnapshot> {
    this.requireOpen();
    const pending = this.pending;
    if (pending === undefined) {
      fail("AUTH_FAILED", "no login is pending");
    }
    if (this.now() > pending.expiresAt) {
      this.pending = undefined;
      this.emitAuth();
      fail("AUTH_TIMEOUT", "login expired");
    }
    try {
      const tokens = await this.oidc.exchangeCode(pending, callbackUri);
      const verified = await this.oidc.verify(tokens, {
        nonce: pending.nonce,
        authTimeStartedAt: pending.createdAt,
      });
      if (this.networkPhase !== "stopped") {
        this.replaceSession(undefined);
        await this.stopNetwork();
      }
      this.pending = undefined;
      this.replaceSession(verified);
      this.reauthRequired = false;
      this.leaseStartedAt = this.now();
      this.leaseExpiresAt = this.leaseStartedAt + VALIDATION_LEASE_MS / 1000;
      this.emitAuth();
      return this.authSnapshot();
    } catch (error) {
      this.pending = undefined;
      this.emitAuth();
      throw sanitize(error);
    }
  }

  async login(options: LoginOptions = {}): Promise<AuthSnapshot> {
    this.requireOpen();
    if (typeof globalThis.window === "undefined") {
      fail("UNSUPPORTED", "popup login requires a browser window");
    }
    const popup = this.openWindow(
      "about:blank",
      options.popupName ?? "cyberbus-web-auth",
      options.windowFeatures ??
        "popup,width=480,height=720,resizable=yes,scrollbars=yes",
    );
    if (popup === null) {
      fail("POPUP_BLOCKED", "the login popup was blocked");
    }
    let began = false;
    try {
      const handle = await this.beginLogin(options.intent ?? "login");
      began = true;
      popup.location.replace(handle.authorizationUrl);
      const callbackUri = await this.waitForCallback(
        popup,
        this.config.authTimeoutMs,
      );
      return await this.completeLogin(callbackUri);
    } catch (error) {
      popup.close();
      if (began && this.pending !== undefined) {
        this.pending = undefined;
        this.emitAuth();
      }
      throw sanitize(error);
    }
  }

  cancelLogin(): void {
    this.requireOpen();
    this.pending = undefined;
    this.emitAuth();
  }

  async startNetwork(): Promise<NetworkSnapshot> {
    this.requireOpen();
    const session = this.requireUsableSession();
    if (this.networkPhase === "running") {
      return this.networkSnapshot();
    }
    if (this.networkStart !== undefined) {
      await this.networkStart;
      return this.networkSnapshot();
    }
    const epoch = ++this.networkEpoch;
    const start = this.startNetworkInner(session, epoch);
    this.networkStart = start;
    try {
      await start;
    } finally {
      if (this.networkStart === start) {
        this.networkStart = undefined;
      }
    }
    return this.networkSnapshot();
  }

  async stopNetwork(): Promise<void> {
    const epoch = ++this.networkEpoch;
    this.networkStart = undefined;
    this.clearTimers();
    this.networkPhase = "stopping";
    this.emitNetwork();
    const instance = this.instance;
    this.instance = undefined;
    for (const stream of [...this.streams]) {
      await stream.close();
    }
    if (instance !== undefined) {
      try {
        await instance.close();
      } catch {
        // The instance is already terminal from the caller's perspective.
      }
    }
    if (epoch !== this.networkEpoch) {
      return;
    }
    this.networkPhase = "stopped";
    this.networkIpv4 = undefined;
    this.emitNetwork();
  }

  async connectTcp(
    host: string,
    port: number,
    options: ConnectOptions = {},
  ): Promise<TcpConnection> {
    this.requireOpen();
    this.requireUsableSession();
    if (
      this.networkPhase !== "running" ||
      this.instance === undefined
    ) {
      fail("NETWORK_NOT_STARTED", "startNetwork() must complete first");
    }
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      fail("INVALID_CONFIG", "TCP port must be in 1..65535");
    }
    try {
      ipv4Number(host);
    } catch {
      fail("INVALID_CONFIG", "overlay host must be a dotted IPv4 address");
    }
    const timeoutMs =
      options.timeoutMs ?? this.config.connectTimeoutMs;
    if (
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > 120_000
    ) {
      fail("INVALID_CONFIG", "connect timeout must be in 1..120000 ms");
    }
    const epoch = this.networkEpoch;
    let native: EasyTierTcpStream;
    try {
      native = await this.instance.connectTcp(`${host}:${port}`, {
        timeout: timeoutMs,
      });
    } catch {
      fail("CONNECTION_FAILED", "overlay TCP connection failed", true);
    }
    if (
      this.closed ||
      epoch !== this.networkEpoch ||
      this.networkPhase !== "running"
    ) {
      await native.close().catch(() => {});
      fail(
        "NETWORK_NOT_STARTED",
        "network stopped while the TCP connection was opening",
        true,
      );
    }
    const connection = new TcpConnection(native, (closed) => {
      this.streams.delete(closed);
    });
    this.streams.add(connection);
    return connection;
  }

  async openPort(
    host: string,
    port: number,
    options: ConnectOptions = {},
  ): Promise<TcpConnection> {
    return this.connectTcp(host, port, options);
  }

  async refresh(): Promise<AuthSnapshot> {
    this.requireOpen();
    if (this.refreshInFlight !== undefined) {
      return this.refreshInFlight;
    }
    const refresh = this.refreshInner();
    this.refreshInFlight = refresh;
    try {
      return await refresh;
    } finally {
      if (this.refreshInFlight === refresh) {
        this.refreshInFlight = undefined;
      }
    }
  }

  private async refreshInner(): Promise<AuthSnapshot> {
    const session = this.requireSession();
    if (this.reauthRequired) {
      fail(
        "CREDENTIALS_CHANGED",
        "CyberBus network credentials changed; login again",
      );
    }
    const sessionEpoch = this.sessionEpoch;
    const refreshToken = session.tokens.refreshToken;
    if (refreshToken === undefined) {
      fail("AUTH_FAILED", "Logto did not issue a refresh token");
    }
    const requestStartedAt = this.now();
    const tokens = await this.oidc.refresh(refreshToken);
    const verified = await this.oidc.verify(
      {
        ...tokens,
        refreshToken: tokens.refreshToken ?? refreshToken,
      },
      { expectedAccount: session.account },
    );
    if (this.closed || sessionEpoch !== this.sessionEpoch) {
      return this.authSnapshot();
    }
    const changed = !sameNetworkMaterial(session.material, verified.material);
    this.replaceSession(verified);
    this.leaseStartedAt = requestStartedAt;
    this.leaseExpiresAt = requestStartedAt + VALIDATION_LEASE_MS / 1000;
    if (changed) {
      this.reauthRequired = true;
      await this.stopNetwork();
      this.emit({
        type: "credentials-changed",
        message: "CyberBus network credentials changed; restart the network",
      });
      this.emitAuth();
      return this.authSnapshot();
    }
    this.reauthRequired = false;
    this.armExpiry();
    this.armValidation();
    this.emitAuth();
    return this.authSnapshot();
  }

  async logout(): Promise<void> {
    this.requireOpen();
    const refreshToken = this.session?.tokens.refreshToken;
    this.replaceSession(undefined);
    this.clearTimers();
    this.pending = undefined;
    this.reauthRequired = false;
    await this.stopNetwork();
    if (refreshToken !== undefined) {
      try {
        await this.oidc.revoke(refreshToken);
      } catch {
        // Local logout is authoritative; cloud revocation is best effort.
      }
    }
    this.emitAuth();
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.replaceSession(undefined);
    this.clearTimers();
    this.pending = undefined;
    this.reauthRequired = false;
    await this.stopNetwork().catch(() => {});
    this.emitAuth();
  }

  async status(): Promise<NetworkSnapshot> {
    this.requireOpen();
    const instance = this.instance;
    if (instance === undefined) {
      return this.networkSnapshot();
    }
    try {
      const status = await instance.status();
      return {
        ...this.networkSnapshot(),
        connections: status.connections,
      };
    } catch {
      fail("NETWORK_NOT_STARTED", "EasyTier status is unavailable", true);
    }
  }

  private async startNetworkInner(
    session: VerifiedAuth,
    epoch: number,
  ): Promise<void> {
    this.networkPhase = "starting";
    this.emitNetwork();
    try {
      this.factory ??= await loadEasyTierBrowser();
      if (this.closed || epoch !== this.networkEpoch) {
        return;
      }
      const ipv4 =
        this.config.ipv4 ??
        `${await candidateIpv4(
          this.crypto,
          session.material.networkName,
          this.installationId,
        )}/20`;
      const instance = await this.factory.create(
        {
          networkName: session.material.networkName,
          networkSecret: session.material.networkSecret,
          instanceName: this.config.instanceName,
          encryption: this.config.encryption,
          ipv4,
          peers: this.config.peers,
        },
        {
          onEvent: (event) => {
            this.emit({
              type: "easytier",
              kind: sanitizeKind(event.kind),
            });
          },
        },
      );
      if (this.closed || epoch !== this.networkEpoch) {
        await instance.close().catch(() => {});
        return;
      }
      this.instance = instance;
      this.networkIpv4 = ipv4.slice(0, ipv4.lastIndexOf("/"));
      this.networkPhase = "running";
      this.leaseStartedAt = this.now();
      this.leaseExpiresAt = this.leaseStartedAt + VALIDATION_LEASE_MS / 1000;
      this.armExpiry();
      this.armValidation();
      this.emitNetwork();
    } catch (error) {
      if (this.closed || epoch !== this.networkEpoch) {
        return;
      }
      this.instance = undefined;
      this.networkPhase = "failed";
      this.emitNetwork();
      if (error instanceof CyberBusWebError) {
        throw error;
      }
      fail("NETWORK_START_FAILED", "EasyTier browser startup failed");
    }
  }

  private requireSession(): VerifiedAuth {
    if (this.session === undefined) {
      fail("SESSION_EXPIRED", "login is required");
    }
    return this.session;
  }

  private requireUsableSession(): VerifiedAuth {
    const session = this.requireSession();
    const expiresAt = Math.min(
      session.accessTokenExpiresAt,
      this.leaseExpiresAt,
    );
    if (this.now() >= expiresAt) {
      this.replaceSession(undefined);
      void this.stopNetwork().catch(() => {});
      this.reauthRequired = true;
      this.emitAuth();
      fail("SESSION_EXPIRED", "CyberBus login validation expired");
    }
    if (this.reauthRequired) {
      fail(
        "CREDENTIALS_CHANGED",
        "CyberBus network credentials changed; login again",
      );
    }
    return session;
  }

  private armExpiry(): void {
    this.clearExpiryTimer();
    const session = this.session;
    if (session === undefined) {
      return;
    }
    const expiresAt = Math.min(
      session.accessTokenExpiresAt,
      this.leaseExpiresAt,
    );
    const delay = Math.max(0, (expiresAt - this.now()) * 1000);
    this.expiryTimer = setTimeout(() => {
      this.replaceSession(undefined);
      this.reauthRequired = true;
      this.emitAuth();
      void this.stopNetwork().catch(() => {});
    }, delay);
  }

  private armValidation(): void {
    this.clearValidationTimer();
    if (
      this.session?.tokens.refreshToken === undefined ||
      this.networkPhase !== "running"
    ) {
      return;
    }
    const delay =
      VALIDATION_MIN_MS +
      Math.floor(Math.random() * (VALIDATION_MAX_MS - VALIDATION_MIN_MS));
    this.validationTimer = setTimeout(() => {
      void this.validateSession();
    }, delay);
  }

  private async validateSession(): Promise<void> {
    if (this.closed || this.networkPhase !== "running") {
      return;
    }
    try {
      await this.refresh();
    } catch (error) {
      const code = error instanceof CyberBusWebError ? error.code : "INTERNAL";
      if (
        code === "SESSION_EXPIRED" ||
        code === "INVALID_CLAIMS" ||
        code === "CREDENTIALS_CHANGED"
      ) {
        this.replaceSession(undefined);
        this.reauthRequired = true;
        this.emitAuth();
        await this.stopNetwork().catch(() => {});
        this.emitError(error);
        return;
      }
      this.emitError(error);
      if (this.now() >= this.leaseExpiresAt) {
        this.replaceSession(undefined);
        this.reauthRequired = true;
        this.emitAuth();
        await this.stopNetwork().catch(() => {});
      } else {
        this.validationTimer = setTimeout(() => {
          void this.validateSession();
        }, 60_000);
      }
    }
  }

  private async waitForCallback(
    popup: Window,
    timeoutMs: number,
  ): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let settled = false;
      const finish = (callback: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        globalThis.window.removeEventListener("message", onMessage);
        clearInterval(closedPoll);
        clearTimeout(timeout);
        callback();
      };
      const onMessage = (event: MessageEvent): void => {
        if (
          event.origin !== this.config.redirectOrigin ||
          event.source !== popup
        ) {
          return;
        }
        const data = event.data;
        if (
          data === null ||
          typeof data !== "object" ||
          (data as { type?: unknown }).type !== AUTH_CALLBACK_MESSAGE ||
          typeof (data as { url?: unknown }).url !== "string" ||
          (data as { url: string }).url.length > 16_384
        ) {
          return;
        }
        finish(() => resolve((data as { url: string }).url));
      };
      const closedPoll = setInterval(() => {
        if (popup.closed) {
          finish(() =>
            reject(
              new CyberBusWebError(
                "AUTH_CANCELLED",
                "the login window was closed",
              ),
            ),
          );
        }
      }, 500);
      const timeout = setTimeout(() => {
        finish(() =>
          reject(
            new CyberBusWebError("AUTH_TIMEOUT", "login timed out"),
          ),
        );
      }, timeoutMs);
      globalThis.window.addEventListener("message", onMessage);
    });
  }

  private authSnapshot(): AuthSnapshot {
    const session = this.session;
    return {
      phase: this.closed
        ? "closed"
        : this.reauthRequired
          ? "reauth-required"
          : session === undefined
            ? this.pending === undefined
              ? "logged-out"
              : "authorizing"
            : "authenticated",
      ...(session === undefined
        ? {}
        : {
            account: {
              issuer: session.account.issuer,
              subject: session.account.subject,
              productId: session.account.productId,
            },
            accessTokenExpiresAt: iso(session.accessTokenExpiresAt),
            validationLeaseExpiresAt: iso(this.leaseExpiresAt),
          }),
      refreshSupported: session?.tokens.refreshToken !== undefined,
    };
  }

  private networkSnapshot(): NetworkSnapshot {
    return {
      phase: this.networkPhase,
      ...(this.networkIpv4 === undefined
        ? {}
        : { ipv4: this.networkIpv4 }),
    };
  }

  private emitAuth(): void {
    this.emit({ type: "auth", state: this.authSnapshot() });
  }

  private emitNetwork(): void {
    this.emit({ type: "network", state: this.networkSnapshot() });
  }

  private emitError(error: unknown): void {
    const sanitized = sanitize(error);
    this.emit({
      type: "error",
      code: sanitized.code,
      message: sanitized.message,
      retryable: sanitized.retryable,
    });
  }

  private emit(event: CyberBusWebEvent): void {
    try {
      this.onEvent?.(event);
    } catch {
      // Application event handlers cannot corrupt SDK lifecycle.
    }
  }

  private replaceSession(session: VerifiedAuth | undefined): void {
    this.session = session;
    this.sessionEpoch += 1;
  }

  private clearTimers(): void {
    this.clearValidationTimer();
    this.clearExpiryTimer();
  }

  private clearValidationTimer(): void {
    if (this.validationTimer !== undefined) {
      clearTimeout(this.validationTimer);
      this.validationTimer = undefined;
    }
  }

  private clearExpiryTimer(): void {
    if (this.expiryTimer !== undefined) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = undefined;
    }
  }

  private requireOpen(): void {
    if (this.closed) {
      fail("CLOSED", "CyberBus web SDK is closed");
    }
  }
}

export function authCallbackMessage(callbackUri: string): {
  readonly type: typeof AUTH_CALLBACK_MESSAGE;
  readonly url: string;
} {
  return { type: AUTH_CALLBACK_MESSAGE, url: callbackUri };
}

function sanitize(error: unknown): CyberBusWebError {
  if (error instanceof CyberBusWebError) {
    return error;
  }
  return new CyberBusWebError("INTERNAL", "CyberBus web operation failed");
}

function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

function sanitizeKind(kind: string): string {
  return kind.replace(/[^A-Za-z0-9_.:-]/gu, "").slice(0, 64) || "event";
}
