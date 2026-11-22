export type CyberBusWebErrorCode =
  | "INVALID_CONFIG"
  | "POPUP_BLOCKED"
  | "AUTH_CANCELLED"
  | "AUTH_TIMEOUT"
  | "AUTH_FAILED"
  | "INVALID_CLAIMS"
  | "SESSION_EXPIRED"
  | "CREDENTIALS_CHANGED"
  | "NETWORK_NOT_STARTED"
  | "NETWORK_START_FAILED"
  | "CONNECTION_FAILED"
  | "UNSUPPORTED"
  | "CLOSED"
  | "INTERNAL";

/**
 * Sanitized SDK error. Messages never include tokens, seeds, network secrets,
 * authorization codes, PKCE verifiers, or raw token-endpoint responses.
 */
export class CyberBusWebError extends Error {
  readonly code: CyberBusWebErrorCode;
  readonly retryable: boolean;

  constructor(code: CyberBusWebErrorCode, message: string, retryable = false) {
    super(message);
    this.name = "CyberBusWebError";
    this.code = code;
    this.retryable = retryable;
  }
}

export function fail(
  code: CyberBusWebErrorCode,
  message: string,
  retryable = false,
): never {
  throw new CyberBusWebError(code, message, retryable);
}
