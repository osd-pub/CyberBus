import { fail } from "./errors.js";

export interface EasyTierTcpReadResult {
  readonly data: Uint8Array;
  readonly eof: boolean;
}

export interface EasyTierTcpStream {
  readonly localAddress: { readonly ipv4: string; readonly port: number };
  readonly peerAddress: { readonly ipv4: string; readonly port: number };
  read(maxLength?: number): Promise<EasyTierTcpReadResult>;
  write(data: Uint8Array): Promise<number>;
  shutdownWrite(): Promise<void>;
  close(): Promise<void>;
}

export interface EasyTierInstance {
  connectTcp(
    address: string,
    options?: { readonly timeout?: number },
  ): Promise<EasyTierTcpStream>;
  status(): Promise<{ readonly state: string; readonly connections: number }>;
  close(): Promise<void>;
}

export interface EasyTierFactory {
  create(
    config: {
      readonly networkName: string;
      readonly networkSecret: string;
      readonly instanceName?: string;
      readonly encryption?: boolean;
      readonly ipv4: string;
      readonly peers: string | readonly string[];
    },
    options?: {
      readonly onEvent?: (event: {
        readonly kind: string;
        readonly message: string;
      }) => void;
    },
  ): Promise<EasyTierInstance>;
}

export async function loadEasyTierBrowser(): Promise<EasyTierFactory> {
  const wasm = WebAssembly as typeof WebAssembly & {
    readonly promising?: unknown;
    readonly Suspending?: unknown;
  };
  if (
    typeof wasm.promising !== "function" ||
    typeof wasm.Suspending !== "function"
  ) {
    fail(
      "UNSUPPORTED",
      "This browser does not support WebAssembly JSPI",
    );
  }
  let module: typeof import("@easytier/browser");
  try {
    module = await import("@easytier/browser");
  } catch {
    fail(
      "UNSUPPORTED",
      "The @easytier/browser package is not available to this bundle",
    );
  }
  if (typeof module.createEasyTier !== "function") {
    fail("UNSUPPORTED", "The @easytier/browser bundle has no createEasyTier export");
  }
  return {
    create: (config, options) => module.createEasyTier(config, options),
  };
}
