declare module "@easytier/browser" {
  export interface EasyTierNetworkConfig {
    networkName: string;
    networkSecret: string;
    instanceName?: string;
    encryption?: boolean;
  }

  export interface EasyTierIpv4SocketAddress {
    ipv4: string;
    port: number;
  }

  export interface EasyTierTcpReadResult {
    data: Uint8Array;
    eof: boolean;
  }

  export interface EasyTierTcpStream {
    readonly localAddress: EasyTierIpv4SocketAddress;
    readonly peerAddress: EasyTierIpv4SocketAddress;
    read(maxLength?: number): Promise<EasyTierTcpReadResult>;
    write(data: Uint8Array): Promise<number>;
    shutdownWrite(): Promise<void>;
    close(): Promise<void>;
  }

  export interface EasyTierInstance {
    connectTcp(
      address: string,
      options?: { timeout?: number },
    ): Promise<EasyTierTcpStream>;
    status(): Promise<{ state: string; connections: number }>;
    close(): Promise<void>;
  }

  export interface EasyTierEvent {
    kind: string;
    message: string;
  }

  export function createEasyTier(
    config: EasyTierNetworkConfig & {
      ipv4: string;
      peers: string | readonly string[];
    },
    options?: { onEvent?: (event: EasyTierEvent) => void },
  ): Promise<EasyTierInstance>;
}
