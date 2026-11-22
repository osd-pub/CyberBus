import { fail } from "./errors.js";
import type {
  EasyTierTcpReadResult,
  EasyTierTcpStream,
} from "./easytier.js";

export interface TcpAddress {
  readonly ipv4: string;
  readonly port: number;
}

export interface TcpReadResult {
  readonly data: Uint8Array;
  readonly eof: boolean;
}

/**
 * One outbound overlay TCP connection. Writes may be partial; use writeAll()
 * unless the caller deliberately handles partial writes.
 */
export class TcpConnection {
  private closed = false;

  constructor(
    private readonly stream: EasyTierTcpStream,
    private readonly onClosed: (connection: TcpConnection) => void,
  ) {}

  get localAddress(): TcpAddress {
    return this.stream.localAddress;
  }

  get remoteAddress(): TcpAddress {
    return this.stream.peerAddress;
  }

  get isClosed(): boolean {
    return this.closed;
  }

  async read(maxLength = 64 * 1024): Promise<TcpReadResult> {
    this.requireOpen();
    if (!Number.isInteger(maxLength) || maxLength <= 0) {
      fail("CONNECTION_FAILED", "read length must be a positive integer");
    }
    try {
      return await this.stream.read(maxLength);
    } catch {
      fail("CONNECTION_FAILED", "overlay TCP read failed", true);
    }
  }

  async write(data: Uint8Array): Promise<number> {
    this.requireOpen();
    try {
      return await this.stream.write(data);
    } catch {
      fail("CONNECTION_FAILED", "overlay TCP write failed", true);
    }
  }

  async writeAll(data: Uint8Array): Promise<void> {
    this.requireOpen();
    let offset = 0;
    while (offset < data.length) {
      const written = await this.write(data.subarray(offset));
      if (
        !Number.isSafeInteger(written) ||
        written <= 0 ||
        written > data.length - offset
      ) {
        fail("CONNECTION_FAILED", "overlay TCP write made no progress");
      }
      offset += written;
    }
  }

  async shutdownWrite(): Promise<void> {
    this.requireOpen();
    try {
      await this.stream.shutdownWrite();
    } catch {
      fail("CONNECTION_FAILED", "overlay TCP write shutdown failed");
    }
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.onClosed(this);
    try {
      await this.stream.close();
    } catch {
      // Closing is terminal; the underlying instance may already be gone.
    }
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<Uint8Array, void, void> {
    for (;;) {
      const result = await this.read();
      if (result.data.length > 0) {
        yield result.data;
      }
      if (result.eof) {
        return;
      }
    }
  }

  private requireOpen(): void {
    if (this.closed) {
      fail("CONNECTION_FAILED", "overlay TCP connection is closed");
    }
  }
}
