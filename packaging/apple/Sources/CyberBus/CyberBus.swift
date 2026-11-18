import Foundation
import CCyberBus

public struct CyberBusError: Error {
    public let status: Int32
    /// Sanitized binary ProtocolError; callers decode with the shipped schema.
    public let protobuf: Data
}
public enum CyberBusPoll {
    case event(Data)
    case timeout
    case eof
}

/// Trusted host intent for plaintext development storage. Never select provision
/// or migrate as an automatic fallback from an open error.
public enum DevelopmentStoreMode {
    case provision
    case open
    case migrate
}

/// Blocking bytes boundary. Use worker threads and one poll consumer. Handles
/// remain native-owned; every returned buffer is copied then freed exactly once.
/// Execute SdkClose, drain poll to EOF, then close to release the native handle.
/// This object is not Sendable: coordinate calls/close in the host's executor.
public final class CyberBusClient {
    private var handle: UInt64
    private static func consume(_ response: CyberbusResponse) throws -> Data {
        defer { precondition(cyberbus_buffer_free(response.buffer) == 0) }
        let data: Data
        if response.buffer.len == 0 { data = Data() }
        else { data = Data(bytes: response.buffer.data!, count: response.buffer.len) }
        guard response.status == 0 else { throw CyberBusError(status: response.status, protobuf: data) }
        return data
    }
    /// A valid store transfers its context to Rust even when creation fails.
    /// Callbacks must never throw across C, must serialize/durably replace the
    /// entire blob, and must return read/write failures without provisioning.
    public init(publicConfigJSON: Data, store: CyberbusStore) throws {
        var callbacks = store
        let response = publicConfigJSON.withUnsafeBytes { bytes in
            cyberbus_create(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, &callbacks)
        }
        _ = try Self.consume(response)
        handle = response.handle
    }
    /// Explicit DEVELOPMENT plaintext atomic file storage, not Keychain.
    /// Parent must already exist and be private to the current user/app.
    /// Defaults to installed-only open. Provision is only for trusted first use;
    /// migrate explicitly upgrades a valid legacy vault with no marker.
    public init(publicConfigJSON: Data, developmentStorePath: String,
                mode: DevelopmentStoreMode = .open) throws {
        let path = Data(developmentStorePath.utf8)
        let response = publicConfigJSON.withUnsafeBytes { config in
            path.withUnsafeBytes { path in
                switch mode {
                case .open:
                    return cyberbus_create_development(config.bindMemory(to: UInt8.self).baseAddress, config.count,
                        path.bindMemory(to: UInt8.self).baseAddress, path.count)
                case .provision:
                    return cyberbus_create_development_new(config.bindMemory(to: UInt8.self).baseAddress, config.count,
                        path.bindMemory(to: UInt8.self).baseAddress, path.count)
                case .migrate:
                    return cyberbus_create_development_migrate(config.bindMemory(to: UInt8.self).baseAddress, config.count,
                        path.bindMemory(to: UInt8.self).baseAddress, path.count)
                }
            }
        }
        _ = try Self.consume(response)
        handle = response.handle
    }
    public func execute(_ command: Data) throws -> Data {
        try command.withUnsafeBytes { bytes in
            try Self.consume(cyberbus_execute(handle, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count))
        }
    }
    public func poll(timeoutMilliseconds: UInt32) throws -> CyberBusPoll {
        let response = cyberbus_poll(handle, timeoutMilliseconds)
        if response.status == 1 || response.status == 2 {
            precondition(cyberbus_buffer_free(response.buffer) == 0)
            return response.status == 1 ? .timeout : .eof
        }
        return .event(try Self.consume(response))
    }
    public func onResume() throws { _ = try Self.consume(cyberbus_on_resume(handle)) }
    public func close() throws {
        if handle == 0 { return }
        let old = handle
        handle = 0
        _ = try Self.consume(cyberbus_close(old))
    }
    deinit { if handle != 0 { _ = try? Self.consume(cyberbus_close(handle)) } }
}
