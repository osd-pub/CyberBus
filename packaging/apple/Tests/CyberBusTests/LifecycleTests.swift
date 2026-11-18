import XCTest
import Foundation
import CyberBus
import CCyberBus

final class LifecycleTests: XCTestCase {
    func testNativeLifecycle() throws {
        XCTAssertEqual(cyberbus_abi_version(), 1)
        // Local lifecycle only: no login/start and no contact with this fixture issuer.
        let config = Data(#"{"issuer":"https://example.invalid/oidc","client_id":"package-tests","resource":"https://example.invalid/api","product_id":"cyberbus","native_clients":{"package-tests":"cyberbus"},"redirect_uri":"cyberbus://auth/callback","bootstrap_peers":[],"listeners":[],"enable_p2p":false}"#.utf8)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("state")
        XCTAssertThrowsError(try CyberBusClient(publicConfigJSON: config, developmentStorePath: path.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: path.path))
        let client = try CyberBusClient(publicConfigJSON: config, developmentStorePath: path.path, mode: .provision)
        let id = [UInt8](repeating: 1, count: 16)
        let query = Data([10,16] + id + [0xc2,2,0])
        XCTAssertEqual(try client.execute(query).prefix(18), query.prefix(18))
        try client.onResume()
        _ = try client.execute(Data([10,16] + id + [0x8a,2,0]))
        var eof = false
        for _ in 0..<100 {
            if case .eof = try client.poll(timeoutMilliseconds: 100) { eof = true; break }
        }
        XCTAssertTrue(eof)
        try client.close(); try client.close()
        XCTAssertThrowsError(try client.execute(query))

        // Retry installed-only open for asynchronous native lock release. Never provision.
        func reopen(_ mode: DevelopmentStoreMode = .open) throws -> CyberBusClient {
            let deadline = Date().addingTimeInterval(3)
            while true {
                do { return try CyberBusClient(publicConfigJSON: config, developmentStorePath: path.path, mode: mode) }
                catch { if Date() >= deadline { throw error }; Thread.sleep(forTimeInterval: 0.01) }
            }
        }
        let installed = try Data(contentsOf: path)
        let reopened = try reopen()
        XCTAssertEqual(try reopened.execute(query).prefix(18), query.prefix(18))
        XCTAssertThrowsError(try CyberBusClient(publicConfigJSON: config, developmentStorePath: path.path, mode: .provision))
        try reopened.close()
        let marker = path.appendingPathExtension("auth-install")
        // Remove only the marker to model a valid legacy record. Host explicitly authorizes migration.
        let released = try reopen(); try released.close()
        Thread.sleep(forTimeInterval: 0.05)
        try FileManager.default.removeItem(at: marker)
        XCTAssertThrowsError(try CyberBusClient(publicConfigJSON: config, developmentStorePath: path.path))
        XCTAssertThrowsError(try CyberBusClient(publicConfigJSON: config, developmentStorePath: path.path, mode: .provision))
        XCTAssertEqual(try Data(contentsOf: path), installed)
        let migrated = try reopen(.migrate)
        XCTAssertEqual(try migrated.execute(query).prefix(18), query.prefix(18))
        try migrated.close()
        let finalOpen = try reopen(); try finalOpen.close()
        Thread.sleep(forTimeInterval: 0.05)
        try FileManager.default.removeItem(at: path)
        for mode: DevelopmentStoreMode in [.open, .provision, .migrate] {
            XCTAssertThrowsError(try CyberBusClient(publicConfigJSON: config, developmentStorePath: path.path, mode: mode))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path.path))
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
    }
}
