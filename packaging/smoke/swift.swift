import Foundation
import CyberBus

func check(_ condition: @autoclosure () -> Bool) { precondition(condition()) }
let config = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
defer { try? FileManager.default.removeItem(at: dir) }
let path = dir.appendingPathComponent("state").path
let client = try CyberBusClient(publicConfigJSON: config, developmentStorePath: path, mode: .provision)
if case .timeout = try client.poll(timeoutMilliseconds: 0) {} else { fatalError("initial poll") }
try client.onResume()
let id = [UInt8](repeating: 7, count: 16)
let query = Data([0x0a, 0x10] + id + [0xc2, 0x02, 0])
let result = try client.execute(query)
check(result.prefix(18) == query.prefix(18))
// Actual SdkClose command; preserve native handle until EOF has been drained.
let closeResult = try client.execute(Data([0x0a, 0x10] + id + [0x8a, 0x02, 0]))
check(closeResult.contains(0x82)) // SdkResult.sdk_closed, field 16.
var eof = false
for _ in 0..<100 {
    switch try client.poll(timeoutMilliseconds: 100) {
    case .eof: eof = true
    case .event(let bytes): check(!bytes.isEmpty)
    case .timeout: break
    }
    if eof { break }
}
check(eof)
try client.close()
try client.close()
do { _ = try client.execute(query); fatalError("stale handle accepted") }
catch let error as CyberBusError { check(error.status == 4) }
let deadline = Date().addingTimeInterval(3)
var reopened: CyberBusClient?
while reopened == nil {
    do { reopened = try CyberBusClient(publicConfigJSON: config, developmentStorePath: path) }
    catch { if Date() >= deadline { throw error }; Thread.sleep(forTimeInterval: 0.01) }
}
let reopenedResult = try reopened!.execute(query)
check(reopenedResult.prefix(18) == query.prefix(18))
try reopened!.close()
try FileManager.default.removeItem(atPath: path)
for mode: DevelopmentStoreMode in [.open, .provision, .migrate] {
    do { _ = try CyberBusClient(publicConfigJSON: config, developmentStorePath: path, mode: mode); fatalError("lost installed record accepted") }
    catch is CyberBusError {}
    check(!FileManager.default.fileExists(atPath: path))
}
print("PASS Swift: real C boundary, explicit provision/reopen/lost-record refusal; query/resume/SdkClose/EOF/stale handle")
