// jade:ring local
// Appended to the exact current relay HTTP parser/exchange by uat-relay-io.py.
// No copied implementation, VM startup, credentials or provider connection.
private func connected(_ path: String) throws -> Int32 {
    guard path.utf8.count < 104 else { throw FixtureError.refused("fixture-socket-path") }
    let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw FixtureError.refused("fixture-socket") }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &address.sun_path) { destination in
        path.utf8CString.withUnsafeBytes { destination.copyBytes(from: $0) }
    }
    let result = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    if result != 0 { Darwin.close(fd); throw FixtureError.refused("fixture-connect") }
    return fd
}

do {
    signal(SIGPIPE, SIG_IGN)
    guard CommandLine.arguments.count == 3 else { throw FixtureError.refused("fixture-arguments") }
    let request = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]))
    guard request.count <= 1024 * 1024 + 16384 else { throw FixtureError.refused("fixture-request-bound") }
    let upstream = try connected(CommandLine.arguments[1])
    defer { Darwin.close(upstream) }
    var didWrite = false
    let result = try relayExchange(upstream: upstream, downstream: STDOUT_FILENO, request: request,
                                   requestSent: { didWrite = true })
    let out: [String: Any] = ["passed": true, "requestComplete": result.requestComplete,
                            "earlyRefusal": result.earlyRefusal, "responseCancelled": result.responseCancelled,
                            "requestSent": didWrite]
    FileHandle.standardError.write(try JSONSerialization.data(withJSONObject: out, options: .sortedKeys))
} catch {
    FileHandle.standardError.write(try! JSONSerialization.data(
        withJSONObject: ["passed": false, "error": String(describing: error)], options: .sortedKeys))
    exit(2)
}
