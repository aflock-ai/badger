// jade:ring local
// Appended to the exact current RelayConnection. The generated FD-only VZ
// holder is a fixture: these tests execute real sockets, not a virtual machine.
private func sockets() -> [Int32] {
    var pair: [Int32] = [0, 0]
    precondition(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
    return pair
}
private func refuses(_ current: RelayConnection) -> Bool {
    do { try current.completeExchange(); return false } catch { return true }
}

signal(SIGPIPE, SIG_IGN)
var reports: [[String: Any]] = []
for mode in ["cancel-before-complete", "complete-before-cancel", "real-deadline-downstream-close"] {
    let start = DispatchTime.now().uptimeNanoseconds
    let down = sockets(), up = sockets()
    let current = RelayConnection(VZVirtioSocketConnection(down[0]))
    try current.setGateway(up[0])
    var good = false
    if mode == "complete-before-cancel" {
        try current.completeExchange()
        current.cancel()
        var byte: UInt8 = 7
        good = Darwin.write(down[0], &byte, 1) == 1 && !current.cancelled
    } else {
        if mode == "real-deadline-downstream-close" {
            let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
            let fired = DispatchSemaphore(value: 0), joined = DispatchSemaphore(value: 0)
            timer.setEventHandler { current.cancel(); fired.signal() }
            timer.setCancelHandler { joined.signal() }
            timer.schedule(deadline: DispatchTime(uptimeNanoseconds: current.deadline))
            timer.resume()
            precondition(fired.wait(timeout: .now() + 32) == .success)
            timer.cancel()
            joined.wait()
        } else {
            current.cancel()
        }
        var byte: UInt8 = 7
        let written = Darwin.write(down[0], &byte, 1), code = errno
        good = written == -1 && code == EPIPE && refuses(current)
    }
    current.closeGateway()
    Darwin.close(up[1]); Darwin.close(down[0]); Darwin.close(down[1])
    reports.append(["name": mode, "passed": good,
                    "elapsedSeconds": Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000])
}
let report: [String: Any] = ["passed": reports.allSatisfy { $0["passed"] as? Bool == true }, "cases": reports]
FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .prettyPrinted]))
if !(report["passed"] as! Bool) { exit(2) }
