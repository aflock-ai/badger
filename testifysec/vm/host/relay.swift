// Development transport only: VM/device custody and configured assignments are
// local fixture inputs, not signed authorization or hardware attestation.
import Foundation
import Virtualization
import CryptoKit
import Darwin

private let relayRequestLimit = 1024 * 1024
private let relayFrameLimit = 1400000
private let relayResponseLimit = 16 * 1024 * 1024 + 65536

// Foundation accepts duplicate object keys. Reject them before decoding an
// untrusted relay envelope; only bounded object/string/integer syntax is needed.
private struct RelayJSON {
    let bytes: [UInt8]
    var offset = 0
    mutating func whitespace() { while offset < bytes.count && [9,10,13,32].contains(bytes[offset]) { offset += 1 } }
    mutating func string() throws -> String {
        guard offset < bytes.count, bytes[offset] == 34 else { throw FixtureError.refused("relay-json-string") }
        let start = offset; offset += 1
        while offset < bytes.count {
            let value = bytes[offset]; offset += 1
            if value == 34 {
                guard let text = try JSONSerialization.jsonObject(with:Data(bytes[start..<offset]), options:.fragmentsAllowed) as? String else { throw FixtureError.refused("relay-json-string") }
                return text
            }
            if value == 92 { offset += 1 }
        }
        throw FixtureError.refused("relay-json-string")
    }
    mutating func value(_ depth: Int = 0) throws {
        whitespace()
        guard depth <= 8, offset < bytes.count else { throw FixtureError.refused("relay-json-bounds") }
        if bytes[offset] == 34 { _ = try string(); return }
        if bytes[offset] == 123 {
            offset += 1; whitespace(); var keys = Set<String>()
            if offset < bytes.count && bytes[offset] == 125 { offset += 1; return }
            while offset < bytes.count {
                let key = try string()
                guard keys.insert(key).inserted else { throw FixtureError.refused("relay-json-duplicate") }
                whitespace()
                guard offset < bytes.count, bytes[offset] == 58 else { throw FixtureError.refused("relay-json-colon") }
                offset += 1; try value(depth + 1); whitespace()
                guard offset < bytes.count else { throw FixtureError.refused("relay-json-object") }
                if bytes[offset] == 125 { offset += 1; return }
                guard bytes[offset] == 44 else { throw FixtureError.refused("relay-json-comma") }
                offset += 1; whitespace()
            }
            throw FixtureError.refused("relay-json-object")
        }
        let start = offset
        while offset < bytes.count && (48...57).contains(bytes[offset]) { offset += 1 }
        guard offset > start, offset - start <= 3 else { throw FixtureError.refused("relay-json-number") }
    }
}

struct RelayEnvelope: Decodable {
    let schema: String
    let nonce: String
    let jobSha256: String
    let binding: Binding
    let sequence: Int
    let path: String
    let bodyBase64: String
}

struct GatewayAssignment {
    let file: String
    let digest: String
    let socket: String
    init(file: String, digest: String, binding: Binding, backendManifestSha256: String? = nil) throws {
        let raw = try boundedOwnedInput(file, limit:32768)
        let object: [String:Any]
        if let manifest = backendManifestSha256 {
            var parser = ManagedJSON(bytes:Array(raw)); object = try parser.parse()
            guard validHex(manifest,count:64),
                  object["schema"] as? String == "testifysec.hardened-opencode.gateway/v2",
                  let backend = object["backend"] as? [String:Any],
                  Set(backend.keys) == Set(["kind","manifestSha256"]),
                  backend["kind"] as? String == "darwin-vz/v1",
                  backend["manifestSha256"] as? String == manifest else {
                throw FixtureError.refused("gateway-backend-assignment")
            }
        } else {
            guard let legacy = try JSONSerialization.jsonObject(with:raw) as? [String:Any],
                  legacy["schema"] as? String == "testifysec.hardened-opencode.gateway/v1" else {
                throw FixtureError.refused("gateway-assignment")
            }
            object = legacy
        }
        guard validHex(digest,count:64), SHA256.hash(data:raw).map({String(format:"%02x",$0)}).joined() == digest,
              object["session"] as? String == binding.sessionId,
              object["profileDigest"] as? String == binding.profileSha256,
              let socket = object["socket"] as? String, socket.hasPrefix("/"), socket.utf8.count < 104,
              URL(fileURLWithPath:socket).standardized.path == socket else { throw FixtureError.refused("gateway-assignment") }
        self.file = file; self.digest = digest; self.socket = socket
    }
    func connect() throws -> Int32 {
        let raw = try boundedOwnedInput(file,limit:32768)
        guard SHA256.hash(data:raw).map({String(format:"%02x",$0)}).joined() == digest else { throw FixtureError.refused("gateway-config-changed") }
        let parent = URL(fileURLWithPath:socket).deletingLastPathComponent().path
        guard let resolvedParent = realpath(parent,nil) else { throw FixtureError.refused("gateway-socket-parent") }
        defer { free(resolvedParent) }
        var directory = stat(), before = stat(), after = stat()
        guard lstat(parent,&directory) == 0, directory.st_mode & S_IFMT == S_IFDIR,
              directory.st_mode & 0o777 == 0o700, directory.st_uid == getuid(),
              String(cString:resolvedParent) == parent,
              lstat(socket,&before) == 0, before.st_mode & S_IFMT == S_IFSOCK, before.st_uid == getuid() else { throw FixtureError.refused("gateway-socket-custody") }
        let fd = Darwin.socket(AF_UNIX,SOCK_STREAM,0)
        guard fd >= 0 else { throw FixtureError.refused("gateway-socket") }
        do {
            try relaySocketOptions(fd)
            var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            withUnsafeMutableBytes(of:&address.sun_path) { destination in
                _ = socket.utf8CString.withUnsafeBytes { destination.copyBytes(from:$0) }
            }
            guard fcntl(fd,F_SETFL,O_NONBLOCK) == 0 else { throw FixtureError.refused("gateway-connect-options") }
            let result = withUnsafePointer(to:&address) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { Darwin.connect(fd,$0,socklen_t(MemoryLayout<sockaddr_un>.size)) } }
            if result != 0 {
                guard errno == EINPROGRESS else { throw FixtureError.refused("gateway-connect") }
                var ready = pollfd(fd:fd,events:Int16(POLLOUT),revents:0)
                var socketError: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size)
                guard poll(&ready,1,3000) == 1, ready.revents & Int16(POLLOUT) != 0,
                      getsockopt(fd,SOL_SOCKET,SO_ERROR,&socketError,&size) == 0, socketError == 0 else { throw FixtureError.refused("gateway-connect-deadline") }
            }
            guard fcntl(fd,F_SETFL,0) == 0 else { throw FixtureError.refused("gateway-connect-options") }
            var uid: uid_t = 0, gid: gid_t = 0
            guard getpeereid(fd,&uid,&gid) == 0, uid == getuid(),
                  lstat(socket,&after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino else { throw FixtureError.refused("gateway-peer-or-path") }
            return fd
        } catch { Darwin.close(fd); throw error }
    }
}

private func relaySocketOptions(_ fd: Int32) throws {
    var timeout = timeval(tv_sec:3,tv_usec:0), noSignal: Int32 = 1
    guard setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,socklen_t(MemoryLayout<timeval>.size)) == 0,
          setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,socklen_t(MemoryLayout<timeval>.size)) == 0,
          setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&noSignal,socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw FixtureError.refused("relay-socket-options") }
}
private func relayRead(_ fd: Int32, count: Int) throws -> Data {
    var result = Data(), bytes = [UInt8](repeating:0,count:min(count,32768))
    while result.count < count {
        let length = Darwin.read(fd,&bytes,min(bytes.count,count-result.count))
        if length < 0 && errno == EINTR { continue }
        guard length > 0 else { throw FixtureError.refused("relay-frame-truncated") }
        result.append(contentsOf:bytes.prefix(length))
    }
    return result
}
private func relayWrite(_ fd: Int32, _ data: Data) throws {
    var offset = 0
    while offset < data.count {
        let length = data.withUnsafeBytes { Darwin.write(fd,$0.baseAddress!.advanced(by:offset),data.count-offset) }
        if length < 0 && errno == EINTR { continue }
        guard length > 0 else { throw FixtureError.refused("relay-write") }
        offset += length
    }
}

// Fixed native gateway HTTP/1.x exchange. The caller has already validated
// frame, receipt acceptance, EOF and session assignment. No authority is taken
// from response headers. This parser checks transport framing, not model output.
private struct RelayHTTPResponse {
    private var header = Data()
    private var kind = "header"
    private var remaining = 0
    private var sizeLine = Data()
    private var suffix = Data()
    private var decoded = 0
    private(set) var status: Int?
    private(set) var complete = false

    mutating func observe(_ data: Data) throws -> Data {
        if kind == "header" {
            header.append(data)
            guard let end = header.range(of:Data("\r\n\r\n".utf8)) else {
                guard header.count <= 16384 else { throw FixtureError.refused("gateway-response-header-limit") }
                return Data()
            }
            guard end.upperBound <= 16384 else { throw FixtureError.refused("gateway-response-header-limit") }
            let parsed = try Self.parseHeader(Data(header[..<end.lowerBound]))
            status = parsed.0;kind = parsed.1;remaining = parsed.2
            if kind == "none" || (kind == "length" && remaining == 0) { complete = true }
            try body(Data(header[end.upperBound...]))
            let output = header;header = Data()
            return output
        }
        try body(data)
        return data
    }

    private static func parseHeader(_ data: Data) throws -> (Int,String,Int) {
        guard data.allSatisfy({ $0 == 9 || $0 == 10 || $0 == 13 || (32...126).contains($0) }),
              let text = String(data:data,encoding:.ascii) else { throw FixtureError.refused("gateway-response-header") }
        let lines = text.components(separatedBy:"\r\n")
        let first = Array((lines.first ?? "").utf8)
        guard first.count >= 12,
              ["HTTP/1.1 ","HTTP/1.0 "].contains(String(bytes:first.prefix(9),encoding:.ascii) ?? ""),
              first[9...11].allSatisfy({ (48...57).contains($0) }),
              first.count == 12 || first[12] == 32,
              first.allSatisfy({ (32...126).contains($0) }),
              let status = Int(String(bytes:first[9...11],encoding:.ascii)!), (200...599).contains(status)
        else { throw FixtureError.refused("gateway-response-status") }
        let token = Set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".utf8)
        var headers: [String:String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of:":") else { throw FixtureError.refused("gateway-response-header") }
            let name = String(line[..<colon])
            let value = String(line[line.index(after:colon)...]).trimmingCharacters(in:CharacterSet(charactersIn:" \t"))
            guard !name.isEmpty, name.utf8.allSatisfy({ token.contains($0) }),
                  value.utf8.allSatisfy({ $0 == 9 || (32...126).contains($0) }),
                  headers[name.lowercased()] == nil else { throw FixtureError.refused("gateway-response-header") }
            headers[name.lowercased()] = value
        }
        // This fixed gateway emits no informational responses, upgrades or
        // trailers. A contradictory/unsupported framing header is not an EOF.
        guard headers["trailer"] == nil, headers["upgrade"] == nil,
              !(headers["content-length"] != nil && headers["transfer-encoding"] != nil)
        else { throw FixtureError.refused("gateway-response-framing") }
        if let value = headers["transfer-encoding"] {
            guard value.lowercased() == "chunked", status != 204, status != 304 else { throw FixtureError.refused("gateway-response-framing") }
            return (status,"chunk-size",0)
        }
        if let value = headers["content-length"] {
            guard !value.isEmpty, value.count <= 8, value.utf8.allSatisfy({ (48...57).contains($0) }),
                  let length = Int(value), length <= 16*1024*1024,
                  (status != 204 && status != 304) || length == 0 else { throw FixtureError.refused("gateway-response-framing") }
            return (status,"length",length)
        }
        return (status,(status == 204 || status == 304) ? "none" : "close",0)
    }

    private mutating func body(_ data: Data) throws {
        var offset = 0
        while offset < data.count {
            guard !complete else { throw FixtureError.refused("gateway-response-extra") }
            switch kind {
            case "none": throw FixtureError.refused("gateway-response-extra")
            case "close":
                decoded += data.count-offset;offset = data.count
            case "length", "chunk-data":
                let count = min(remaining,data.count-offset)
                remaining -= count;offset += count;decoded += count
                if remaining == 0 {
                    if kind == "length" { complete = true } else { kind = "chunk-crlf";suffix = Data() }
                }
            case "chunk-size":
                sizeLine.append(data[offset]);offset += 1
                guard sizeLine.count <= 18 else { throw FixtureError.refused("gateway-response-chunk") }
                if sizeLine.count >= 2 && sizeLine.suffix(2) == Data("\r\n".utf8) {
                    let digits = sizeLine.dropLast(2)
                    guard !digits.isEmpty, digits.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
                          let value = String(data:Data(digits),encoding:.ascii), let length = Int(value,radix:16),
                          length <= 16*1024*1024-decoded else { throw FixtureError.refused("gateway-response-chunk") }
                    sizeLine = Data();remaining = length
                    kind = length == 0 ? "chunk-end" : "chunk-data";suffix = Data()
                }
            case "chunk-crlf", "chunk-end":
                suffix.append(data[offset]);offset += 1
                guard suffix.count <= 2, suffix == Data("\r\n".utf8).prefix(suffix.count) else { throw FixtureError.refused("gateway-response-chunk") }
                if suffix.count == 2 {
                    if kind == "chunk-end" { complete = true } else { kind = "chunk-size" }
                }
            default: throw FixtureError.refused("gateway-response-framing")
            }
            guard decoded <= 16*1024*1024 else { throw FixtureError.refused("gateway-response-limit") }
        }
    }

    mutating func finish() throws {
        guard status != nil, kind == "close" || complete else { throw FixtureError.refused("gateway-response-truncated") }
        complete = true
    }
}

private struct RelayExchangeOutcome {
    let requestComplete: Bool
    let earlyRefusal: Bool
    let responseCancelled: Bool
}

// One thread owns both upstream directions. A normal early HTTP denial may
// close the request writer while its response is buffered for reading. No
// descriptor can outlive this function in a detached request-writer task.
private func relayExchange(upstream: Int32, downstream: Int32, request: Data,
                           requestSent: () -> Void) throws -> RelayExchangeOutcome {
    guard request.count <= relayRequestLimit + 16384,
          fcntl(upstream,F_SETFL,O_NONBLOCK) == 0 else { throw FixtureError.refused("gateway-exchange-options") }
    let started = DispatchTime.now().uptimeNanoseconds
    var progress = started, offset = 0, responseBytes = 0
    var writeFailure: Int32?
    var response = RelayHTTPResponse()
    var bytes = [UInt8](repeating:0,count:32768)
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now-started < 30_000_000_000, now-progress < 3_000_000_000 else { throw FixtureError.refused("gateway-exchange-deadline") }
        let writable = offset < request.count && writeFailure == nil
        var ready = pollfd(fd:upstream,events:Int16(POLLIN | (writable ? POLLOUT : 0)),revents:0)
        let polled = poll(&ready,1,100)
        if polled < 0 && errno == EINTR { continue }
        guard polled >= 0, ready.revents & Int16(POLLNVAL) == 0 else { throw FixtureError.refused("gateway-exchange-poll") }
        if polled == 0 { continue }
        if ready.revents & Int16(POLLIN | POLLHUP | POLLERR) != 0 {
            let length = Darwin.read(upstream,&bytes,bytes.count)
            if length == 0 {
                try response.finish()
                let denied = (400...599).contains(response.status!)
                guard offset == request.count || denied else { throw FixtureError.refused("gateway-request-incomplete") }
                return RelayExchangeOutcome(requestComplete:offset == request.count,earlyRefusal:offset != request.count && denied,responseCancelled:false)
            }
            if length > 0 {
                progress = DispatchTime.now().uptimeNanoseconds
                responseBytes += length
                guard responseBytes <= relayResponseLimit else { throw FixtureError.refused("gateway-response-limit") }
                let output = try response.observe(Data(bytes.prefix(length)))
                if let status = response.status, offset != request.count && !(400...599).contains(status) {
                    throw FixtureError.refused("gateway-request-write")
                }
                var sent = 0
                while sent < output.count {
                    let count = output.withUnsafeBytes { Darwin.write(downstream,$0.baseAddress!.advanced(by:sent),output.count-sent) }
                    let code = errno
                    if count < 0 && code == EINTR { continue }
                    if count < 0 && (code == EPIPE || code == ECONNRESET) {
                        return RelayExchangeOutcome(requestComplete:offset == request.count,earlyRefusal:false,responseCancelled:true)
                    }
                    guard count > 0 else { throw FixtureError.refused("relay-response-write") }
                    sent += count
                }
                progress = DispatchTime.now().uptimeNanoseconds
            } else if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                throw FixtureError.refused("gateway-response-read")
            }
        }
        if writable && ready.revents & Int16(POLLOUT | POLLHUP | POLLERR) != 0 {
            let length = request.withUnsafeBytes { Darwin.write(upstream,$0.baseAddress!.advanced(by:offset),min(32768,request.count-offset)) }
            let code = errno
            if length > 0 {
                progress = DispatchTime.now().uptimeNanoseconds;offset += length
                if offset == request.count { requestSent() }
            } else if length < 0 && (code == EPIPE || code == ECONNRESET) {
                writeFailure = code
                if let status = response.status, !(400...599).contains(status) { throw FixtureError.refused("gateway-request-write") }
            } else if length == 0 || (code != EAGAIN && code != EWOULDBLOCK && code != EINTR) {
                throw FixtureError.refused("gateway-request-write")
            }
        }
    }
}

private final class RelayConnection {
    let connection: VZVirtioSocketConnection
    let lock = NSLock()
    var gateway: Int32 = -1
    var cancelled = false
    private var completed = false
    let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
    init(_ connection: VZVirtioSocketConnection) { self.connection = connection }
    func cancel() {
        lock.lock(); defer { lock.unlock() }
        if completed { return }
        cancelled = true
        _ = shutdown(connection.fileDescriptor,SHUT_RDWR)
        if gateway >= 0 { _ = shutdown(gateway,SHUT_RDWR) }
    }
    func setGateway(_ fd: Int32) throws {
        lock.lock(); defer { lock.unlock() }
        if cancelled { Darwin.close(fd); throw FixtureError.refused("relay-cancelled") }
        gateway = fd
    }
    func closeGateway() {
        lock.lock(); defer { lock.unlock() }
        if gateway >= 0 { Darwin.close(gateway); gateway = -1 }
    }
    // Linearize completion against host cancellation before classifying a peer
    // close as benign. A fired deadline cannot be hidden by its resulting EPIPE.
    func completeExchange() throws {
        lock.lock(); defer { lock.unlock() }
        guard !cancelled, DispatchTime.now().uptimeNanoseconds < deadline else { throw FixtureError.refused("relay-cancelled") }
        completed = true
    }
}

final class ModelRelay: NSObject, VZVirtioSocketListenerDelegate {
    let listener = VZVirtioSocketListener()
    let lock = NSLock(), workers = DispatchGroup()
    let assignment: GatewayAssignment
    let binding: Binding, nonce: String, jobSha256: String
    let allowed: () -> Bool, refuse: (String) -> Void
    private var active: [Int:RelayConnection] = [:]
    private var used = Set<Int>()
    private var closed = false, connections = 0, forwarded = 0, errors = 0
    private var earlyGatewayRefusals = 0, responseCancellations = 0
    private var lastError: String?
#if HC_VM_PROTOCOL_UAT
    var fixtureReceiptFault: String?
#endif
    init(assignment: GatewayAssignment,binding: Binding,nonce: String,jobSha256: String,allowed: @escaping () -> Bool,refuse: @escaping (String)->Void) {
        self.assignment=assignment;self.binding=binding;self.nonce=nonce;self.jobSha256=jobSha256;self.allowed=allowed;self.refuse=refuse
        super.init(); listener.delegate=self
    }
    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection connection: VZVirtioSocketConnection, from socketDevice: VZVirtioSocketDevice) -> Bool {
        lock.lock()
        guard !closed, allowed(), active.count < 2, connections < 32 else {
            lock.unlock(); refuse("gateway-connection-refused"); return false
        }
        connections += 1; let id = connections, current = RelayConnection(connection)
        active[id] = current; workers.enter(); lock.unlock()
        DispatchQueue.global().async {
            let timer = DispatchSource.makeTimerSource(queue:DispatchQueue.global())
            let timerDone = DispatchSemaphore(value:0)
            timer.setEventHandler { current.cancel() }
            timer.setCancelHandler { timerDone.signal() }
            timer.schedule(deadline:DispatchTime(uptimeNanoseconds:current.deadline));timer.resume()
            defer {
                timer.cancel(); timerDone.wait()
                current.closeGateway(); _ = shutdown(connection.fileDescriptor,SHUT_RDWR)
                self.lock.lock(); self.active.removeValue(forKey:id); self.lock.unlock(); self.workers.leave()
            }
            do { try self.forward(current) }
            catch {
                let reason: String
                if case FixtureError.refused(let code) = error { reason = code } else { reason = "relay-invalid-envelope" }
                self.lock.lock(); self.errors += 1; self.lastError = reason; self.lock.unlock(); self.refuse("gateway-relay-refused")
            }
        }
        return true
    }
    private func forward(_ current: RelayConnection) throws {
        let fd = current.connection.fileDescriptor
        try relaySocketOptions(fd)
        let header = try relayRead(fd,count:12)
        guard header.prefix(8) == Data("HCMDL2\r\n".utf8) else { throw FixtureError.refused("relay-magic") }
        let length = header.suffix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= relayFrameLimit else { throw FixtureError.refused("relay-frame-limit") }
        let raw = try relayRead(fd,count:length)
        // Transport receipt only; EOF and all admission checks still precede effects.
        let receipt = Data("HCRCP2\r\n".utf8) + Data(SHA256.hash(data:header + raw))
#if HC_VM_PROTOCOL_UAT
        var emittedReceipt = receipt
        switch fixtureReceiptFault {
        case "receipt-wrong-magic": emittedReceipt[0] ^= 1
        case "receipt-wrong-digest": emittedReceipt[39] ^= 1
        case "receipt-short": emittedReceipt = Data(emittedReceipt.prefix(12))
        case "receipt-missing": emittedReceipt = Data()
        default: break
        }
        if !emittedReceipt.isEmpty { try relayWrite(fd,emittedReceipt) }
#else
        try relayWrite(fd,receipt)
#endif
        let confirmation = try relayRead(fd,count:40)
        guard confirmation == Data("HCCMT2\r\n".utf8) + Data(SHA256.hash(data:receipt)) else {
            throw FixtureError.refused("relay-receipt-confirmation")
        }
        var trailing: UInt8 = 0
        guard Darwin.read(fd,&trailing,1) == 0 else { throw FixtureError.refused("relay-frame-extra-or-no-eof") }
        guard String(data:raw,encoding:.utf8) != nil else { throw FixtureError.refused("relay-utf8") }
        var scanner = RelayJSON(bytes:Array(raw)); try scanner.value(); scanner.whitespace()
        guard scanner.offset == raw.count else { throw FixtureError.refused("relay-json-trailing") }
        let request = try JSONDecoder().decode(RelayEnvelope.self,from:raw)
        guard let object = try JSONSerialization.jsonObject(with:raw) as? [String:Any],
              Set(object.keys) == Set(["schema","nonce","jobSha256","binding","sequence","path","bodyBase64"]),
              let assigned = object["binding"] as? [String:Any], Set(assigned.keys) == Set(["requestSha256","profileSha256","sessionId","materialsSha256","backendSha256"]),
              request.schema == "testifysec.vm-model-request/v1", request.nonce == nonce, request.jobSha256 == jobSha256,
              request.binding == binding, (1...32).contains(request.sequence),
              ["/v1/chat/completions","/v1/responses"].contains(request.path),
              let body = Data(base64Encoded:request.bodyBase64), body.base64EncodedString() == request.bodyBase64,
              !body.isEmpty, body.count <= relayRequestLimit else { throw FixtureError.refused("relay-assignment-or-request") }
        lock.lock()
        let admitted = !closed && used.insert(request.sequence).inserted
        lock.unlock()
        guard admitted, allowed() else { throw FixtureError.refused("relay-replayed-or-closed") }
        try current.setGateway(assignment.connect())
        let upstream = current.gateway
        let head = "POST \(request.path) HTTP/1.1\r\nHost: hardened-gateway\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        let result = try relayExchange(upstream:upstream,downstream:fd,request:Data(head.utf8)+body,requestSent:{
            self.lock.lock();self.forwarded += 1;self.lock.unlock()
        })
        try current.completeExchange()
        lock.lock()
        if result.earlyRefusal { earlyGatewayRefusals += 1 }
        if result.responseCancelled { responseCancellations += 1 }
        lock.unlock()
    }
    // Called on the VM queue before its listener is removed. No late callback
    // can register after the shutdown snapshot and group wait begin.
    func closeAdmission() {
        lock.lock();closed=true;let current=Array(active.values);lock.unlock()
        for item in current { item.cancel() }
    }
    func drain() -> Bool { workers.wait(timeout:.now()+4) == .success }
    func observation() -> [String:Any] {
        lock.lock();defer { lock.unlock() }
        return ["enabled":true,"port":17002,"connections":connections,"forwarded":forwarded,"transportErrors":errors,"earlyGatewayRefusals":earlyGatewayRefusals,"responseCancellations":responseCancellations,
                "admissionClosed":closed,"active":active.count,"gatewayConfigSha256":assignment.digest,"lastError":lastError ?? NSNull(),
                "scope":"local-session-transport-not-model-outcome-or-signed-admission"]
    }
}
