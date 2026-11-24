// Development VM fixture only. No profile admission or production backend activation.
import Foundation
import Virtualization
import CryptoKit
import Darwin

struct Binding: Codable, Equatable {
    let requestSha256: String
    let profileSha256: String
    let sessionId: String
    let materialsSha256: String
    let backendSha256: String
}
struct VMConfig: Decodable {
    var managed: Bool { ["testifysec.vm-config/v3", "testifysec.vm-config/v4"].contains(schema) }
    let schema: String
    let kernel: String
    let kernelSha256: String
    let rootDisk: String
    let rootDiskSha256: String
    let jobSha256: String
    let jobFile: String
    let binding: Binding
    let gatewayConfigFile: String?
    let gatewayConfigSha256: String?
    let backendManifestSha256: String?
#if HC_VM_PROTOCOL_UAT
    let fixtureFault: String?
    let fixtureReplayNonce: String?
#endif
    let memoryMiB: UInt64
    let cpus: Int
    let timeoutSeconds: Int
}

enum FixtureError: Error { case refused(String) }

func sha256(_ path: String) throws -> String {
    let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
    defer { try? handle.close() }
    var digest = SHA256()
    while let data = try handle.read(upToCount: 1 << 20), !data.isEmpty { digest.update(data: data) }
    return digest.finalize().map { String(format: "%02x", $0) }.joined()
}

func checkedFile(_ path: String, digest: String) throws {
    var value = stat()
    guard path.hasPrefix("/"), lstat(path, &value) == 0,
          value.st_mode & S_IFMT == S_IFREG, value.st_nlink == 1,
          value.st_uid == getuid(), value.st_mode & 0o022 == 0,
          digest.count == 64, try sha256(path) == digest else {
        throw FixtureError.refused("input-file-or-digest")
    }
}

func validHex(_ value: String, count: Int) -> Bool {
    value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
func boundedOwnedInput(_ path: String, limit: Int) throws -> Data {
    guard path.hasPrefix("/") else { throw FixtureError.refused("input-path") }
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw FixtureError.refused("input-file") }
    let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    defer { try? file.close() }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
          info.st_nlink == 1, info.st_uid == getuid(), info.st_mode & 0o077 == 0,
          info.st_size > 0, info.st_size <= limit else { throw FixtureError.refused("input-file-bounds") }
    let data = try file.read(upToCount: limit + 1) ?? Data()
    guard data.count == info.st_size else { throw FixtureError.refused("input-read") }
    return data
}
func boundedJob(_ path: String, digest: String, managed: Bool = false) throws -> Data {
    let data = try boundedOwnedInput(path, limit: managed ? managedJobLimit : 32768)
    guard SHA256.hash(data: data).map({String(format:"%02x",$0)}).joined() == digest else { throw FixtureError.refused("job-digest") }
    return data
}

// Only a successful empty/nil FileHandle read ends normally. A read exception
// remains distinct from EOF even when the reader task itself has drained.
func readVMSerial(_ input: FileHandle, consume: (Data) -> Void) throws {
    while let data = try input.read(upToCount:4096), !data.isEmpty { consume(data) }
}

func serialObservation(_ observation: [String:Any], configSchema: String, drained: Bool, eof: Bool) -> [String:Any] {
    guard configSchema == "testifysec.vm-config/v4" else { return observation }
    var result = observation
    result["schema"] = "testifysec.vm-observation/v4"
    result["serialReaderDrained"] = drained
    result["serialEOFObserved"] = eof
    result["passed"] = observation["passed"] as? Bool == true && drained && eof
    return result
}

final class Runner: NSObject, VZVirtualMachineDelegate, VZVirtioSocketListenerDelegate {
    let queue = DispatchQueue(label: "testifysec.vm.lifecycle")
    let lock = NSLock()
    let completed = DispatchSemaphore(value: 0)
    let pipe = Pipe()
    let config: VMConfig
    let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    let job: Data
    let managed: ManagedJob?
    let socketListener = VZVirtioSocketListener()
    var jobConnection: VZVirtioSocketConnection?
    var jobConnections = 0
    var jobAdmissionClosed = false
    var jobConnectionsRefusedAfterClose = 0
    var jobSent = false
    var jobFrameSha256: String?
    let transportDone = DispatchSemaphore(value: 0)
    var modelRelay: ModelRelay?
    var machine: VZVirtualMachine!
    var buffer = Data()
    var serialBytes = 0
    var serialEOFObserved = false
    var serialTail = Data()
    var guest: [String: Any]?
    var error: String?
    var running = false
    var stopped = false
    var stopping = false
    var completedOnce = false

    init(_ config: VMConfig, job: Data, managed: ManagedJob? = nil) { self.config = config; self.job = job; self.managed = managed }

    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection connection: VZVirtioSocketConnection,
                  from socketDevice: VZVirtioSocketDevice) -> Bool {
        lock.lock()
#if HC_VM_PROTOCOL_UAT
        // Exercise an actual VZ callback arriving after the admission fence.
        if config.fixtureFault == "closed-job-admission" { jobAdmissionClosed = true }
#endif
        if jobAdmissionClosed || stopping || completedOnce {
            jobConnectionsRefusedAfterClose += 1
            lock.unlock()
#if HC_VM_PROTOCOL_UAT
            if config.fixtureFault == "closed-job-admission" { stop("fixture-job-admission-closed") }
#endif
            return false
        }
        if jobConnections != 0 { lock.unlock(); stop("duplicate-job-connection"); return false }
        jobConnections += 1; jobConnection = connection
        lock.unlock()
        DispatchQueue.global().async {
            defer { self.transportDone.signal() }
            do {
                var sentNonce = self.nonce
#if HC_VM_PROTOCOL_UAT
                if self.config.fixtureFault == "replay-nonce" { sentNonce = self.config.fixtureReplayNonce! }
#endif
                let version = self.config.managed ? "3" : "2"
                let envelope = try JSONSerialization.data(withJSONObject: ["schema":"testifysec.vm-envelope/v"+version, "nonce":sentNonce, "jobBase64":self.job.base64EncodedString()], options: [.sortedKeys])
                guard envelope.count <= (self.config.managed ? managedFrameLimit : 65536) else { throw FixtureError.refused("job-envelope-size") }
                var size = UInt32(envelope.count).bigEndian
                var frame = Data(("HCJOB"+version+"\r\n").utf8)
                withUnsafeBytes(of: &size) { frame.append(contentsOf: $0) }
                frame.append(envelope)
#if HC_VM_PROTOCOL_UAT
                switch self.config.fixtureFault {
                case "duplicate-frame": frame.append(frame)
                case "oversize-frame": frame.replaceSubrange(8..<12, with: [0,1,0,1]); frame = Data(frame.prefix(12))
                case "truncated-frame": frame.removeLast()
                default: break
                }
#endif
                self.lock.lock(); self.jobFrameSha256 = SHA256.hash(data:frame).map { String(format:"%02x",$0) }.joined(); self.lock.unlock()
                let fd = connection.fileDescriptor
                var timeout = timeval(tv_sec: 3, tv_usec: 0)
                guard setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else { throw FixtureError.refused("job-write-deadline") }
                var noSignal: Int32 = 1
                guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw FixtureError.refused("job-write-options") }
                var offset = 0
                while offset < frame.count {
                    let written = frame.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), frame.count-offset) }
                    if written < 0 && errno == EINTR { continue }
                    guard written > 0 else { throw FixtureError.refused("job-write") }
                    offset += written
                }
#if HC_VM_PROTOCOL_UAT
                if self.config.fixtureFault == "hold-open" { return }
#endif
                guard shutdown(fd, SHUT_WR) == 0 else { throw FixtureError.refused("job-close-write") }
                self.lock.lock(); self.jobSent = true; self.lock.unlock()
            } catch { self.stop("job-transport-failed") }
        }
        return true
    }

    func finish(stopped: Bool, error: String?) {
        lock.lock()
        self.stopped = stopped
        if let error = error, self.error == nil { self.error = error }
        let signal = !completedOnce
        jobAdmissionClosed = true
        completedOnce = true
        lock.unlock()
        if signal { completed.signal() }
    }

    func stop(_ reason: String) {
        queue.async {
            self.lock.lock()
            if self.error == nil { self.error = reason }
            self.jobAdmissionClosed = true
            if self.stopping || self.stopped { self.lock.unlock(); return }
            self.stopping = true
            self.lock.unlock()
            guard let machine = self.machine else { self.finish(stopped: false, error: "vm-already-released"); return }
            if machine.state == .stopped { self.finish(stopped: true, error: nil); return }
            if !machine.canStop { self.finish(stopped: false, error: "vm-not-stoppable"); return }
            machine.stop { error in
                self.finish(stopped: error == nil && machine.state == .stopped,
                            error: error == nil ? nil : "vm-stop-failed")
            }
        }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) { finish(stopped: virtualMachine.state == .stopped, error: nil) }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        finish(stopped: virtualMachine.state == .stopped, error: "vm-runtime-error")
    }

    func consume(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        serialBytes += data.count
        serialTail.append(data)
        if serialTail.count > 4096 { serialTail.removeFirst(serialTail.count - 4096) }
        let resultLimit = config.managed ? managedResultLimit : 65536
        if serialBytes > (config.managed ? managedResultLimit + 262144 : 262144) { if error == nil { error = "serial-output-limit" }; stop("serial-output-limit"); return }
        buffer.append(data)
        if buffer.count > resultLimit + 24 && !buffer.contains(10) { error = "serial-frame-limit"; stop("serial-frame-limit"); return }
        while let newline = buffer.firstIndex(of: 10) {
            var line = Data(buffer[..<newline]); buffer.removeSubrange(...newline)
            if line.last == 13 { line.removeLast() }
            guard line.starts(with: Data((config.managed ? "HCVM3 " : "HCVM1 ").utf8)) else { continue }
            if config.managed {
                do {
                    guard guest == nil,line.count>=15,line.count<=resultLimit+15,
                          let hex=String(data:line[6..<14],encoding:.ascii),let size=Int(hex,radix:16),size<=resultLimit,
                          line[14]==32,size==line.count-15,let expected=managed else {throw FixtureError.refused("managed-result-frame")}
                    guest=try managedResult(line.subdata(in:15..<line.count),config:config,nonce:nonce,job:expected)
                } catch {self.error="invalid-managed-result";stop("invalid-managed-result")}
                continue
            }
            guard guest == nil, line.count >= 15, line.count <= 65551,
                  let sizeString = String(data: line[6..<14], encoding: .ascii),
                  let size = Int(sizeString, radix: 16), size <= 65536,
                  line[14] == 32, size == line.count - 15,
                  let value = try? JSONSerialization.jsonObject(with: line.subdata(in: 15..<line.count)) as? [String: Any],
                  value["schema"] as? String == "testifysec.vm-result/v2",
                  value["nonce"] as? String == nonce,
                  value["jobSha256"] as? String == config.jobSha256,
                  let bindingJSON = value["binding"],
                  let bindingData = try? JSONSerialization.data(withJSONObject: bindingJSON),
                  let binding = try? JSONDecoder().decode(Binding.self, from: bindingData), binding == config.binding,
                  value["pid"] as? Int == 1 else {
                error = "invalid-guest-frame"; stop("invalid-guest-frame"); return
            }
            guest = value
        }
    }

    func run() throws -> [String: Any] {
        let vm = VZVirtualMachineConfiguration()
        vm.platform = VZGenericPlatformConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: config.kernel))
        boot.commandLine = "console=hvc0 root=/dev/vda rootfstype=ext4 ro init=/init panic=-1 loglevel=3 bonding.max_bonds=0 dummy.numdummies=0" +
            " hc.nonce=\(nonce) hc.job=\(config.jobSha256) hc.request=\(config.binding.requestSha256) hc.profile=\(config.binding.profileSha256) hc.session=\(config.binding.sessionId) hc.materials=\(config.binding.materialsSha256) hc.backend=\(config.binding.backendSha256)"
        if config.managed { boot.commandLine += " hc.protocol=3" }
        if config.gatewayConfigFile != nil { boot.commandLine += " hc.gateway=1" }
        vm.bootLoader = boot
        vm.cpuCount = config.cpus
        vm.memorySize = config.memoryMiB * 1024 * 1024
        vm.networkDevices = []
        vm.directorySharingDevices = []
        vm.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        vm.memoryBalloonDevices = []
        vm.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        let attachment = try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: config.rootDisk), readOnly: true)
        vm.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: attachment)]
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: pipe.fileHandleForWriting)
        vm.serialPorts = [serial]
        try vm.validate()
        if let file = config.gatewayConfigFile, let digest = config.gatewayConfigSha256 {
            modelRelay = ModelRelay(assignment:try GatewayAssignment(file:file,digest:digest,binding:config.binding,backendManifestSha256:config.backendManifestSha256),
                binding:config.binding,nonce:nonce,jobSha256:config.jobSha256,allowed:{
                    self.lock.lock();defer { self.lock.unlock() }
                    return self.jobSent && !self.stopping && !self.completedOnce
                },refuse:{ self.stop($0) })
#if HC_VM_PROTOCOL_UAT
            modelRelay?.fixtureReceiptFault = config.fixtureFault
#endif
        }
        queue.sync {
            machine = VZVirtualMachine(configuration: vm, queue: queue)
            machine.delegate = self
            socketListener.delegate = self
            (machine.socketDevices[0] as! VZVirtioSocketDevice).setSocketListener(socketListener, forPort: 17001)
            if let relay = modelRelay { (machine.socketDevices[0] as! VZVirtioSocketDevice).setSocketListener(relay.listener,forPort:17002) }
        }
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: queue)
        term.setEventHandler { self.stop("cancelled") }
        interrupt.setEventHandler { self.stop("cancelled") }
        term.resume(); interrupt.resume()
        defer { term.cancel(); interrupt.cancel(); signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL) }
        let readerDone = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { readerDone.signal() }
            do {
                try readVMSerial(self.pipe.fileHandleForReading, consume:self.consume)
                self.lock.lock(); self.serialEOFObserved = true; self.lock.unlock()
            } catch {
                // V4 must expose/refuse the read failure even if the asynchronous
                // stop callback runs after final observation assembly.
                if self.config.schema == "testifysec.vm-config/v4" {
                    self.lock.lock(); if self.error == nil { self.error = "serial-read-failed" }; self.lock.unlock()
                }
                self.stop("serial-read-failed")
            }
        }
        queue.async {
            self.machine.start { result in
                switch result {
                case .success: self.lock.lock(); self.running = true; self.lock.unlock()
                case .failure: self.finish(stopped: self.machine.state == .stopped, error: "vm-start-failed")
                }
            }
        }
        let timeout = completed.wait(timeout: .now() + .seconds(config.timeoutSeconds))
        if timeout == .timedOut {
            stop("host-deadline")
            if completed.wait(timeout: .now() + .seconds(10)) == .timedOut { finish(stopped: false, error: "vm-stop-deadline") }
        }
        // Release the VZ attachment before waiting for serial EOF. A reported
        // guest result alone is never a successful VM lifecycle result.
        // Listener callbacks run on the VM queue. Close admission and remove
        // the listener there before taking the complete transport snapshot.
        // A callback queued later also sees the closed flag and cannot register
        // a sender after this drain begins.
        let transport = queue.sync { () -> (VZVirtioSocketConnection?, Int) in
            lock.lock(); jobAdmissionClosed = true; lock.unlock()
            modelRelay?.closeAdmission()
            if let device = machine?.socketDevices.first as? VZVirtioSocketDevice {
                device.removeSocketListener(forPort: 17001)
                device.removeSocketListener(forPort: 17002)
            }
            lock.lock(); defer { lock.unlock() }
            return (jobConnection, jobConnections)
        }
        let (connection, connections) = transport
        if let connection = connection { _ = shutdown(connection.fileDescriptor, SHUT_RDWR) }
        let transportDrained = connections == 0 || transportDone.wait(timeout: .now() + .seconds(4)) == .success
        if !transportDrained {
            lock.lock(); error = "job-transport-drain-deadline"; lock.unlock()
        }
        let relayDrained = modelRelay?.drain() ?? true
        if !relayDrained { lock.lock();error = "gateway-relay-drain-deadline";lock.unlock() }
        queue.sync { machine = nil }
        lock.lock(); jobConnection = nil; lock.unlock()
        try? pipe.fileHandleForWriting.close()
        let serialReaderDrained = readerDone.wait(timeout: .now() + .seconds(3)) == .success
        if !serialReaderDrained { lock.lock(); error = "serial-drain-deadline"; lock.unlock() }
        try? pipe.fileHandleForReading.close()
        lock.lock(); defer { lock.unlock() }
        let observation: [String:Any] = ["schema":config.managed ? "testifysec.vm-observation/v3" : "testifysec.vm-observation/v2", "passed":running && stopped && jobSent && error == nil && guest?["passed"] as? Bool == true && guest?["jobValidated"] as? Bool == true,
                "started":running, "stopped":stopped, "error":error ?? NSNull(), "guestResult":guest ?? [:],
                "serialBytes":serialBytes, "serialTailBase64":serialTail.base64EncodedString(), "configuredCPUs":config.cpus, "configuredMemoryMiB":config.memoryMiB,
                "networkDevices":0, "sharedDirectories":0, "writableHostDisks":0,
                "jobPort":17001, "jobFrameSha256":jobFrameSha256 ?? NSNull(), "jobConnections":jobConnections, "jobSent":jobSent, "bootNonce":nonce,
                "jobAdmissionClosed":jobAdmissionClosed, "jobTransportDrained":transportDrained, "jobConnectionsRefusedAfterClose":jobConnectionsRefusedAfterClose,
                "rootDiskSha256":config.rootDiskSha256, "jobSha256":config.jobSha256,
                "qualification":"developer-only-unqualified", "admissionIntegrated":false, "gatewayIntegrated":modelRelay != nil,
                "gatewayRelay":modelRelay?.observation() ?? ["enabled":false], "gatewayRelayDrained":relayDrained]
        return serialObservation(observation,configSchema:config.schema,drained:serialReaderDrained,eof:serialEOFObserved)
    }
}

// Shared by the normal host and the compiled configuration UAT. No VM starts
// until this exact validation succeeds; a returned value is not an execution grant.
func validatedVMInputs(_ raw: Data) throws -> (config: VMConfig, job: Data, managed: ManagedJob?) {
    guard raw.count <= 4096 else { throw FixtureError.refused("config-size") }
    let config = try JSONDecoder().decode(VMConfig.self, from: raw)
    guard ["testifysec.vm-config/v2","testifysec.vm-config/v3","testifysec.vm-config/v4"].contains(config.schema), config.cpus == 1,
          [UInt64(512),1024].contains(config.memoryMiB), (1...70).contains(config.timeoutSeconds),
          validHex(config.jobSha256, count:64), validHex(config.binding.requestSha256,count:64),
          validHex(config.binding.profileSha256,count:64), validHex(config.binding.materialsSha256,count:64),
          validHex(config.binding.backendSha256,count:64),
          config.binding.sessionId.range(of:"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", options:.regularExpression) != nil else { throw FixtureError.refused("config-bounds") }
    if config.schema == "testifysec.vm-config/v4" {
        // This runtime-only pin is assigned after backend export. It is not the
        // legacy kernel/root pair hash and never enters build provenance.
        var parser = ManagedJSON(bytes:Array(raw)); let object = try parser.parse()
        try managedKeys(object, ["schema","kernel","kernelSha256","rootDisk","rootDiskSha256","jobFile","jobSha256","binding","memoryMiB","cpus","timeoutSeconds","gatewayConfigFile","gatewayConfigSha256","backendManifestSha256"])
        guard let digest = config.backendManifestSha256, validHex(digest,count:64),
              config.gatewayConfigFile != nil, config.gatewayConfigSha256 != nil else {
            throw FixtureError.refused("backend-manifest-config")
        }
    }
    try checkedFile(config.kernel, digest: config.kernelSha256)
    try checkedFile(config.rootDisk, digest: config.rootDiskSha256)
    let backend = SHA256.hash(data: Data((config.kernelSha256 + "\n" + config.rootDiskSha256 + "\n").utf8)).map { String(format:"%02x",$0) }.joined()
    guard config.binding.backendSha256 == backend else { throw FixtureError.refused("backend-binding") }
    let job = try boundedJob(config.jobFile, digest: config.jobSha256, managed: config.managed)
    let managed = config.managed ? try ManagedJob(job,binding:config.binding) : nil
    if let managed=managed {
        var parser=ManagedJSON(bytes:Array(raw));_ = try parser.parse()
        guard config.memoryMiB==1024,config.timeoutSeconds>=managed.timeoutSeconds+10 else {throw FixtureError.refused("managed-config-limits")}
    }
    guard (config.gatewayConfigFile == nil) == (config.gatewayConfigSha256 == nil) else { throw FixtureError.refused("gateway-config-pair") }
    var fields = Set(["schema","kernel","kernelSha256","rootDisk","rootDiskSha256","jobFile","jobSha256","binding","memoryMiB","cpus","timeoutSeconds","gatewayConfigFile","gatewayConfigSha256"])
    if config.schema == "testifysec.vm-config/v4" { fields.insert("backendManifestSha256") }
#if HC_VM_PROTOCOL_UAT
    fields.insert("fixtureFault"); fields.insert("fixtureReplayNonce")
    guard config.fixtureReplayNonce == nil || (config.fixtureFault == "replay-nonce" && validHex(config.fixtureReplayNonce!, count:32)),
          config.fixtureFault != "replay-nonce" || config.fixtureReplayNonce != nil else { throw FixtureError.refused("fixture-replay-nonce") }
    guard config.fixtureFault == nil || ["replay-nonce","duplicate-frame","oversize-frame","truncated-frame","hold-open","closed-job-admission","receipt-wrong-magic","receipt-wrong-digest","receipt-short","receipt-missing"].contains(config.fixtureFault!) else { throw FixtureError.refused("fixture-fault") }
#endif
    guard let object = try JSONSerialization.jsonObject(with:raw) as? [String:Any], Set(object.keys).isSubset(of:fields),
          let assigned = object["binding"] as? [String:Any],
          Set(assigned.keys) == Set(["requestSha256","profileSha256","sessionId","materialsSha256","backendSha256"]) else { throw FixtureError.refused("config-fields") }
    // Validate the selected gateway before creating VZ devices; Runner checks
    // it again when establishing the relay. This does not admit a profile.
    if let file = config.gatewayConfigFile, let digest = config.gatewayConfigSha256 {
        _ = try GatewayAssignment(file:file,digest:digest,binding:config.binding,backendManifestSha256:config.backendManifestSha256)
    }
    return (config, job, managed)
}

@main struct Main {
    static func main() {
        do {
            guard CommandLine.arguments.count == 2 else { throw FixtureError.refused("usage: hc-vm CONFIG") }
            let raw = try boundedOwnedInput(CommandLine.arguments[1], limit:4096)
            let (config, job, managed) = try validatedVMInputs(raw)
            let report = try Runner(config, job:job, managed:managed).run()
            guard try sha256(config.kernel) == config.kernelSha256,
                  try sha256(config.rootDisk) == config.rootDiskSha256 else { throw FixtureError.refused("input-path-changed") }
            let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
            FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data("\n".utf8))
            exit(report["passed"] as? Bool == true ? 0 : 3)
        } catch {
            FileHandle.standardError.write(Data("VM fixture refused: \(error)\n".utf8))
            exit(2)
        }
    }
}
