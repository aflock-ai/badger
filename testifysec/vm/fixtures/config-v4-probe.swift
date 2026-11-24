// jade:ring local
// Compiled with the exact host sources and only the production @main attribute
// removed. Calls the same pre-launch validation; never constructs a Runner.
import Foundation
import Darwin

final class SerialFixtureState {
    let lock = NSLock()
    var eof = false
    var failed = false
    var bytes = Data()
}

@main struct ConfigV4Probe {
    static func main() {
        var output: [String:Any]
        var code: Int32 = 0
        do {
            if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--serial-case" {
                try serialCase(CommandLine.arguments[2]); return
            }
            guard CommandLine.arguments.count == 2 else { throw FixtureError.refused("fixture-arguments") }
            let raw = try boundedOwnedInput(CommandLine.arguments[1],limit:4096)
            let inputs = try validatedVMInputs(raw)
            output = ["accepted":true,"configSchema":inputs.config.schema,"managed":inputs.config.managed,
                      "jobSha256":managedHash(inputs.job),"backendPairSha256":inputs.config.binding.backendSha256,
                      "backendManifestSha256":inputs.config.backendManifestSha256 ?? NSNull(),
                      "gatewayConfigured":inputs.config.gatewayConfigFile != nil,"vmStarted":false]
        } catch FixtureError.refused(let reason) {
            output = ["accepted":false,"code":reason,"vmStarted":false]; code = 2
        } catch {
            output = ["accepted":false,"code":"decode-refused","vmStarted":false]; code = 2
        }
        do {
            let raw = try JSONSerialization.data(withJSONObject:output,options:.sortedKeys)
            FileHandle.standardOutput.write(raw); FileHandle.standardOutput.write(Data("\n".utf8))
        } catch { exit(3) }
        exit(code)
    }
    static func serialCase(_ mode: String) throws {
        guard ["empty-eof","bytes-eof","read-error","held-writer"].contains(mode) else {throw FixtureError.refused("fixture-mode")}
        let pipe = Pipe(), state = SerialFixtureState(), done = DispatchSemaphore(value:0)
        defer { try? pipe.fileHandleForReading.close(); try? pipe.fileHandleForWriting.close() }
        if mode == "read-error" { try pipe.fileHandleForReading.close() }
        if mode == "bytes-eof" { try pipe.fileHandleForWriting.write(contentsOf:Data("actual serial bytes\n".utf8)) }
        if mode != "held-writer" { try pipe.fileHandleForWriting.close() }
        DispatchQueue.global().async {
            defer {done.signal()}
            do {
                try readVMSerial(pipe.fileHandleForReading) {data in state.lock.lock();state.bytes.append(data);state.lock.unlock()}
                state.lock.lock();state.eof = true;state.lock.unlock()
            } catch {state.lock.lock();state.failed = true;state.lock.unlock()}
        }
        let drained = done.wait(timeout:.now() + .milliseconds(mode == "held-writer" ? 30 : 1000)) == .success
        state.lock.lock();let eof=state.eof, failed=state.failed, bytes=state.bytes;state.lock.unlock()
        var followup: [String:Any] = [:]
        if mode == "held-writer" {
            try pipe.fileHandleForWriting.close()
            guard done.wait(timeout:.now() + .seconds(1)) == .success else {throw FixtureError.refused("fixture-drain")}
            state.lock.lock();followup=["drained":true,"eof":state.eof,"failed":state.failed];state.lock.unlock()
        } else if !drained {throw FixtureError.refused("fixture-drain")}
        let base: [String:Any] = ["schema":"testifysec.vm-observation/v3","passed":true,"admissionIntegrated":false]
        var versions: [String:Any] = [:]
        for version in [2,3,4] {
            var old=base;old["schema"]="testifysec.vm-observation/v\(version == 2 ? 2 : 3)"
            versions[String(version)] = serialObservation(old,configSchema:"testifysec.vm-config/v\(version)",drained:drained,eof:eof)
        }
        let result: [String:Any] = ["mode":mode,"drained":drained,"eof":eof,"failed":failed,
                                  "bytesBase64":bytes.base64EncodedString(),"observations":versions,"followup":followup]
        let raw=try JSONSerialization.data(withJSONObject:result,options:.sortedKeys)
        FileHandle.standardOutput.write(raw);FileHandle.standardOutput.write(Data("\n".utf8))
    }

}
