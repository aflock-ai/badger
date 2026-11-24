// jade:ring local
// Built with exact host pre-Runner declarations and host/managed.swift.
import Foundation
import Darwin
@main struct Validation {
    static func main() {
        do {
            guard CommandLine.arguments.count==4 else {throw FixtureError.refused("fixture-arguments")}
            let config=try JSONDecoder().decode(VMConfig.self,from:Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[1])))
            let job=try ManagedJob(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2])),binding:config.binding)
            let data=try Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[3]))
            let value=try managedResult(data,config:config,nonce:"0123456789abcdef0123456789abcdef",job:job)
            guard value["passed"] as? Bool == true else {throw FixtureError.refused("fixture-not-completed")}
            print("accepted")
        } catch {print("refused");exit(2)}
    }
}
