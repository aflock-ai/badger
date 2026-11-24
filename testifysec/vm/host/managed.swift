// Managed-shaped V3 transport and regular-file observations only. No signed
// admission, credential authority, broker receipt or hardware measurement.
import Foundation
import CryptoKit

let managedJobLimit = 512 * 1024
let managedFrameLimit = 768 * 1024
let managedResultLimit = 768 * 1024
let managedContentLimit = 256 * 1024
let managedFileLimit = 64 * 1024
let managedOutputLimit = 64 * 1024
let managedFilesLimit = 128
let managedEntriesLimit = 256

func managedHash(_ data: Data) -> String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }

// Validate original bytes before Foundation can collapse duplicate aliases or
// coerce JSON numbers. Track exact root value spans for job content bindings.
struct ManagedJSON {
    let bytes: [UInt8]
    var offset = 0
    var fields: [String:Range<Int>] = [:]
    mutating func space() { while offset < bytes.count && [9,10,13,32].contains(bytes[offset]) { offset += 1 } }
    mutating func string() throws -> String {
        guard offset < bytes.count, bytes[offset] == 34 else { throw FixtureError.refused("managed-json-string") }
        let start = offset; offset += 1
        while offset < bytes.count {
            let ch = bytes[offset]; offset += 1
            if ch == 34 {
                guard let value = try JSONSerialization.jsonObject(with:Data(bytes[start..<offset]),options:.fragmentsAllowed) as? String else { throw FixtureError.refused("managed-json-string") }
                return value
            }
            if ch == 92 { offset += 1 }
        }
        throw FixtureError.refused("managed-json-string")
    }
    mutating func value(_ depth: Int = 0) throws {
        space(); guard depth <= 40, offset < bytes.count else { throw FixtureError.refused("managed-json-bounds") }
        if bytes[offset] == 34 { _ = try string(); return }
        if bytes[offset] == 123 {
            offset += 1; space(); var seen = Set<String>()
            if offset < bytes.count && bytes[offset] == 125 { offset += 1; return }
            while offset < bytes.count {
                let key = try string(); guard seen.insert(key).inserted else { throw FixtureError.refused("managed-json-duplicate") }
                space(); guard offset < bytes.count, bytes[offset] == 58 else { throw FixtureError.refused("managed-json-object") }
                offset += 1; space(); let start = offset; try value(depth+1)
                if depth == 0 { fields[key] = start..<offset }
                space(); guard offset < bytes.count else { throw FixtureError.refused("managed-json-object") }
                if bytes[offset] == 125 { offset += 1; return }
                guard bytes[offset] == 44 else { throw FixtureError.refused("managed-json-object") }; offset += 1; space()
            }
            throw FixtureError.refused("managed-json-object")
        }
        if bytes[offset] == 91 {
            offset += 1; space()
            if offset < bytes.count && bytes[offset] == 93 { offset += 1; return }
            while offset < bytes.count {
                try value(depth+1);space();guard offset < bytes.count else { throw FixtureError.refused("managed-json-array") }
                if bytes[offset] == 93 {offset += 1;return}
                guard bytes[offset] == 44 else {throw FixtureError.refused("managed-json-array")};offset += 1
            }
            throw FixtureError.refused("managed-json-array")
        }
        for literal in ["true","false","null"] {
            let data=Array(literal.utf8)
            if bytes.dropFirst(offset).starts(with:data) {offset += data.count;return}
        }
        let start=offset
        if bytes[offset] == 45 {offset += 1}
        let digits=offset
        while offset < bytes.count && (48...57).contains(bytes[offset]) {offset += 1}
        guard offset>digits, offset-digits<=10, !(bytes[digits] == 48 && offset-digits>1), !(offset-start>1 && bytes[start] == 45 && bytes[digits] == 48) else {throw FixtureError.refused("managed-json-number")}
    }
    mutating func parse() throws -> [String:Any] {
        guard String(bytes:bytes,encoding:.utf8) != nil else {throw FixtureError.refused("managed-json-encoding")}
        try value();space()
        guard offset == bytes.count, let object = try JSONSerialization.jsonObject(with:Data(bytes)) as? [String:Any] else {throw FixtureError.refused("managed-json-trailing")}
        return object
    }
}
func managedKeys(_ object: [String:Any], _ names: [String]) throws {
    guard Set(object.keys) == Set(names) else {throw FixtureError.refused("managed-fields")}
}

struct ManagedFile: Codable {
    let path: String
    let sha256: String
    let size: Int
    let executable: Bool
    let contentBase64: String
}
func managedPath(_ name: String) -> Bool {
    let bytes=Array(name.utf8)
    guard !bytes.isEmpty,bytes.count<=1024,bytes.allSatisfy({$0>=32 && $0<127}),!name.contains(where:{"\\:*?\"<>|".contains($0)}) else {return false}
    let parts=name.split(separator:"/",omittingEmptySubsequences:false)
    guard parts.count<=32 else {return false}
    for part in parts {
        guard !part.isEmpty,part != ".",part != "..",part.utf8.count<=255,!part.hasSuffix("."),!part.hasSuffix(" ") else {return false}
        let lower=part.lowercased(),stem=part.lowercased().split(separator:".",omittingEmptySubsequences:false)[0]
        if lower == ".git" || lower.hasPrefix("git~") || ["con","prn","aux","nul"].contains(stem) {return false}
        if stem.count == 4 && (stem.hasPrefix("com") || stem.hasPrefix("lpt")) && "0123456789".contains(stem.last!) {return false}
    }
    return true
}
func managedManifest(_ files: [ManagedFile]) -> String {
    // Exact Go json.Marshal descriptor field order; paths are portable ASCII.
    let parts=files.map { f in
        let name=f.path.replacingOccurrences(of:"&",with:"\\u0026")
        return "{\"path\":\"\(name)\",\"sha256\":\"\(f.sha256)\",\"size\":\(f.size),\"executable\":\(f.executable ? "true":"false")}"
    }
    return managedHash(Data(("["+parts.joined(separator:",")+"]").utf8))
}
func managedFiles(_ values: Any) throws -> [ManagedFile] {
    guard let array=values as? [[String:Any]],array.count<=managedFilesLimit else {throw FixtureError.refused("managed-files")}
    var files=[ManagedFile](),names=[String:String](),regular=Set<String>(),previous="",total=0
    for object in array {
        try managedKeys(object,["path","sha256","size","executable","contentBase64"])
        let f=try JSONDecoder().decode(ManagedFile.self,from:JSONSerialization.data(withJSONObject:object))
        guard managedPath(f.path),f.path>previous,validHex(f.sha256,count:64),f.size>=0,f.size<=managedFileLimit,
              let bytes=Data(base64Encoded:f.contentBase64),bytes.base64EncodedString()==f.contentBase64,bytes.count==f.size,managedHash(bytes)==f.sha256 else {throw FixtureError.refused("managed-file-binding")}
        previous=f.path;total += f.size;guard total<=managedContentLimit else {throw FixtureError.refused("managed-content-limit")}
        let parts=f.path.split(separator:"/")
        for i in parts.indices {
            let prefix=parts[0...i].joined(separator:"/"),key=prefix.lowercased()
            guard names[key] == nil || names[key] == prefix && !regular.contains(key) && i != parts.count-1 else {throw FixtureError.refused("managed-file-collision")}
            names[key]=prefix
            if i==parts.count-1 {regular.insert(key)}
        }
        guard names.count<=managedEntriesLimit else {throw FixtureError.refused("managed-entry-limit")}
        files.append(f)
    }
    return files
}

struct ManagedJob {
    let files: [ManagedFile]
    let timeoutSeconds: Int
    init(_ data: Data, binding: Binding) throws {
        guard data.count<=managedJobLimit else {throw FixtureError.refused("managed-job-limit")}
        var parser=ManagedJSON(bytes:Array(data));let object=try parser.parse()
        try managedKeys(object,["schema","binding","request","materials"])
        guard data.count<=managedJobLimit,object["schema"] as? String == "testifysec.vm-job/v3",
              let assigned=object["binding"] as? [String:Any],let request=object["request"] as? [String:Any],
              let requestSpan=parser.fields["request"],let materialSpan=parser.fields["materials"] else {throw FixtureError.refused("managed-job")}
        try managedKeys(assigned,["requestSha256","profileSha256","sessionId","materialsSha256","backendSha256"])
        try managedKeys(request,["prompt","timeoutSeconds"])
        struct Request:Decodable {let prompt:String;let timeoutSeconds:Int}
        let req=try JSONDecoder().decode(Request.self,from:JSONSerialization.data(withJSONObject:request))
        guard req.prompt.utf8.count<=4096,(1...45).contains(req.timeoutSeconds),
              try JSONDecoder().decode(Binding.self,from:JSONSerialization.data(withJSONObject:assigned))==binding,
              managedHash(data.subdata(in:requestSpan))==binding.requestSha256,
              managedHash(data.subdata(in:materialSpan))==binding.materialsSha256 else {throw FixtureError.refused("managed-job-binding")}
        files=try managedFiles(object["materials"] as Any);timeoutSeconds=req.timeoutSeconds
    }
}

struct ManagedResult: Decodable {
    let schema:String;let nonce:String;let jobSha256:String;let binding:Binding
    let jobValidated:Bool;let passed:Bool;let error:String;let pid:Int;let workerUid:Int;let rootReadonly:Bool
    let workerStarted:Bool;let exitObserved:Bool;let exitCode:Int?;let reaped:Bool
    let outputDrained:Bool;let outputComplete:Bool;let outputBase64:String;let outputSha256:String
    let captureComplete:Bool;let initialManifestSha256:String;let finalManifestSha256:String
    let files:[ManagedFile];let removed:[String]
}
func managedResult(_ data: Data, config: VMConfig, nonce: String, job: ManagedJob) throws -> [String:Any] {
    guard data.count<=managedResultLimit else {throw FixtureError.refused("managed-result-limit")}
    var parser=ManagedJSON(bytes:Array(data));let object=try parser.parse()
    try managedKeys(object,["schema","nonce","jobSha256","binding","jobValidated","passed","error","pid","workerUid","rootReadonly","workerStarted","exitObserved","exitCode","reaped","outputDrained","outputComplete","outputBase64","outputSha256","captureComplete","initialManifestSha256","finalManifestSha256","files","removed"])
    guard let assigned=object["binding"] as? [String:Any] else {throw FixtureError.refused("managed-result-binding")}
    try managedKeys(assigned,["requestSha256","profileSha256","sessionId","materialsSha256","backendSha256"])
    let r=try JSONDecoder().decode(ManagedResult.self,from:data)
    guard r.schema=="testifysec.vm-result/v3",r.nonce==nonce,r.jobSha256==config.jobSha256,r.binding==config.binding,r.pid==1,r.workerUid==65534,
          let output=Data(base64Encoded:r.outputBase64),output.count<=managedOutputLimit,output.base64EncodedString()==r.outputBase64,managedHash(output)==r.outputSha256,
          r.error.utf8.count<=256,r.exitObserved == (r.exitCode != nil),r.exitCode == nil || (-1...255).contains(r.exitCode!) else {throw FixtureError.refused("managed-result-binding")}
    let files=try managedFiles(object["files"] as Any)
    if r.captureComplete {
        let remaining=Set(files.map(\.path))
        guard r.jobValidated,r.rootReadonly,r.workerStarted,r.exitObserved,r.exitCode==0,r.reaped,r.outputDrained,r.outputComplete,
              r.initialManifestSha256==managedManifest(job.files),r.finalManifestSha256==managedManifest(files),
              r.removed==job.files.map(\.path).filter({!remaining.contains($0)}) else {throw FixtureError.refused("managed-capture-binding")}
    } else {
        guard files.isEmpty,r.removed.isEmpty,r.finalManifestSha256.isEmpty else {throw FixtureError.refused("managed-incomplete-capture")}
    }
    guard r.passed == (r.error.isEmpty && r.captureComplete) else {throw FixtureError.refused("managed-result-completion")}
    return object
}
