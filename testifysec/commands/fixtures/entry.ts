// jade:ring local
import { runNative } from "../embedded"
import fs from "node:fs/promises"
import path from "node:path"
import type { EnrollmentRequest } from "../request"
const [mode, state] = process.argv.slice(2)
const request = { schema: "testifysec.hardened-code.enroll/v1", trustMode: "local-self-signed", stateDirectory: state, name: mode } as EnrollmentRequest
if (mode === "mkdir-collision") {
  await fs.mkdir(path.join(state,"mkdir-collision"),{mode:0o700})
  await fs.writeFile(path.join(state,"mkdir-collision","unowned-sentinel"),"fixture-owned before runner mkdir")
}
for (const key of ["DYLD_INSERT_LIBRARIES","LD_PRELOAD","NODE_OPTIONS","BUN_OPTIONS","HTTPS_PROXY","HTTP_PROXY","ALL_PROXY","OPENAI_API_KEY","CILOCK_TOKEN"]) process.env[key]="synthetic-poison"
if (mode === "platform") { request.trustMode="platform"; request.platformURL="https://fixture.invalid" }
if (mode === "attest") (request as {schema:string}).schema="testifysec.hardened-code.attest/v1"
let events = 0
try {
  const controller = new AbortController()
  if (mode === "cancel-before") controller.abort()
  if (mode === "request-size") request.name = "x".repeat(16385)
  if (mode === "request-accessor") Object.defineProperty(request, "name", {enumerable:true,get(){throw new Error("must-not-run")}})
  const result = await runNative(mode === "unknown-role" ? "unknown" as "enroll" : mode === "attest" ? "attest" : "enroll", request as never, event => {
    events++
    if (mode === "callback") throw new Error("fixture callback rejected")
    if (mode === "cancel") controller.abort()
    if (mode === "signal") process.kill(process.pid,"SIGTERM")
  }, {signal:controller.signal})
  process.stdout.write(JSON.stringify({passed:true,...result})+"\n")
} catch (error) {
  process.stdout.write(JSON.stringify({passed:false,code:(error as {code?:string}).code ?? "unclassified",events})+"\n")
  process.exitCode=1
}
