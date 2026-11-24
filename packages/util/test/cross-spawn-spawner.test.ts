import { describe, expect, test } from "bun:test"
import { PassThrough } from "node:stream"
import { tolerateClosedPipe } from "../src/cross-spawn-spawner.js"

const epipe = () => Object.assign(new Error("EPIPE: broken pipe, write"), { code: "EPIPE", syscall: "write" })

// Bun can emit EPIPE on a child's stdin after "finish": end() finishes, then the auto-destroy flushes and the
// child has already exited (seen on Linux CI with `git check-ignore` on a broken config). The stdin sink drops
// its error listener on "finish", so without a listener of our own the error is uncaught.
describe("tolerateClosedPipe", () => {
  test("control: an EPIPE emitted on a stream with no error listener throws", () => {
    const stdin = new PassThrough()
    expect(() => stdin.emit("error", epipe())).toThrow("EPIPE")
  })

  test("a child stdin that hits EPIPE after its writer is done does not throw", () => {
    const stdin = tolerateClosedPipe(new PassThrough())
    expect(() => stdin.emit("error", epipe())).not.toThrow()
  })

  test("an error the writer is listening for is left to the writer", () => {
    const stdin = tolerateClosedPipe(new PassThrough())
    const seen: string[] = []
    stdin.once("error", (error: Error) => seen.push(error.message))
    expect(() => stdin.emit("error", Object.assign(new Error("boom"), { code: "EIO" }))).not.toThrow()
    expect(seen).toEqual(["boom"])
  })

  test("other stdin errors still surface when nothing else listens", () => {
    const stdin = tolerateClosedPipe(new PassThrough())
    expect(() => stdin.emit("error", Object.assign(new Error("boom"), { code: "EIO" }))).toThrow("boom")
  })
})
