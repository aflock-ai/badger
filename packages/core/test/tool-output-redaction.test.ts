import { describe, expect, test } from "bun:test"
import { inspect, types } from "node:util"
import { ToolOutputRedaction } from "../src/tool-output-redaction"

const secret = "synthetic-password-123456"
const encodedSecret = Array.from(secret, (char) => "%" + char.charCodeAt(0).toString(16)).join("")
const forms = [
  `https://alice:${secret}@example.test/repo.git`,
  `https://alice:${encodeURIComponent(secret + "@:/")}@example.test/repo.git`,
  encodeURIComponent(`https://alice:${secret}@example.test/repo.git`),
  `https://%61%6c%69%63%65:${encodedSecret}@example.test/repo.git`,
  `https:\\/\\/alice\\u003a${secret}\\u0040example.test/repo.git`,
  `https://alice:\x1b[31m${secret}\x1b[0m@example.test/repo.git`,
  `\x1b]8;;https://alice:${secret}@example.test\x07link\x1b]8;;\x07`,
  `\x1b]0;${secret}\nmore metadata\x1b\\ok`,
  `Authorization: Bearer ${secret}`,
  `Authorization: Basic ${secret}`,
  `ssh://${secret}@example.test/repo`,
  `ghp_${secret.replaceAll("-", "")}`,
  `github_pat_${secret.replaceAll("-", "")}`,
  `glpat-${secret}`,
  `sk-proj-${secret}`,
  `sk-ant-${secret}`,
  `xoxb-${secret}`,
  `eyJ${secret}.payload.signature`,
]

const holdouts = [
  ["HTTPS://reviewer:UPPERHOLDOUT@example.invalid/x", "HTTPS://[redacted]@example.invalid/x"],
  ["sSh://reviewer:MIXEDHOLDOUT@example.invalid/x", "sSh://[redacted]@example.invalid/x"],
  ["bearer AUTHHOLDOUT", "[redacted]"],
  ["BASIC BASICHOLDOUT", "[redacted]"],
  ["https://reviewer:pa'ssHOLDOUT@example.invalid/x", "https://[redacted]@example.invalid/x"],
  ["'https://reviewer:pa'ssHOLDOUT@example.invalid/x'", "'https://[redacted]@example.invalid/x'"],
  ['"https://reviewer:pa\'ssHOLDOUT@example.invalid/x"', '"https://[redacted]@example.invalid/x"'],
] as const

const fixedLength = [
  ["aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "aws_access_key_id = [redacted]"],
  ["AWS_ACCESS_KEY_ID=ASIAY34FZKBOKMUTVV7A", "AWS_ACCESS_KEY_ID=[redacted]"],
  ["key=AIzaSyD-synthetic_HOLDOUT_0123456789abc", "key=[redacted]"],
  [
    "//registry.npmjs.org/:_authToken=npm_SYNTHETICholdout0123456789abcdefghij",
    "//registry.npmjs.org/:_authToken=[redacted]",
  ],
  ["AKIAEXAMPLE AIzaShort npm_short", "AKIAEXAMPLE AIzaShort npm_short"],
] as const

// Keys whose alphabet includes "-" can end in it; there is no word boundary after a trailing
// "-", so termination must not depend on one. Cover each at end of output and before text.
const dashEnding = [
  ["AIza" + "A".repeat(34) + "-", "[redacted]"],
  ["key=AIza" + "A".repeat(34) + "- next", "key=[redacted] next"],
  ["glpat-" + "a".repeat(19) + "-", "[redacted]"],
  ['token "glpat-' + "a".repeat(19) + '-"', 'token "[redacted]"'],
  ["xoxb-" + "1".repeat(15) + "-", "[redacted]"],
  ["sk-" + "a".repeat(15) + "-", "[redacted]"],
  ["aws AKIAIOSFODNN7EXAMPLE-suffix", "aws [redacted]-suffix"],
] as const

test("keys that end in a dash redact at end of output and before text", () => {
  for (const [raw, expected] of dashEnding) {
    expect(ToolOutputRedaction.text(raw)).toBe(expected)
    for (let split = 0; split <= raw.length; split++) {
      const stream = ToolOutputRedaction.stream()
      expect(stream.push(raw.slice(0, split))).toBe("")
      expect(stream.push(raw.slice(split))).toBe("")
      expect(stream.finish()).toBe(expected)
    }
  }
})

test("fixed-length cloud and registry keys redact at every stream split", () => {
  for (const [raw, expected] of fixedLength) {
    expect(ToolOutputRedaction.text(raw)).toBe(expected)
    for (let split = 0; split <= raw.length; split++) {
      const stream = ToolOutputRedaction.stream()
      expect(stream.push(raw.slice(0, split))).toBe("")
      expect(stream.push(raw.slice(split))).toBe("")
      expect(stream.finish()).toBe(expected)
    }
  }
})

test("independent scheme and RFC userinfo holdouts redact at every stream split", () => {
  for (const [raw, expected] of holdouts) {
    expect(ToolOutputRedaction.text(raw)).toBe(expected)
    for (let split = 0; split <= raw.length; split++) {
      const stream = ToolOutputRedaction.stream()
      expect(stream.push(raw.slice(0, split))).toBe("")
      expect(stream.push(raw.slice(split))).toBe("")
      expect(stream.finish()).toBe(expected)
    }
  }
  expect(ToolOutputRedaction.text("'https://example.invalid/x' author@example.invalid")).toBe(
    "'https://example.invalid/x' author@example.invalid",
  )
})

test("diagnostic own fields are cloned and sanitized without losing the error type", () => {
  class DiagnosticError extends Error {
    readonly _tag = "DiagnosticError"
  }
  const raw = new DiagnosticError("request failed")
  const response = { authorization: "bearer DIAGNOSTICHOLDOUT", status: 403 }
  Object.defineProperty(raw, "response", { value: response, enumerable: false })
  Object.assign(raw, { extra: { url: "HTTPS://reviewer:EXTRAHOLDOUT@example.invalid/x" } })
  const safe = ToolOutputRedaction.error(raw) as DiagnosticError & { response: typeof response; extra: { url: string } }
  expect(safe).toBeInstanceOf(DiagnosticError)
  expect(types.isNativeError(safe)).toBe(true)
  expect(safe._tag).toBe("DiagnosticError")
  expect(safe).not.toBe(raw)
  expect(safe.response).not.toBe(response)
  expect(safe.response).toEqual({ authorization: "[redacted]", status: 403 })
  expect(safe.extra.url).toBe("HTTPS://[redacted]@example.invalid/x")
  expect(response.authorization).toBe("bearer DIAGNOSTICHOLDOUT")
})

test("diagnostic cycles, causes and accessors retain no raw object or closure", () => {
  const raw = new Error("outer", { cause: new TypeError("bearer CAUSEHOLDOUT") })
  const response: { authorization: string; self?: unknown } = { authorization: "BASIC CYCLEHOLDOUT" }
  response.self = response
  let accessed = false
  Object.defineProperty(response, "body", {
    get: () => {
      accessed = true
      return "bearer ACCESSORHOLDOUT"
    },
    enumerable: true,
  })
  Object.assign(raw, { response })
  const safe = ToolOutputRedaction.error(raw) as Error & { response: typeof response & { body: string } }
  expect(safe.cause).toBeInstanceOf(TypeError)
  expect(safe.cause).not.toBe(raw.cause)
  expect((safe.cause as Error).message).toBe("[redacted]")
  expect(safe.response).not.toBe(response)
  expect(safe.response.self).toBe(safe.response)
  expect(safe.response.authorization).toBe("[redacted]")
  expect(safe.response.body).toBe("[omitted diagnostic accessor]")
  expect(accessed).toBe(false)
})

test("supported credentials are removed without decoding or rewriting ordinary source", () => {
  for (const form of forms) {
    const safe = ToolOutputRedaction.text(form)
    expect(safe).not.toContain(secret)
    expect(safe).not.toContain(secret.replaceAll("-", ""))
    expect(safe).not.toContain(encodedSecret)
    expect(safe).not.toContain("alice")
  }
  const source = 'const token = value; password = input.password; https://example.test/a%20b?x=1\n\treturn "ok"'
  expect(ToolOutputRedaction.text(source)).toBe(source)
})

test("every split is safe before emission, including ANSI and encoded credentials", () => {
  for (const form of forms) {
    for (let split = 0; split <= form.length; split++) {
      const stream = ToolOutputRedaction.stream()
      expect(stream.push(form.slice(0, split))).toBe("")
      expect(stream.push(form.slice(split))).toBe("")
      const emitted = stream.push("\n") + stream.finish()
      expect(emitted).toBe(ToolOutputRedaction.text(form) + "\n")
    }
  }
})

test("a long line fails closed and withholds the rest of the stream behind one marker", () => {
  const stream = ToolOutputRedaction.stream()
  expect(stream.push("https://alice:" + "x".repeat(100_000))).toBe("")
  // Dropping the long line is not yet withholding: nothing has been emitted in its place.
  expect(stream.withheld()).toBe(false)
  expect(stream.push(secret + "@example.test\nok\n")).toBe(ToolOutputRedaction.withheldMarker + "\n")
  expect(stream.withheld()).toBe(true)
  expect(stream.push("more\n")).toBe("")
  expect(stream.finish()).toBe("")
})

test("metadata is copied, nested strings and keys sanitized, numbers preserved", () => {
  const raw = { [forms[0]]: [{ message: forms[2], exit: 7 }] }
  const safe = ToolOutputRedaction.value(raw)
  expect(JSON.stringify(safe)).not.toContain(secret)
  expect(Object.values(safe)[0][0].exit).toBe(7)
  expect(JSON.stringify(raw)).toContain(secret)
})

test("generic MCP text blocks cannot split a credential around the boundary", () => {
  const result = ToolOutputRedaction.value({
    content: [
      { type: "text", text: "https://alice:" },
      { type: "text", text: secret + "@example.test/repo" },
    ],
  })
  expect(JSON.stringify(result).includes(secret)).toBe(false)
})

test("joining text blocks cannot undo a redaction the boundary made possible", () => {
  // Alone, the second block is a token. Joined, "prefixghp_..." has no word boundary before it.
  const token = "ghp_" + "A".repeat(36)
  for (const blocks of [
    ["prefix", token],
    [token, "suffix"],
    ["a", token, "b"],
  ]) {
    const result = ToolOutputRedaction.value(blocks.map((text) => ({ type: "text", text })))
    expect(JSON.stringify(result)).not.toContain(token)
  }
})

test("block structure is kept when every credential lies inside one block", () => {
  const token = "ghp_" + "A".repeat(36)
  const result = ToolOutputRedaction.value([
    { type: "text", text: "first" },
    { type: "text", text: `token ${token}` },
  ])
  expect(result).toEqual([
    { type: "text", text: "first" },
    { type: "text", text: "token [redacted]" },
  ])
})

test("a credential URL glued to the word before it is still redacted", () => {
  for (const glued of [`foo${forms[0]}`, `x${forms[10]}`, `git+${forms[0]}`])
    expect(ToolOutputRedaction.text(glued)).not.toContain(secret)
})

test("value keeps JSON data only: functions and symbols are dropped", () => {
  const token = "ghp_" + "A".repeat(36)
  const result: unknown = ToolOutputRedaction.value({ toJSON: () => ({ token }), keep: 1, nested: [() => token] })
  expect(JSON.stringify(result)).not.toContain(token)
  expect(result).toEqual({ keep: 1, nested: [] })
})

test("a credential used as an inherited key never appears on the copy", () => {
  const token = "ghp_" + "A".repeat(36)
  class KeyLeak extends Error {}
  ;(KeyLeak.prototype as unknown as Record<string, boolean>)[token] = true
  const copy = ToolOutputRedaction.error(new KeyLeak("x")) as object
  expect(inspect(copy, { showHidden: true, depth: Infinity })).not.toContain(token)
  expect(Object.getPrototypeOf(copy)).toBe(Error.prototype)
})

test("value works from one snapshot, so a getter cannot change shape between reads", () => {
  const token = "ghp_" + "A".repeat(36)
  let reads = 0
  const entry = {
    text: "ok",
    secret: token,
    get type() {
      return reads++ === 0 ? "text" : "other"
    },
  }
  expect(JSON.stringify(ToolOutputRedaction.value([entry]))).not.toContain(token)
})

test("an error prototype's name is part of what must be clean", () => {
  const token = "ghp_" + "A".repeat(36)
  class NameLeak extends Error {}
  ;(NameLeak.prototype as unknown as Record<string, string>).name = token
  expect(ToolOutputRedaction.safePrototype(new NameLeak("x"))).toBe(false)
  expect(String(ToolOutputRedaction.error(new NameLeak("x")))).not.toContain(token)
})

test("a shared reference is copied in each place; only a real cycle is cut", () => {
  const row = { id: 1 }
  expect(ToolOutputRedaction.value({ a: row, b: row })).toEqual({ a: { id: 1 }, b: { id: 1 } })
  const loop: Record<string, unknown> = { id: 2 }
  loop.self = loop
  expect(ToolOutputRedaction.value(loop)).toEqual({ id: 2, self: "[circular]" })
})

// 20,000 nested arrays fit in well under 50 KiB of JSON and overflow a recursive walk.
test("deeply nested data fails closed instead of overflowing the stack", () => {
  const secret = "https://alice:s3cret-deep@host.test"
  let nested: unknown = secret
  for (let depth = 0; depth < 20_000; depth++) nested = [nested]
  const value = ToolOutputRedaction.value({ output: nested })
  expect(JSON.stringify(value)).toContain(ToolOutputRedaction.tooDeep)
  expect(JSON.stringify(value)).not.toContain("s3cret")
  const cause = Object.assign(new Error("failed"), { nested })
  const copy = ToolOutputRedaction.error(cause)
  expect(copy).toBeInstanceOf(Error)
  expect(JSON.stringify((copy as { nested: unknown }).nested)).toContain(ToolOutputRedaction.tooDeep)
  // Data within the limit is copied in full.
  let shallow: unknown = "ok"
  for (let depth = 0; depth < ToolOutputRedaction.maxDepth - 2; depth++) shallow = [shallow]
  expect(JSON.stringify(ToolOutputRedaction.value(shallow))).not.toContain(ToolOutputRedaction.tooDeep)
})

test("stream() reads an encoded terminal sequence across a raw newline the way text() does", () => {
  for (const input of [
    "Bearer%1b]0;x\n%07 opaque-secret-123",
    "Bearer\\u001b]0;x\n\\u0007 opaque-secret-123\nafter",
    "status ok\nBearer%1b]2;title\nmore title\n%1b\\ opaque-secret-123\n",
  ]) {
    const whole = ToolOutputRedaction.text(input)
    expect(whole).not.toContain("opaque-secret-123")
    for (const size of [1, 3, input.length]) {
      const stream = ToolOutputRedaction.stream()
      let streamed = ""
      for (let at = 0; at < input.length; at += size) streamed += stream.push(input.slice(at, at + size))
      streamed += stream.finish()
      expect(streamed, `${JSON.stringify(input)} in ${size}s`).toBe(whole)
    }
  }
  // A line outside any sequence is still emitted as soon as it ends.
  expect(ToolOutputRedaction.stream().push("plain line\nnext")).toBe("plain line\n")
  // held() says when complete lines are being held.
  const held = ToolOutputRedaction.stream()
  expect(held.push("Bearer%1b]0;x\n")).toBe("")
  expect(held.held()).toBe(true)
  expect(held.push("%07 opaque-secret-123\n")).not.toContain("opaque-secret-123")
  expect(held.held()).toBe(false)
})

test("an overlong line inside an encoded terminal sequence drops the rest of the stream", () => {
  const long = "x".repeat(70_000)
  for (const input of [
    `Bearer%1b]0;${long}\n%07 opaque-secret-123\nafter`,
    `Bearer%1b]0;${long}\nmore title\n%1b%5c opaque-secret-123\nafter`,
    `Bearer\\u001b]0;${long}\n\\u0007 opaque-secret-123\nafter`,
    `Bearer%1b]0;${long}%07 opaque-secret-123\nafter`,
    // A look-alike of a terminator ("07" in a title) is not one.
    `Bearer%1b]0;${long}\ntitle07\n%07 opaque-secret-123\nafter`,
  ])
    for (const size of [997, input.length]) {
      const stream = ToolOutputRedaction.stream()
      let streamed = ""
      for (let at = 0; at < input.length; at += size) streamed += stream.push(input.slice(at, at + size))
      streamed += stream.finish()
      expect(streamed, `${JSON.stringify(input.slice(0, 20))} in ${size}s`).not.toContain("opaque-secret-123")
      // Where the dropped text left the sequence cannot be known, so nothing after it is trusted, and
      // one marker says output was withheld.
      expect(streamed).toBe(ToolOutputRedaction.withheldMarker + "\n")
    }
})

test("an overlapping candidate does not hide the credential after it", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
  for (const [input, hidden] of [
    ["Bearer Bearer opaque-secret-123", "opaque-secret-123"],
    ["Authorization: Basic Bearer  opaque-secret-123", "opaque-secret-123"],
    ["bearer BEARER\tbasic opaque-secret-123", "opaque-secret-123"],
    [`eyJx.a.${jwt}`, "eyJzdWIiOiIxIn0"],
    [`eyJx.a.${jwt}`, "c2lnbmF0dXJl"],
    [`eyJx.eyJy.${jwt}`, "c2lnbmF0dXJl"],
  ]) {
    const result = ToolOutputRedaction.text(input)
    const stream = ToolOutputRedaction.stream()
    expect(stream.push(input) + stream.finish()).toBe(result)
    expect(result, input).not.toContain(hidden)
  }
})

test("terminal metadata that only the JSON-only view sees is removed", () => {
  // Fully decoded, "%07" ends the escaped OSC title early and "%2F" ends the authority, so no view
  // reads a credential; JSON-only, the title runs to the escaped BEL and holds the whole URL.
  for (const input of [
    "\\u001b]0;x%07https\\u003a//alice:pa%2Fss@host\\u0007 after",
    "\\u001b]2;t%07https\\u003a//alice:pa%2Fss@host\\u001b\\\\ after",
  ]) {
    const result = ToolOutputRedaction.text(input)
    const stream = ToolOutputRedaction.stream()
    expect(stream.push(input) + stream.finish()).toBe(result)
    expect(result, input).not.toContain("alice")
    expect(result, input).not.toContain("pa%2Fss")
    expect(result).toContain("after")
  }
})

test("formatting removed after a fixed-length key keeps the boundary after it", () => {
  for (const input of [
    "AKIAIOSF\x1b[31mODNN7EXAMPLE\x1b[0mnext",
    "AKIAIOSFODNN7EXAMPLE\x1b[0mnext",
    "AKIAIOSFODNN7EXAMPLE​next",
    "npm_" + "a".repeat(36) + "\x1b[0mnext",
    JSON.stringify("AKIAIOSF\x1b[31mODNN7EXAMPLE\x1b[0mnext"),
  ]) {
    const result = ToolOutputRedaction.text(input)
    const stream = ToolOutputRedaction.stream()
    expect(stream.push(input) + stream.finish()).toBe(result)
    expect(result, JSON.stringify(input)).not.toContain("EXAMPLE")
    expect(result, JSON.stringify(input)).not.toContain("aaaaaaaaaa")
  }
  // A longer identifier that merely starts like a key, with nothing removed, is still kept.
  expect(ToolOutputRedaction.text("AKIAIOSFODNN7EXAMPLEnext")).toBe("AKIAIOSFODNN7EXAMPLEnext")
})

test("an encoded terminal opener after the line cap withholds the rest of the stream", () => {
  for (const [tail, terminator] of [
    [" Bearer%1b]0;t", "%07"],
    [" Bearer\\u001b]0;t", "%07"],
    [" Bearer%251b]0;t", "%07"],
    // Mixed spellings that decode to ESC only after two layers.
    [" Bearer%25%31%62]0;t", "%2507"],
    [" Bearer%5Cu001b]0;t", "%07"],
    [" Bearer" + "y".repeat(5000) + "%25%31%62]0;t", "%2507"],
  ]) {
    const input = "x".repeat(65_537) + tail + `\n${terminator} opaque-secret-123\nafter\n`
    for (const size of [1009, input.length]) {
      const stream = ToolOutputRedaction.stream()
      let streamed = ""
      for (let at = 0; at < input.length; at += size) streamed += stream.push(input.slice(at, at + size))
      streamed += stream.finish()
      expect(streamed, `${tail} in ${size}s`).toBe(ToolOutputRedaction.withheldMarker + "\n")
    }
  }
  // An opener split across the cap is seen too.
  const split = "x".repeat(64 * 1024 - 2) + "%1b]0;t\n%07 opaque-secret-123\n"
  const stream = ToolOutputRedaction.stream()
  expect(stream.push(split) + stream.finish()).not.toContain("opaque-secret-123")
})

test("a JSON \\uXXXX escape of a format character cannot split a token", () => {
  // Then JSON surrogate pairs for format characters outside the BMP (U+E0020, U+E0001), and U+E0020 as a
  // pair assembled across decoding passes or with one half raw.
  for (const escaped of [
    "\\u200b",
    "\\u2060",
    "\\uFEFF",
    "\\u00ad",
    "\\uDB40\\uDC20",
    "\\udb40\\udc01",
    "\\uDB40\\\\uDC20",
    "\uDB40\\uDC20",
    "\\uDB40\uDC20",
  ]) {
    const input = "ghp_AAAAAAAA" + escaped + "A".repeat(28)
    const result = ToolOutputRedaction.text(input)
    const stream = ToolOutputRedaction.stream()
    expect(stream.push(input) + stream.finish()).toBe(result)
    expect(result, input).not.toContain("AAAAAAAA")
  }
  // An escaped pair for an ordinary character is kept as written.
  expect(ToolOutputRedaction.text("smile \\uD83D\\uDE00 ok")).toBe("smile \\uD83D\\uDE00 ok")
})

test("a held block of many short lines is not rescanned at every newline", () => {
  const input = "Bearer%1b]0;t" + "\n".repeat(50_000) + "%07 opaque-secret-123\n"
  const started = performance.now()
  const stream = ToolOutputRedaction.stream()
  const streamed = stream.push(input) + stream.finish()
  expect(performance.now() - started).toBeLessThan(1000)
  expect(streamed).not.toContain("opaque-secret-123")
})

test("a percent-encoded UTF-8 format character cannot split a word or a token", () => {
  for (const [input, hidden] of [
    ["Bea%E2%80%8Brer opaque-secret-123", "opaque-secret-123"],
    ["ghp_AAAAAAAA%E2%81%A0" + "A".repeat(28), "AAAAAAAA"],
    ["ghp_AAAAAAAA%EF%BB%BF" + "A".repeat(28), "AAAAAAAA"],
  ]) {
    const result = ToolOutputRedaction.text(input)
    const stream = ToolOutputRedaction.stream()
    expect(stream.push(input) + stream.finish()).toBe(result)
    expect(result, input).not.toContain(hidden)
  }
  // Other UTF-8 is still shown as written.
  expect(ToolOutputRedaction.text("caf%C3%A9 %F0%9F%98%80")).toBe("caf%C3%A9 %F0%9F%98%80")
})

test("a surrogate pair split between blocks or chunks is read as one character", () => {
  // U+E0020, a format character, as a pair split after the high surrogate.
  const first = "ghp_AAAAAAAA\uDB40"
  const second = "\uDC20" + "A".repeat(28)
  const blocks = [
    { type: "text", text: first },
    { type: "text", text: second },
  ]
  expect(JSON.stringify(ToolOutputRedaction.value({ content: blocks }))).not.toContain("AAAAAAAA")
  expect(ToolOutputRedaction.textBlocksClean(blocks)).toBe(false)
  const stream = ToolOutputRedaction.stream()
  expect(stream.push(first) + stream.push(second) + stream.finish()).not.toContain("AAAAAAAA")
  // A lone high surrogate at the very end is kept, not lost.
  const tail = ToolOutputRedaction.stream()
  expect(tail.push("x\uD83D") + tail.finish()).toBe("x\uD83D")
  expect(ToolOutputRedaction.text("x\uD83D")).toBe("x\uD83D")
  // An ordinary pair split between chunks comes out whole.
  const emoji = ToolOutputRedaction.stream()
  expect(emoji.push("smile \uD83D") + emoji.push("\uDE00 ok\n")).toBe("smile 😀 ok\n")
})

test("tabs a URL parser drops cannot hide a URL's scheme", () => {
  for (const input of [
    "ht\ttps://alice:s3cret@host.test",
    "see h\tt\ttp\ts:/\t/alice:s3cret@host.test now",
    "f\ttp:\t//alice:s3cret@host.test",
    "s\tsh:/\t/alice:s3cret@host.test",
  ]) {
    const parsed = new URL(input.replace(/^see |\snow$/g, ""))
    expect(parsed.password).not.toBe("")
    const result = ToolOutputRedaction.text(input)
    const stream = ToolOutputRedaction.stream()
    expect(stream.push(input) + stream.finish()).toBe(result)
    expect(result, JSON.stringify(input)).not.toContain("s3")
  }
})

test("adversarial runs scan in linear time", () => {
  for (const input of [
    "eyJ-".repeat(100_000),
    "eyJa.".repeat(50_000) + "eyJ",
    "ghp_".repeat(100_000),
    "eyJ".repeat(100_000) + ".a.b",
    "Bearer ".repeat(50_000) + "x",
  ]) {
    const started = performance.now()
    ToolOutputRedaction.text(input)
    expect(performance.now() - started).toBeLessThan(2000)
  }
})

// 1 MiB of each pathological shape: encoded runs only decoded views see, deep escape chains, terminal
// storms and URL-like runs. Each finishes within a fixed budget, and the decoding search stays within
// its bound (past it the output is redacted whole, which viewCount reports as one more than the bound).
test("1 MiB pathological inputs finish within budget and within the view bound", () => {
  const size = 1 << 20
  const fill = (unit: string, prefix = "") => (prefix + unit.repeat(Math.ceil(size / unit.length))).slice(0, size)
  const inputs = [
    fill("eyJ%2d"),
    fill("eyJ\\u002d"),
    fill("eyJ-"),
    fill("eyJa."),
    fill("eyJa%2E"),
    fill("ghp_"),
    fill("ghp%5F"),
    fill("25", "%"),
    fill("%25"),
    fill("%2525"),
    fill("\\"),
    fill("\\u001b[31m"),
    fill("\x1b[31m\x1b]0;x\x07"),
    fill("%1b[2K%1b]0;t%07"),
    fill("\u200b"),
    fill("https:"),
    fill("a", "https://"),
    fill("a@", "https://"),
    fill("Bearer%20a%0d"),
    fill("%5Cu0025%255C\\n%2520eyJ%2d"),
  ]
  for (const input of inputs) {
    const started = performance.now()
    const result = ToolOutputRedaction.text(input)
    expect(performance.now() - started, input.slice(0, 24)).toBeLessThan(2000)
    // The same input streamed is one overlong line, read in windows rather than kept.
    const streamed = performance.now()
    const stream = ToolOutputRedaction.stream()
    stream.push(input)
    stream.finish()
    expect(performance.now() - streamed, "stream " + input.slice(0, 24)).toBeLessThan(2000)
    const views = ToolOutputRedaction.viewCount(input)
    expect(views).toBeLessThanOrEqual(257)
    if (views === 257) expect(result).toBe("[redacted]")
  }
}, 120_000)

test("formatting inside and before Bearer or Basic does not hide the value", () => {
  for (const scheme of ["Bearer", "Basic", "bearer"])
    for (const [before, inside] of [
      ["\x1b[2K\x1b[1G", "\x1b[31m"],
      // No removal before the word: the space is the boundary, as in plain text.
      [" ", "\x1b[31m"],
      ["\x1b[2K", ""],
      ["​", "​"],
      ["\x1b]0;t\x07", "\x1b(B"],
    ]) {
      const word = scheme.slice(0, 3) + inside + scheme.slice(3)
      for (const input of [
        `status${before}${word} opaque-secret-123`,
        JSON.stringify(`status${before}${word} opaque-secret-123`),
      ]) {
        const result = ToolOutputRedaction.text(input)
        const stream = ToolOutputRedaction.stream()
        expect(stream.push(input) + stream.finish()).toBe(result)
        expect(result, JSON.stringify(input)).not.toContain("opaque-secret-123")
      }
    }
})

test("a terminal sequence or format character between words keeps the boundary before a token", () => {
  const token = "ghp_" + "A".repeat(36)
  for (const between of ["\x1b[2K\x1b[1G", "\x1b[31m", "\x1b]0;title\x07", "\x1b(B", "\u200b", "\u2060"])
    for (const input of [
      `status${between}${token}`,
      `status${between}${token}${between}more`,
      JSON.stringify(`status${between}${token}`),
    ]) {
      const result = ToolOutputRedaction.text(input)
      const stream = ToolOutputRedaction.stream()
      expect(stream.push(input) + stream.finish()).toBe(result)
      expect(result, JSON.stringify(input)).not.toContain("AAAA")
      // The removed sequence leaves nothing visible behind.
      expect(result).not.toContain("\x1b")
      expect(result).not.toContain("\ufffe")
    }
  // Still invisible where nothing is redacted: color inside a word does not split it in the output.
  expect(ToolOutputRedaction.text("re\x1b[31md\x1b[0m alert")).toBe("red alert")
})

test("a JWT is still redacted after punctuation, but not inside a longer token run", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
  expect(ToolOutputRedaction.text(`token=${jwt}`)).toBe("token=[redacted]")
  expect(ToolOutputRedaction.text(`"${jwt}"`)).toBe('"[redacted]"')
})

test("escaped terminal formatting before a token does not hide it", () => {
  const token = "ghp_" + "A".repeat(36)
  for (const input of [`\\u001b[31m${token}`, `%1b[31m${token}`, `\\u001b]0;title\\u0007${token}`]) {
    const result = ToolOutputRedaction.text(input)
    expect(result).not.toContain(token)
    expect(result).toContain("[redacted]")
  }
})

test("escaped terminal metadata is removed from the output, not just from the scan", () => {
  const url = "https://alice:synthetic-password-123456@example.test"
  for (const input of [`%1b]0;${encodeURIComponent(url)}%07after`, `\\u001b]0;${url}\\u0007after`]) {
    const result = ToolOutputRedaction.text(input)
    expect(result).not.toContain("synthetic-password")
    expect(decodeURIComponent(result)).not.toContain("synthetic-password")
    expect(result.endsWith("after")).toBe(true)
  }
})

test("percent-encoded UTF-8 is left intact", () => {
  for (const input of ["https://example.test/%E2%82%AC", "caf%C3%A9 %F0%9F%98%80"])
    expect(ToolOutputRedaction.text(input)).toBe(input)
})

test("many text blocks are handled in linear time", () => {
  const token = "ghp_" + "A".repeat(36)
  const blocks = Array.from({ length: 20_000 }, (_, index) => ({
    type: "text",
    text: index === 10_000 ? token : "x".repeat(500),
  }))
  const started = performance.now()
  const result = ToolOutputRedaction.value(blocks)
  expect(performance.now() - started).toBeLessThan(3000)
  expect(JSON.stringify(result)).not.toContain(token)
})

test("JSON short escapes before a token do not hide it, and are kept in the output", () => {
  const token = "ghp_" + "A".repeat(36)
  for (const escape of ["\n", "\t", "\r", "\b", "\f", '"', "\\"]) {
    const input = JSON.stringify({ text: escape + token })
    const result = ToolOutputRedaction.text(input)
    expect(result).not.toContain(token)
    expect(result).toBe(input.replace(token, "[redacted]"))
  }
  // An escaped backslash ends the escape: what follows is literal text at this layer.
  expect(ToolOutputRedaction.text("a\\\\u0041b")).toBe("a\\\\u0041b")
})

test("a control character next to or inside a token neither hides nor splits it", () => {
  const token = "ghp_" + "A".repeat(36)
  for (const input of [`progress\r${token}`, `x\u0000${token}`, `ghp_${"A".repeat(18)}\r${"A".repeat(18)}`]) {
    const result = ToolOutputRedaction.text(input)
    expect(result).not.toContain("A".repeat(18))
    expect(result).toContain("[redacted]")
  }
  expect(ToolOutputRedaction.text("50%\rdone")).toBe("50% done")
})

test("a Proxy error is copied with a plain Error prototype", () => {
  const token = "ghp_" + "A".repeat(36)
  let reads = 0
  const leaky = Object.create(Error.prototype, { toJSON: { value: () => token } })
  const proxy = new Proxy(new Error("x"), { getPrototypeOf: () => (reads++ < 6 ? Error.prototype : leaky) })
  for (let i = 0; i < 20; i++) Object.getPrototypeOf(proxy)
  reads = 0
  const copy = ToolOutputRedaction.error(proxy) as object
  expect(Object.getPrototypeOf(copy)).toBe(Error.prototype)
  expect(JSON.stringify(copy)).not.toContain(token)
})

test("an encoded control inside a token cannot split it", () => {
  for (const control of ["%0d", "%00", "\\u000d", "\\r", "\\n"]) {
    const input = "ghp_" + "A".repeat(8) + control + "A".repeat(28)
    expect(ToolOutputRedaction.text(input)).not.toContain("A".repeat(28))
  }
})

test("an inherited key that is a credential fails the prototype check, marker prefix or not", () => {
  const token = "ghp_" + "A".repeat(36)
  class MarkerLeak extends Error {}
  Object.defineProperty(MarkerLeak.prototype, `~effect/Schema/Class/${token}`, { value: "x" })
  expect(ToolOutputRedaction.safePrototype(new MarkerLeak("x"))).toBe(false)
})

test("only a genuine Effect schema marker is exempt", () => {
  const token = "ghp_" + "A".repeat(36)
  class DataMarker extends Error {}
  Object.defineProperty(DataMarker.prototype, "~effect/Schema/Class/leak", { value: `Bearer ${token}` })
  class GetterMarker extends Error {}
  Object.defineProperty(GetterMarker.prototype, "~effect/Schema/Class/leak", { get: () => `Bearer ${token}` })
  expect(ToolOutputRedaction.safePrototype(new DataMarker("x"))).toBe(false)
  expect(ToolOutputRedaction.safePrototype(new GetterMarker("x"))).toBe(false)
})

test("a decoded line feed or tab inside a token does not split it", () => {
  for (const control of ["%0a", "%09", "\\u000a", "\\u0009"]) {
    const token = `ghp_${"A".repeat(8)}${control}${"A".repeat(28)}`
    expect(ToolOutputRedaction.text(token)).not.toContain("A".repeat(28))
  }
})

test("a JSON-escaped string terminator ends an escaped OSC sequence", () => {
  expect(ToolOutputRedaction.text("\\u001b]0;title\\u001b\\\\ok")).toEndWith("ok")
})

test("URL userinfo ends at the last @ of the authority", () => {
  expect(ToolOutputRedaction.text("https://alice@example.test:secret@host/repo")).toBe("https://[redacted]@host/repo")
  expect(ToolOutputRedaction.text("see https://host/a@b and mail c@d")).toBe("see https://host/a@b and mail c@d")
})

test("an error cause with a credential split across text blocks is redacted", () => {
  const cause = [
    { type: "text", text: "https://alice:" },
    { type: "text", text: "password@example.test" },
  ]
  expect(JSON.stringify(ToolOutputRedaction.error(cause))).not.toContain("password")
})

test("a URL password is found across text blocks before each block is redacted on its own", () => {
  const cause = [
    { type: "text", text: "https://alice@" },
    { type: "text", text: "example.test:secret@host/repo" },
  ]
  expect(JSON.stringify(ToolOutputRedaction.error(cause))).not.toContain("secret")
})

test("URL credentials are found by parsing; literal whitespace and quotes end a URL", () => {
  for (const input of [
    "https://alice:my%20secret@host/repo",
    "https://alice:se%09cr%0aet@host/repo",
    "https://alice:secret@host\\repo",
    "https://alice@example.test:se@cret@host/repo",
  ]) {
    const result = ToolOutputRedaction.text(input)
    expect(result).toContain("[redacted]@host")
    expect(result).not.toMatch(/alice|cret/)
  }
  for (const input of [
    "see https://host and mail bob@x",
    "https://example.test\tbob@example.test",
    "https://example.test\nbob@example.test",
    '"https://example.test" bob@example.test',
    "https://host/a@b",
    "https://host:8443/x",
    "ssh://host/repo",
  ])
    expect(ToolOutputRedaction.text(input)).toBe(input)
})

test("a URL credential split across stream chunks at any point is redacted", () => {
  const input = "push https://alice:secret@host/repo done\n"
  for (let at = 0; at <= input.length; at++) {
    const stream = ToolOutputRedaction.stream()
    const result = stream.push(input.slice(0, at)) + stream.push(input.slice(at)) + stream.finish()
    expect(result).toBe("push https://[redacted]@host/repo done\n")
  }
})

test("text and stream agree, newlines included", () => {
  for (const input of [
    "https://alice:secret\n@host/repo\n",
    "https://alice:secret@host/repo\nnext line\n",
    "https://example.test\nbob@example.test\n",
    "token ghp_" + "A".repeat(36) + "\nhttps://u:p@h/x",
    "a\tb\nhttps://alice:my%20secret@host\n",
  ]) {
    const stream = ToolOutputRedaction.stream()
    expect(stream.push(input) + stream.finish()).toBe(ToolOutputRedaction.text(input))
  }
})

// Differential: new URL() is the oracle for what a URL client reads as credentials.
test("URL credentials match WHATWG parsing for special schemes", () => {
  const slashes = [""]
  for (let length = 1; length <= 4; length++)
    for (let mask = 0; mask < 1 << length; mask++)
      slashes.push(Array.from({ length }, (_, bit) => ((mask >> bit) & 1 ? "\\" : "/")).join(""))
  const userinfos = ["", "alice@", "alice:s3cret@", "al%69ce:s%33cret@", "o'neil:pa'ss@", "a@b.test:pw@"]
  const hosts = ["host.test", "host.test:8443", "host.test/p/a@b", "host.test:8443/x?q=1#f"]
  const checked = { redacted: 0, kept: 0 }
  for (const scheme of ["https", "HTTPS", "http", "Ws", "wss", "ftp"])
    for (const slash of slashes)
      for (const userinfo of userinfos)
        for (const host of hosts)
          for (const end of [" ", '"', "\t", "\n"]) {
            const candidate = `${scheme}:${slash}${userinfo}${host}`
            const input = `see ${candidate}${end}tail`
            const result = ToolOutputRedaction.text(input)
            const stream = ToolOutputRedaction.stream()
            expect(stream.push(input) + stream.finish()).toBe(result)
            let parsed: URL | undefined
            try {
              parsed = new URL(candidate)
            } catch {}
            if (parsed && (parsed.username || parsed.password)) {
              expect(result).not.toContain(userinfo.slice(0, -1))
              expect(result).toContain(`[redacted]@${host}`)
              checked.redacted++
            } else {
              expect(result).toBe(input)
              checked.kept++
            }
          }
  expect(checked.redacted).toBeGreaterThan(1000)
  expect(checked.kept).toBeGreaterThan(1000)
})

// Every printable ASCII character inside userinfo, against new URL(). Whitespace and '"' end a URL in
// text (TOOL-OUTPUT-REDACTION.md); everything else a URL client accepts in userinfo must not end it.
test("each character a URL client accepts in userinfo stays inside the credential", () => {
  let checked = 0
  for (let code = 0x21; code < 0x7f; code++) {
    const char = String.fromCharCode(code)
    if (char === '"') continue
    for (const url of [
      `https://alice:pa${char}ss9q@host.test/p`,
      `https://al${char}ic9q:pw@host.test/p`,
      `ftp:\\\\al${char}ic9q@host.test`,
    ]) {
      let parsed: URL | undefined
      try {
        parsed = new URL(url)
      } catch {}
      if (!parsed || (!parsed.username && !parsed.password)) continue
      for (const input of [`see ${url} tail`, `<${url}>`, "`" + url + "`"]) {
        const result = ToolOutputRedaction.text(input)
        const stream = ToolOutputRedaction.stream()
        expect(stream.push(input) + stream.finish()).toBe(result)
        expect(result, input).not.toContain("9q")
        checked++
      }
    }
  }
  expect(checked).toBeGreaterThan(200)
})

test("repeated URL schemes are scanned in linear time", () => {
  for (const input of [
    "https:".repeat(30_000),
    "https:".repeat(30_000) + "alice:secret@host",
    "ftp:\\".repeat(30_000),
  ]) {
    const started = performance.now()
    const result = ToolOutputRedaction.text(input)
    expect(performance.now() - started).toBeLessThan(1000)
    expect(result).not.toContain("secret")
  }
})

test("a scheme right after another scheme still has its credentials found", () => {
  for (const input of [
    "https:https://alice:s3cret@host.test",
    "ftp:\\https://alice:s3cret@host.test",
    "https:ssh://alice:s3cret@host.test",
  ])
    expect(ToolOutputRedaction.text(input)).not.toContain("s3cret")
})

// Seeded fuzz: oracle URLs from new URL(), wrapped in text built from scheme fragments and delimiters.
test("an oracle URL credential survives no surrounding text", () => {
  let seed = 0x5eed
  const random = () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const pick = <T>(items: readonly T[]) => items[Math.floor(random() * items.length)]
  const alphabet = ["https:", "ftp:\\", "ssh://", "@", ":", "/", "\\", "%", " ", "\n", "a", "Z", "x"]
  const noise = () => Array.from({ length: Math.floor(random() * 6) }, () => pick(alphabet)).join("")
  const urls: Array<{ url: string; secrets: string[] }> = []
  for (const scheme of ["https", "HTTP", "wss", "ftp"])
    for (const slash of ["", "/", "//", "\\\\", "/\\/"])
      for (const [userinfo, secrets] of [
        ["alice:s3cret@", ["s3cret"]],
        ["t0kenuser@", ["t0kenuser"]],
        ["al%69ce:s%33cret@", ["s%33cret"]],
        ["o'neil:pa'ss@", ["pa'ss"]],
        ["a@b.test:pw9x@", ["pw9x"]],
      ] as const)
        for (const host of ["host.test", "host.test:8443/p", "host.test?q#f"]) {
          const url = `${scheme}:${slash}${userinfo}${host}`
          const parsed = new URL(url)
          if (parsed.username || parsed.password) urls.push({ url, secrets: [...secrets] })
        }
  let checked = 0
  for (let round = 0; round < 12; round++)
    for (const { url, secrets } of urls) {
      const input = noise() + url + pick([" ", "\n", '"', "\t", ""]) + noise()
      const result = ToolOutputRedaction.text(input)
      const stream = ToolOutputRedaction.stream()
      expect(stream.push(input) + stream.finish()).toBe(result)
      for (const secret of secrets) expect(result, input).not.toContain(secret)
      checked++
    }
  expect(checked).toBeGreaterThan(3000)
  const large = Array.from({ length: 50_000 }, () => pick(alphabet)).join("")
  expect(large.length).toBeGreaterThan(100_000)
  const started = performance.now()
  ToolOutputRedaction.text(large + "x".repeat(200_000 - large.length))
  expect(performance.now() - started).toBeLessThan(1000)
})

test("escape sequences with intermediate bytes are consumed whole", () => {
  const token = "ghp_" + "A".repeat(36)
  for (const escape of ["\x1b(B", "\x1b)0", "\x1b#8", "\x1b%G", "\x1b$(B"]) {
    for (const input of [escape + token, JSON.stringify(escape + token)]) {
      const result = ToolOutputRedaction.text(input)
      expect(result).not.toContain(token)
      expect(result).not.toContain("B[redacted]")
    }
    for (let at = 0; at <= escape.length + 4; at++) {
      const stream = ToolOutputRedaction.stream()
      const input = escape + token + "\n"
      expect(stream.push(input.slice(0, at)) + stream.push(input.slice(at)) + stream.finish()).toBe("[redacted]\n")
    }
  }
  expect(ToolOutputRedaction.text("\x1b(Bplain\x1b[m text")).toBe("plain text")
  expect(ToolOutputRedaction.text("\x1b(\nnext")).toBe("\nnext")
})

test("a large array in an error cause is copied without hitting argument limits", () => {
  const cause = { header: "Bearer test-credential", items: Array(1_000_000).fill(0) }
  const copy = ToolOutputRedaction.error(cause) as { header: string; items: number[] }
  expect(copy.header).not.toContain("test-credential")
  expect(copy.items.length).toBe(1_000_000)
})

test("a JSON-escaped URL whose password holds an encoded delimiter is redacted", () => {
  for (const input of ["https\\u003a//alice:pa%2Fss@example.test", "https:\\/\\/alice:pa%3Fss@example.test/x"]) {
    const result = ToolOutputRedaction.text(input)
    expect(result).not.toContain("alice")
    expect(result).not.toContain("ss@example")
  }
})

// Seeded fuzz: an oracle URL whose password holds reserved characters, put through random encodings.
test("an encoded URL password survives no combination of escapes", () => {
  let seed = 0xc0de
  const random = () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const pick = <T>(items: readonly T[]) => items[Math.floor(random() * items.length)]
  const chunks = ["Qz7", "Kp9", "Wm3", "Xv5", "Jh2", "Rt8", "Ln4", "Bc6"]
  const password = chunks.map((chunk, index) => chunk + (index < 7 ? "/?#@:% "[index] : "")).join("")
  const hex = (char: string) => char.charCodeAt(0).toString(16).padStart(2, "0")
  const percent = (text: string) =>
    [...text]
      .map((char) => (/[A-Za-z0-9]/.test(char) && random() > 0.3 ? char : `%${hex(char).toUpperCase()}`))
      .join("")
  const terminals = ["\x1b[31m", "\x1b(B", "\x1b]0;t\x07", "\x1b[0m"]
  // Each transform is a valid JSON string encoding layer: every backslash and control is escaped.
  const transforms: Array<(text: string) => string> = [
    (text) =>
      [...text]
        .map((char) =>
          char === "\\" ? pick(["\\\\", "\\u005c"]) : char < " " || random() < 0.3 ? `\\u00${hex(char)}` : char,
        )
        .join(""),
    (text) =>
      text
        .replaceAll("\\", "\\\\")
        .replaceAll("/", "\\/")
        .replace(/[\x00-\x1f]/g, (char) => `\\u00${hex(char)}`),
    (text) => JSON.stringify(text),
    // A percent-encoding layer over any of the above (a JSON string carried in a query parameter).
    (text) => encodeURIComponent(text),
  ]
  // Undo the layers in any order, the way a JSON decoder and a percent decoder would, so a password
  // left in any spelling is found.
  const decode = (text: string) => {
    let result = text
    for (let round = 0; round < 8; round++)
      result = result
        .replace(/\\(?:u([0-9a-fA-F]{4})|(.))/gs, (_, code: string | undefined, char: string) =>
          code
            ? String.fromCharCode(parseInt(code, 16))
            : (({ n: "\n", t: "\t", r: "\r" } as Record<string, string>)[char] ?? char),
        )
        .replace(/%([0-9a-fA-F]{2})/g, (_, code) => String.fromCharCode(parseInt(code, 16)))
    return result
  }
  const leaks: string[] = []
  for (let round = 0; round < 3000; round++) {
    const url = `${pick(["https", "HTTP", "ftp", "wss"])}://${percent("alice")}:${percent(password)}@host.test/p`
    const parsed = new URL(url)
    expect(decodeURIComponent(parsed.password)).toBe(password)
    const cut = Math.floor(random() * (url.length + 1))
    let input = random() < 0.5 ? url : url.slice(0, cut) + pick(terminals) + url.slice(cut)
    // One or two layers: a secret encoded twice is the deepest the redactor covers.
    for (let step = Math.floor(random() * 2); step >= 0; step--) input = pick(transforms)(input)
    const result = ToolOutputRedaction.text(input)
    const stream = ToolOutputRedaction.stream()
    // Past the decoding bound text() redacts the output whole and a stream withholds it.
    const streamed = stream.push(input) + stream.finish()
    if (result === "[redacted]") expect([result, ToolOutputRedaction.withheldMarker]).toContain(streamed)
    else expect(streamed).toBe(result)
    const seen = decode(result)
    if (chunks.some((chunk) => seen.includes(chunk))) leaks.push(JSON.stringify(input))
  }
  expect(leaks.slice(0, 5)).toEqual([])
})

test("a percent-encoded JSON string is JSON-decoded after the percent decode", () => {
  // Percent-decoded, this is "https\u003a//alice:s3cret@host": the colon is still JSON-escaped.
  const input = "%22https%5Cu003a%2F%2Falice%3As3cret%40host%22"
  const result = ToolOutputRedaction.text(input)
  expect(result).not.toContain("s3cret")
  expect(result).not.toContain("alice")
  expect(result).toContain("host")
  // The reverse order: a JSON string holding a percent-encoded URL.
  const reverse = ToolOutputRedaction.text(JSON.stringify(encodeURIComponent("https://alice:s3cret@host/p")))
  expect(reverse).not.toContain("s3cret")
})

test("a control removed in one layer cannot split a token another layer reveals", () => {
  // Percent-decoding once drops the encoded CR from the compact view, where "gh%70_" is still
  // encoded; decoding that compact view again reveals "ghp_" with nothing between its halves.
  const token = "ghp_" + "A".repeat(36)
  const result = ToolOutputRedaction.text("gh%2570_AAAAAAAA%0d" + "A".repeat(28))
  expect(result).toBe("[redacted]")
  expect(ToolOutputRedaction.text(token)).toBe("[redacted]")
})

// Seeded fuzz over the decoding closure: a credential inside random sequences of encoders, any order,
// up to two deep (the deepest covered). Each result must hide the credential under every decoding.
test("a credential survives no sequence of encodings: hidden, or the output redacted whole", () => {
  let seed = 0x5eed
  const random = () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const pick = <T>(items: readonly T[]) => items[Math.floor(random() * items.length)]
  const hex = (char: string) => char.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()
  const chunks = ["Qz7", "Kp9", "Wm3", "Xv5", "Jh2", "Rt8", "Ln4", "Bc6"]
  const password = chunks.map((chunk, index) => chunk + (index < 7 ? "/?#@:% "[index] : "")).join("")
  const token = "ghp_" + chunks.join("").repeat(2).slice(0, 36)
  // Each encoder is a complete layer a real producer could add.
  const encoders: Array<(text: string) => string> = [
    (text) => JSON.stringify(text).slice(1, -1),
    (text) => JSON.stringify(text),
    (text) =>
      text
        .replaceAll("\\", "\\\\")
        .replaceAll("/", "\\/")
        .replace(/[\x00-\x1f]/g, (c) => `\\u00${hex(c)}`),
    (text) =>
      [...text].map((c) => (c === "\\" ? "\\u005C" : c < " " || random() < 0.3 ? `\\u00${hex(c)}` : c)).join(""),
    (text) => encodeURIComponent(text),
    (text) => [...text].map((c) => (/[A-Za-z0-9]/.test(c) && random() < 0.5 ? c : `%${hex(c)}`)).join(""),
  ]
  // Controls inside the credential. Whitespace counts only once a layer encodes it: literal whitespace
  // inside a credential is out of scope (TOOL-OUTPUT-REDACTION.md); terminal sequences count either way.
  const breaks = ["\r", "\n", "\t", "\x1b[31m", "\x1b]0;t\x07"]
  // Undo layers in any order, the way a JSON decoder and a percent decoder would.
  const exposed = (text: string) => {
    let result = text
    for (let round = 0; round < 24; round++)
      result = result
        .replace(/\\(?:u([0-9a-fA-F]{4})|(.))/gs, (_, code: string | undefined, char: string) =>
          code
            ? String.fromCharCode(parseInt(code, 16))
            : (({ n: "\n", t: "\t", r: "\r" } as Record<string, string>)[char] ?? char),
        )
        .replace(/%([0-9a-fA-F]{2})/g, (_, code) => String.fromCharCode(parseInt(code, 16)))
    return result.replace(/[\s\x00-\x1f]|\x1b\[[0-9;]*m|\x1b\][^\x07]*\x07/g, "")
  }
  const leaks: string[] = []
  const whole = new Map<number, number>()
  for (let round = 0; round < 2000; round++) {
    let secret = random() < 0.5 ? `https://alice:${encodeURIComponent(password)}@host.test/p` : token
    const depth = Math.floor(random() * 3)
    if (random() < 0.4) {
      const cut = 8 + Math.floor(random() * (secret.length - 8))
      secret = secret.slice(0, cut) + pick(depth > 0 ? breaks : breaks.slice(3)) + secret.slice(cut)
    }
    let input = `log ${secret} end`
    for (let step = 0; step < depth; step++) input = pick(encoders)(input)
    const result = ToolOutputRedaction.text(input)
    if (result === "[redacted]") whole.set(depth, (whole.get(depth) ?? 0) + 1)
    const seen = exposed(result)
    if (seen.includes(token) || chunks.some((chunk) => seen.includes(chunk))) leaks.push(JSON.stringify(input))
  }
  expect(leaks.slice(0, 3)).toEqual([])
  // One layer is always inspected. Two layers over a URL whose password is itself percent-encoded can
  // still decode a third time, and such an output is withheld whole.
  expect([0, 1].map((depth) => whole.get(depth) ?? 0)).toEqual([0, 0])
}, 60_000)

test("a secret encoded twice is found; an output with a third layer is withheld whole", () => {
  for (const encode of [encodeURIComponent, (text: string) => JSON.stringify(text)]) {
    const twice = encode(encode("log https://alice:s3cret@host.test/p end"))
    const result = ToolOutputRedaction.text(twice)
    expect(result).not.toContain("s3cret")
    expect(result).not.toBe("[redacted]")
  }
  // Percent-encoded three times, the URL is not readable within two layers. Past the layer bound the
  // output is not inspected, so it is not passed through either.
  const thrice = encodeURIComponent(encodeURIComponent(encodeURIComponent("log https://alice:s3cret@host.test/p end")))
  expect(ToolOutputRedaction.text(thrice)).toBe("[redacted]")
  const stream = ToolOutputRedaction.stream()
  expect(stream.push(thrice + "\nafter\n") + stream.finish()).not.toContain("s3cret")
  // Text that a third decode leaves unchanged is not withheld.
  const plain = JSON.stringify(JSON.stringify("100% done, see https://host.test/a b"))
  expect(ToolOutputRedaction.text(plain)).toBe(plain)
})

test("terminal metadata hidden under nested escapes is removed, credential and all", () => {
  for (const input of [
    "\\\\u001b]0;https\\\\u003a//u:secret@h\\\\u0007",
    "a \\\\u001b]0;https://u:secret@h\\\\u0007 b",
    JSON.stringify("\\u001b]0;https://u:secret@h\\u0007 tail"),
  ]) {
    const result = ToolOutputRedaction.text(input)
    expect(result).not.toContain("secret")
    const stream = ToolOutputRedaction.stream()
    expect(stream.push(input) + stream.finish()).toBe(result)
  }
})

// One reading of an output, whole or streamed in any two pieces, must hide `hidden`.
function hidesEverywhere(input: string, hidden: string) {
  const whole = ToolOutputRedaction.text(input)
  expect(whole, JSON.stringify(input)).not.toContain(hidden)
  for (let split = 0; split <= input.length; split += Math.max(1, Math.floor(input.length / 40))) {
    const stream = ToolOutputRedaction.stream()
    const streamed = stream.push(input.slice(0, split)) + stream.push(input.slice(split)) + stream.finish()
    expect(streamed, `${JSON.stringify(input)} split at ${split}`).not.toContain(hidden)
  }
  return whole
}

const keyBody = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7syntheticKeyBody"

test("a private key block is redacted whole, in every PEM and OpenSSH variant", () => {
  for (const label of [
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
  ]) {
    const block = `-----BEGIN ${label}-----\n${keyBody}\n${keyBody.slice(0, 20)}==\n-----END ${label}-----`
    const result = hidesEverywhere(`before\n${block}\nafter\n`, "syntheticKeyBody")
    expect(result).toStartWith("before\n")
    expect(result).toEndWith("after\n")
    // An encoded block (inside a JSON string) runs to the end of the output.
    for (const value of [block, `${block}\n`, `${block}\r\n`])
      hidesEverywhere(JSON.stringify({ key: value, result: keyBody }), "syntheticKeyBody")
    hidesEverywhere(JSON.stringify([{ key: block }, { key: block }, keyBody]), "syntheticKeyBody")
  }
})

test("an unterminated private key block is redacted to the end", () => {
  const result = hidesEverywhere(`before\n-----BEGIN PRIVATE KEY-----\n${keyBody}\n${keyBody}\n`, "syntheticKeyBody")
  expect(result).toStartWith("before\n")
})

test("public keys and certificates are not private keys", () => {
  const input = `-----BEGIN PUBLIC KEY-----\n${keyBody}\n-----END PUBLIC KEY-----\n-----BEGIN CERTIFICATE-----\n${keyBody}\n-----END CERTIFICATE-----\n`
  expect(ToolOutputRedaction.text(input)).toBe(input)
})

test("tabs inside Bearer or Basic do not hide the value", () => {
  for (const input of [
    "Authorization: Bea\tre\u0000r opaque-secret-123",
    "Authorization: B\ta\ts\ti\tc opaque-secret-123",
    "auth=bearer\t opaque-secret-123",
  ])
    hidesEverywhere(input, "opaque-secret-123")
  // A scheme and its value on separate lines stay as they are (see TOOL-OUTPUT-REDACTION.md).
  expect(ToolOutputRedaction.text("Basic\nopaque-secret-123")).toBe("Basic\nopaque-secret-123")
  expect(ToolOutputRedaction.text("Be\tst\tvalue")).toBe("Be\tst\tvalue")
})

test("a scheme split by any number of tabs is read whole before a decoded newline", () => {
  for (const tabs of [1, 63, 64, 200, 5000]) {
    const input = "Bea" + "\t".repeat(tabs) + "rer%0aopaque-secret-123"
    const started = performance.now()
    expect(ToolOutputRedaction.text(input)).not.toContain("opaque-secret-123")
    expect(performance.now() - started).toBeLessThan(500)
  }
})

test("tabs or controls inside URL userinfo do not hide it", () => {
  for (const input of [
    "https://alice:s3cret-value\t@host.test/repo",
    "https://al\tice:s3cret-value@host.test",
    "https://alice:s3cr\u0000et-value@host.test",
    "clone ssh://git:s3cret-value\t@host.test/repo now",
  ]) {
    const parsed = new URL(input.replace(/^clone |\snow$/g, "").replaceAll("\u0000", ""))
    expect(parsed.password).not.toBe("")
    hidesEverywhere(input, "s3cr")
  }
})

// Display mode: stricter rules for untrusted remote text shown to a person or a model as a label
// (the Requirements sidebar and tool). Moved from core/test/requirements/agent.test.ts.
describe("display mode", () => {
  const display = (input: string) => ToolOutputRedaction.text(input, { display: true })

  test("removes URL credentials, auth headers, labelled values, queries and private keys", () => {
    for (const value of [
      "https://user:synthetic-secret@example.test/repo?token=synthetic-secret",
      "Authorization: Bearer synthetic-secret",
      "password=synthetic-secret",
      "https://example.test/?access_token=synthetic-secret&state=synthetic-secret",
      "https://example.test/?unknown=synthetic-secret#synthetic-secret",
      '"password": "synthetic-secret"',
      "-----BEGIN PRIVATE KEY----- synthetic-secret -----END PRIVATE KEY-----",
    ])
      expect({ value, out: display(value) }).not.toEqual({ value, out: expect.stringContaining("synthetic-secret") })
    expect(display(`https://platform.testifysec.com/archivista/download/${"a".repeat(64)}`)).toContain("a".repeat(64))
  })

  test("control and invisible characters cannot split a credential away from its label", () => {
    for (const value of [
      "Authorization: Basic\tsynthetic-secret",
      "Authorization: Basic\nsynthetic-secret",
      "Authorization: Bearer\r\nsynthetic-secret",
      "Authorization: Bearer synthetic-secret",
      "Bea\tre\u0000r synthetic-secret",
      "Bea​rer synthetic-secret",
      "pass\u0007word=synthetic-secret",
      "password\t=\tsynthetic-secret",
      "https://user:synthetic-secret\t@example.test/repo",
      // A split label beside a whole one.
      "Bea\u0000rer synthetic-secret Bearer\u0000x",
    ])
      expect({ value, out: display(value) }).not.toEqual({ value, out: expect.stringContaining("synthetic-secret") })
  })

  test("ordinary text is unchanged, and plain mode keeps code identifiers and queries", () => {
    expect(display("step\tsigned\nmode block")).toBe("step\tsigned\nmode block")
    const source = 'const token = value; password = input.password; https://example.test/a%20b?x=1\n\treturn "ok"'
    expect(ToolOutputRedaction.text(source)).toBe(source)
    expect(ToolOutputRedaction.text("Basic\nopaque-secret-123")).toBe("Basic\nopaque-secret-123")
  })
})

test("many tab-separated URL candidates are read in linear time", () => {
  for (const input of [
    "http:a\t".repeat(20_000) + "u:p4ss-word@host",
    "https://a\t".repeat(10_000) + "u:p4ss-word@host",
  ]) {
    const started = performance.now()
    const result = ToolOutputRedaction.text(input)
    expect(performance.now() - started).toBeLessThan(1000)
    expect(result).not.toContain("p4ss-word")
  }
})

test("tabbed userinfo is redacted even when the URL does not parse", () => {
  for (const input of [
    "https://alice:s3cret-value\t@host.test:bad/",
    "https://alice:s3cret-value\t@host.test:99999/repo",
    "https://alice:s3cr\tet-value@[bad/",
  ])
    hidesEverywhere(input, "s3cr")
  // Prose with a tab and no colon in what would be the userinfo is still left alone.
  expect(ToolOutputRedaction.text("https://example.test\tbob@example.test")).toBe(
    "https://example.test\tbob@example.test",
  )
})

test("only a whole END line with the BEGIN label closes a private key block", () => {
  for (const block of [
    // An END marker inside a header line does not close the block.
    `-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nComment: -----END RSA PRIVATE KEY-----\n\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    // A literal backslash-n outside a JSON string is not a line break.
    `-----BEGIN RSA PRIVATE KEY-----\nComment: \\n-----END RSA PRIVATE KEY-----\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    `-----BEGIN RSA PRIVATE KEY-----\n${keyBody}\\n-----END RSA PRIVATE KEY-----\\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    // A decoded escape beside an END is not a line break: only a decoded newline is.
    `%2D----BEGIN RSA PRIVATE KEY-----\nComment:%20%2D----END RSA PRIVATE KEY-----\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    `%2D----BEGIN RSA PRIVATE KEY-----\nComment:%20%2D----END RSA PRIVATE KEY-----%20\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    `\\u002d----BEGIN RSA PRIVATE KEY-----\nComment:\\t\\u002d----END RSA PRIVATE KEY-----\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    // An escaped BEGIN on a real line is not closed by an END after an escaped newline.
    `\\u002d----BEGIN RSA PRIVATE KEY-----\nComment: \\n-----END RSA PRIVATE KEY-----\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    `%2D----BEGIN RSA PRIVATE KEY-----\nComment: %0A-----END RSA PRIVATE KEY-----%0A${keyBody}\n-----END RSA PRIVATE KEY-----`,
    // A quote right after an END marker does not end its line.
    `-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----"not a whole END line\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    `-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----'x\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    `-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\`x\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    // Any escape right after BEGIN, even one that is not a newline, makes the block an encoded one.
    `-----BEGIN RSA PRIVATE KEY-----\\x\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    `-----BEGIN RSA PRIVATE KEY----- \\q${keyBody}\n-----END RSA PRIVATE KEY-----`,
    // A different label does not close it either; with no matching END it runs to the end.
    `-----BEGIN RSA PRIVATE KEY-----\n${keyBody}\n-----END EC PRIVATE KEY-----\n${keyBody}\n`,
    `-----BEGIN OPENSSH PRIVATE KEY-----\n${keyBody} -----END OPENSSH PRIVATE KEY-----\n${keyBody}\n`,
  ]) {
    hidesEverywhere(`before\n${block}\nafter\n`, "syntheticKeyBody")
    hidesEverywhere(JSON.stringify({ key: block, result: "keep" }), "syntheticKeyBody")
  }
  const closed = ToolOutputRedaction.text(
    `-----BEGIN EC PRIVATE KEY-----\r\n${keyBody}\r\n-----END EC PRIVATE KEY-----\r\nafter\n`,
  )
  expect(closed).not.toContain("syntheticKeyBody")
  expect(closed).toContain("after\n")
})

test("a private key block closes only in the strict raw PEM shape", () => {
  // Well-formed raw PEM, with encryption headers, a blank line, CRLF and indentation, keeps what follows.
  for (const [input, kept] of [
    [
      `-----BEGIN PRIVATE KEY-----\n${keyBody}\n${keyBody.slice(0, 20)}==\n-----END PRIVATE KEY-----\nafter\n`,
      "after\n",
    ],
    [
      `x\r\n-----BEGIN RSA PRIVATE KEY-----\r\nProc-Type: 4,ENCRYPTED\r\nDEK-Info: AES-128-CBC,0123456789ABCDEF\r\n\r\n${keyBody}\r\n-----END RSA PRIVATE KEY-----\r\nafter\n`,
      "after\n",
    ],
    [
      `key: |\n  -----BEGIN EC PRIVATE KEY-----\n  ${keyBody}\n  -----END EC PRIVATE KEY-----\nafter: 1\n`,
      "after: 1\n",
    ],
  ]) {
    expect(hidesEverywhere(input, "syntheticKeyBody")).toEndWith(kept)
  }
  // One byte outside base64 in the body takes the block to the end of the output.
  for (const bad of ["!", "-", "\\", "%", "é", "a b", "a\tb"]) {
    const input = `-----BEGIN PRIVATE KEY-----\n${keyBody}\n${bad}${keyBody}\n-----END PRIVATE KEY-----\nafter ${keyBody}\n`
    const result = hidesEverywhere(input, "syntheticKeyBody")
    expect(result).not.toContain("after")
  }
  // So does anything after BEGIN on its line, or a header that is not printable ASCII.
  for (const input of [
    `-----BEGIN PRIVATE KEY----- ${keyBody}\n-----END PRIVATE KEY-----\nafter ${keyBody}\n`,
    `-----BEGIN PRIVATE KEY-----\nComment: café\n${keyBody}\n-----END PRIVATE KEY-----\nafter ${keyBody}\n`,
  ])
    expect(hidesEverywhere(input, "syntheticKeyBody")).not.toContain("after")
})

test("a long blank line in a private key block is checked in linear time", () => {
  for (const line of [" ".repeat(50_000) + "!", "Name:" + " ".repeat(50_000) + "\u00e9", "\t".repeat(50_000) + "\r!"]) {
    const started = performance.now()
    const result = ToolOutputRedaction.text(`-----BEGIN PRIVATE KEY-----\n${line}\n${keyBody}\n`)
    expect(performance.now() - started).toBeLessThan(500)
    expect(result).not.toContain("syntheticKeyBody")
  }
})

test("an indented private key block closes on its indented END line", () => {
  const indented = `key: |\n  -----BEGIN PRIVATE KEY-----\n  ${keyBody}\n  -----END PRIVATE KEY-----\nafter: 1\n`
  hidesEverywhere(indented, "syntheticKeyBody")
  expect(ToolOutputRedaction.text(indented)).toBe("key: |\n  [redacted]\nafter: 1\n")
})

test("an encoded private key block is redacted to the end of the output", () => {
  const blocks = [
    `-----BEGIN RSA PRIVATE KEY-----\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    `-----BEGIN RSA PRIVATE KEY-----\n${keyBody}\n-----END RSA PRIVATE KEY-----\n`,
    // An encoded header hiding an END line.
    `-----BEGIN RSA PRIVATE KEY-----\nComment: x\n-----END RSA PRIVATE KEY-----\n${keyBody}\n-----END RSA PRIVATE KEY-----`,
    // Another label, and no END at all.
    `-----BEGIN RSA PRIVATE KEY-----\n${keyBody}\n-----END EC PRIVATE KEY-----\n${keyBody}`,
    `-----BEGIN PRIVATE KEY-----\n${keyBody}\n${keyBody}`,
  ]
  for (const block of blocks) {
    const json = JSON.stringify({ key: block, result: keyBody })
    expect(hidesEverywhere(json, "syntheticKeyBody")).toStartWith('{"key":"')
    // The BEGIN marker itself escaped, so only a decoded view reads it.
    for (const dash of ["\\u002d", "\\u002D", "%2D"])
      hidesEverywhere(json.replace("-----BEGIN", `${dash}----BEGIN`), "syntheticKeyBody")
    hidesEverywhere(JSON.stringify({ outer: JSON.stringify({ key: block }), result: keyBody }), "syntheticKeyBody")
    const encoded = encodeURIComponent(block)
    expect(hidesEverywhere(`key=${encoded} after ${keyBody}\n`, "syntheticKeyBody")).toStartWith("key=")
    hidesEverywhere(`key=${encoded.replace("-", "%2D")}&next=${keyBody}\n`, "syntheticKeyBody")
  }
  // Every boundary Codex found that once ended an encoded block early: a quote, a fake END line, an
  // escaped quote, a raw blank, JSON-looking continuations.
  for (const text of [
    `-----BEGIN RSA PRIVATE KEY-----\\nComment: "note"\\n${keyBody}\\n-----END RSA PRIVATE KEY-----`,
    `"-----BEGIN RSA PRIVATE KEY-----\\nComment: "\\n${keyBody}\\n-----END RSA PRIVATE KEY-----"`,
    `-----BEGIN RSA PRIVATE KEY-----\\nComment: -----END RSA PRIVATE KEY-----"\\n${keyBody}\\n-----END RSA PRIVATE KEY-----`,
    `{"key":"-----BEGIN RSA PRIVATE KEY-----\\nComment: -----END RSA PRIVATE KEY-----"\\n${keyBody}\\n-----END RSA PRIVATE KEY-----"}`,
    `{"key":"-----BEGIN RSA PRIVATE KEY-----\\nComment:\\n-----END RSA PRIVATE KEY-----"\\n${keyBody}\\n-----END RSA PRIVATE KEY-----"}`,
    `{"key":"-----BEGIN RSA PRIVATE KEY-----\\nComment:\\n-----END RSA PRIVATE KEY-----",\\n${keyBody}\\n-----END RSA PRIVATE KEY-----"}`,
    `key: -----BEGIN RSA PRIVATE KEY-----\\nComment:\\n-----END RSA PRIVATE KEY-----"} ${keyBody}`,
    `{"key":"-----BEGIN PRIVATE KEY-----%0A-----END%20PRIVATE%20KEY-----\\"%0A${keyBody}%0A-----END%20PRIVATE%20KEY-----"}`,
    `%2D----BEGIN%20RSA%20PRIVATE%20KEY-----%0AComment:%20x y%0A${keyBody}%0A-----END%20RSA%20PRIVATE%20KEY-----`,
    // Any amount of blank space between BEGIN and its escape.
    `-----BEGIN PRIVATE KEY-----${"\t".repeat(40)}%250AComment: x\n-----END PRIVATE KEY-----\n%250A${keyBody}`,
    `-----BEGIN PRIVATE KEY-----${" \u00a0\u3000\u0000".repeat(20)}\\nComment: x\n-----END PRIVATE KEY-----\n${keyBody}`,
    // Escapes nested a level deeper, and a raw END line among them.
    `-----BEGIN PRIVATE KEY-----%250AComment: x\n-----END PRIVATE KEY-----\n%250A${keyBody}%250A-----END PRIVATE KEY-----`,
    `-----BEGIN PRIVATE KEY-----\\\\nComment: x\n-----END PRIVATE KEY-----\n\\\\n${keyBody}`,
    `-----BEGIN PRIVATE KEY-----%5Cn\n-----END PRIVATE KEY-----\n%5Cn${keyBody}`,
  ])
    expect(hidesEverywhere(`before ${text}\nafter ${keyBody}\n`, "syntheticKeyBody")).toStartWith("before ")
})

test("a well-formed encoded private key also takes every field after it (the cost of the rule)", () => {
  const key = `-----BEGIN EC PRIVATE KEY-----\n${keyBody}\n-----END EC PRIVATE KEY-----\n`
  for (const input of [
    JSON.stringify({ key, result: "ordinary", next: 1 }) + "\nnext line\n",
    `key=${encodeURIComponent(key)}&result=ordinary\nnext line\n`,
  ]) {
    const whole = hidesEverywhere(input, "syntheticKeyBody")
    expect(whole).not.toContain("ordinary")
    expect(whole).not.toContain("next line")
  }
})

test("closed() tells whether an output leaves a terminal sequence open", () => {
  expect(ToolOutputRedaction.closed("plain\n")).toBe(true)
  expect(ToolOutputRedaction.closed("title \x1b]0;x\x07 done")).toBe(true)
  expect(ToolOutputRedaction.closed("title \x1b]0;x")).toBe(false)
  expect(ToolOutputRedaction.closed("title %1b]0;x")).toBe(false)
  expect(ToolOutputRedaction.closed("title \\u001b]0;x")).toBe(false)
})

// Base64: Kubernetes Secrets and Docker registry config are redacted by shape, since their values
// are bare secrets with no recognizable format; other base64 is decoded (two layers) and scanned.
const b64 = (text: string) => Buffer.from(text).toString("base64")
const ghToken = "ghp_" + "Zq8".repeat(12)
const dockerConfig = JSON.stringify({
  auths: { "registry.example.test": { auth: b64("robot:hunter2-registry"), email: "ci@example.test" } },
})

test("a Kubernetes Secret keeps its keys and loses every value", () => {
  const yaml = [
    "apiVersion: v1",
    "data:",
    `  .dockerconfigjson: ${b64(dockerConfig)}`,
    `  password: ${b64("hunter2-db")}`,
    `  token: ${b64(ghToken)}`,
    "kind: Secret",
    "metadata:",
    "  name: app-credentials",
    "  namespace: default",
    "stringData:",
    "  api-key: plain-api-key-value",
    "type: Opaque",
    "",
  ].join("\n")
  const json = JSON.stringify(
    {
      apiVersion: "v1",
      kind: "Secret",
      metadata: { name: "app-credentials" },
      data: { password: b64("hunter2-db"), token: b64(ghToken) },
      stringData: { "api-key": "plain-api-key-value" },
      type: "Opaque",
    },
    null,
    2,
  )
  for (const output of [yaml, json, `${yaml}---\n${yaml}`]) {
    const result = hidesEverywhereB64(output)
    for (const kept of ["password", "token", "api-key", "app-credentials", "Opaque"]) expect(result).toContain(kept)
  }
  expect(hidesEverywhereB64(yaml)).toContain(".dockerconfigjson:")
})

test("comments inside a Kubernetes Secret do not end its data block", () => {
  const yaml = [
    "kind: Secret",
    "data:",
    "  # database credentials",
    `  opaque: ${b64("hunter2-db")}`,
    "    # an indented comment",
    `  other: ${b64("hunter2-other")}`,
    "",
  ].join("\n")
  for (const result of [ToolOutputRedaction.text(yaml), streamed(yaml)]) {
    expect(result).not.toContain(b64("hunter2-db"))
    expect(result).not.toContain(b64("hunter2-other"))
    expect(result).toContain("# database credentials")
  }
})

test("multi-line values in a Kubernetes Secret are redacted whole", () => {
  const yaml = [
    "kind: Secret",
    "stringData:",
    "  passphrase: |",
    "    correct horse",
    "    battery staple",
    "  folded: >-",
    "    hunter2 first",
    "",
    "    hunter2 second",
    "  plain: hunter2 start",
    "    hunter2 continued",
    "  api-key: plain-api-key-value",
    "type: Opaque",
    "",
  ].join("\n")
  for (const result of [ToolOutputRedaction.text(yaml), streamed(yaml)]) {
    for (const secret of ["correct horse", "battery staple", "hunter2", "plain-api-key-value"])
      expect(result).not.toContain(secret)
    for (const key of ["passphrase:", "folded:", "plain:", "api-key:", "type: Opaque"]) expect(result).toContain(key)
  }
})

test("a Docker registry config loses its auth values and keeps the registry", () => {
  for (const output of [dockerConfig, JSON.stringify(JSON.parse(dockerConfig), null, 2), b64(dockerConfig)]) {
    const result = hidesEverywhereB64(output)
    if (output !== b64(dockerConfig)) expect(result).toContain("registry.example.test")
  }
  const withPassword = JSON.stringify({
    auths: { "r.example.test": { username: "robot", password: "hunter2-registry" } },
  })
  expect(hidesEverywhereB64(withPassword)).toContain("r.example.test")
})

test("a token base64-encoded once or twice is found; ordinary base64 is kept", () => {
  for (const value of [
    b64(`token=${ghToken}`),
    b64(b64(`token=${ghToken}`)),
    b64(`https://alice:hunter2-registry@host.test/`),
    // URL-safe base64, with "-" and "_" inside the run.
    Buffer.from("https://alice:abcdef~gh@host.test/").toString("base64url"),
    Buffer.from(`??>>token=${ghToken}??>>`).toString("base64url"),
    // Base64 carried percent-encoded in a query string.
    encodeURIComponent(b64("https://alice:abcdef~gh@host.test/")),
  ])
    expect(ToolOutputRedaction.text(`GITHUB_AUTH=${value}\nnext\n`)).toBe("GITHUB_AUTH=[redacted]\nnext\n")
  // Three layers is past the bound: the output is withheld whole rather than passed through.
  expect(ToolOutputRedaction.text(`X=${b64(b64(b64(`token=${ghToken}`)))}\n`)).not.toContain(
    b64(b64(b64(`token=${ghToken}`))),
  )
  for (const ordinary of [
    `sha256-${Buffer.alloc(32, 7).toString("base64")}`,
    `data:image/png;base64,${Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13]).toString("base64").repeat(4)}`,
    `encoded=${b64("just an ordinary sentence with nothing secret in it")}`,
  ])
    expect(ToolOutputRedaction.text(ordinary)).toBe(ordinary)
})

function streamed(input: string) {
  const stream = ToolOutputRedaction.stream()
  return stream.push(input) + stream.finish()
}

// text() and a stream split anywhere both hide every secret used above.
function hidesEverywhereB64(input: string) {
  const whole = ToolOutputRedaction.text(input)
  const stream = ToolOutputRedaction.stream()
  const streamed = stream.push(input) + stream.finish()
  for (const out of [whole, streamed])
    for (const secret of [
      "hunter2",
      "plain-api-key-value",
      ghToken,
      b64("hunter2-db"),
      b64(ghToken),
      b64("robot:hunter2-registry"),
    ])
      expect(out, JSON.stringify(input)).not.toContain(secret)
  return whole
}
