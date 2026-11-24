// jade:ring local
import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { setRendererCapabilities } from "@opentui/core/testing"
import { createSignal, Show } from "solid-js"
import { BadgerWelcome, WelcomeSpace } from "../src/component/badger-welcome"

test("real renderer reserves controls, resizes without stale art, and unmounts welcome in session", async () => {
  const tty = Object.getOwnPropertyDescriptor(process.stdout, "isTTY")
  const env = { NO_COLOR: process.env.NO_COLOR, TERM: process.env.TERM, LC_ALL: process.env.LC_ALL }
  Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true })
  delete process.env.NO_COLOR
  process.env.TERM = "xterm-256color"
  process.env.LC_ALL = "en_US.UTF-8"
  const [session, setSession] = createSignal(false)
  const [controls, setControls] = createSignal(8)
  const app = await testRender(
    () => (
      <box width="100%" height="100%">
        <Show when={!session()} fallback={<text>SESSION</text>}>
          <WelcomeSpace>{(size) => <BadgerWelcome width={size().width} height={size().height} />}</WelcomeSpace>
        </Show>
        <box height={controls()} flexShrink={0}>
          <text>PROMPT / HELP / STATUS</text>
        </box>
      </box>
    ),
    { width: 80, height: 24 },
  )
  try {
    app.renderer.emit("capabilities", setRendererCapabilities(app.renderer, { rgb: true, ansi256: true }))
    await app.flush()
    expect(app.captureCharFrame()).toContain("▀")
    expect(app.captureCharFrame()).toContain("EAT THE WORK.")
    expect(app.captureCharFrame()).toContain("PROMPT / HELP / STATUS")
    expect(
      app
        .captureSpans()
        .lines.flatMap((line) => line.spans)
        .find((span) => span.text.includes("EAT THE WORK."))
        ?.bg.toInts(),
    ).toEqual([11, 19, 25, 255])

    for (const [width, height, artwork] of [
      [260, 60, true],
      [40, 20, true],
      [160, 12, false],
      [3, 10, false],
      [80, 24, true],
    ] as const) {
      app.resize(width, height)
      await app.flush()
      const frame = app.captureCharFrame()
      expect(frame.includes("▀")).toBe(artwork)
      if (width >= 24) expect(frame).toContain("PROMPT / HELP / STATUS")
    }

    setControls(23)
    await app.flush()
    expect(app.captureCharFrame()).toContain("BADGER")
    expect(app.captureCharFrame()).not.toContain("▀")
    setControls(8)
    app.renderer.emit("capabilities", setRendererCapabilities(app.renderer, { rgb: false, ansi256: false }))
    await app.flush()
    expect(app.captureCharFrame()).toContain("BADGER")
    expect(app.captureCharFrame()).not.toContain("▀")
    app.renderer.emit("capabilities", setRendererCapabilities(app.renderer, { rgb: false, ansi256: true }))
    await app.flush()
    expect(app.captureCharFrame()).toContain("▀")
    expect(
      app
        .captureSpans()
        .lines.flatMap((line) => line.spans)
        .find((span) => span.text.includes("▀"))?.fg.intent,
    ).toBe("indexed")

    for (const plain of ["NO_COLOR", "dumb", "ASCII", "redirected"]) {
      process.env.NO_COLOR = plain === "NO_COLOR" ? "1" : ""
      process.env.TERM = plain === "dumb" ? "dumb" : "xterm-256color"
      process.env.LC_ALL = plain === "ASCII" ? "C" : "en_US.UTF-8"
      Object.defineProperty(process.stdout, "isTTY", { value: plain !== "redirected", configurable: true })
      app.renderer.emit("capabilities", setRendererCapabilities(app.renderer, { rgb: true, ansi256: true }))
      await app.flush()
      expect(app.captureCharFrame()).toContain("BADGER")
      expect(app.captureCharFrame()).not.toMatch(/[▀\x1b]/u)
      expect(app.externalOutput.takeText()).toBe("")
    }

    const listeners = app.renderer.listenerCount("capabilities")
    setSession(true)
    await app.flush()
    expect(app.captureCharFrame()).toContain("SESSION")
    expect(app.captureCharFrame()).not.toContain("▀")
    expect(app.renderer.listenerCount("capabilities")).toBe(listeners - 1)
  } finally {
    app.renderer.destroy()
    if (tty) Object.defineProperty(process.stdout, "isTTY", tty)
    else delete (process.stdout as { isTTY?: boolean }).isTTY
    for (const [key, value] of Object.entries(env)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
})

// Seen in VS Code's terminal panel (69x29 under the session tab bar): a slot exactly as tall as the
// art got it edge to edge, its top pixel row against the tab bar, so the face looked clipped.
test("the art never touches the row above it and is drawn whole or not at all", async () => {
  const tty = Object.getOwnPropertyDescriptor(process.stdout, "isTTY")
  const env = { NO_COLOR: process.env.NO_COLOR, TERM: process.env.TERM, LC_ALL: process.env.LC_ALL }
  Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true })
  delete process.env.NO_COLOR
  process.env.TERM = "xterm-256color"
  process.env.LC_ALL = "en_US.UTF-8"
  const app = await testRender(
    () => (
      <box width="100%" height="100%">
        <box height={1} flexShrink={0}>
          <text>TABS</text>
        </box>
        <WelcomeSpace>{(size) => <BadgerWelcome width={size().width} height={size().height} />}</WelcomeSpace>
        <box height={8} flexShrink={0}>
          <text>PROMPT</text>
        </box>
      </box>
    ),
    { width: 80, height: 24 },
  )
  try {
    app.renderer.emit("capabilities", setRendererCapabilities(app.renderer, { rgb: true, ansi256: true }))
    for (const [width, height] of [
      [80, 24],
      [200, 50],
      [69, 18],
      [69, 19],
      [69, 20],
      [86, 16],
      [62, 18],
    ] as const) {
      app.resize(width, height)
      await app.flush()
      const lines = app.captureCharFrame().split("\n")
      expect(lines[0]).toContain("TABS")
      expect(lines[1]).not.toContain("▀")
      const art = lines.filter((line) => line.includes("▀")).length
      expect([0, 9, 23].includes(art)).toBe(true)
      expect(lines.some((line) => line.includes("PROMPT"))).toBe(true)
    }
  } finally {
    app.renderer.destroy()
    if (tty) Object.defineProperty(process.stdout, "isTTY", tty)
    else delete (process.stdout as { isTTY?: boolean }).isTTY
    for (const [key, value] of Object.entries(env)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
})
