/** @jsxImportSource @opentui/solid */
import { expect, test } from "bun:test"
import { RGBA } from "@opentui/core"
import { testRender } from "@opentui/solid"
import type { Context } from "@opencode/plugin/tui/context"
import {
  SidebarRequirements,
  type RequirementsFeed,
  type RequirementsView,
} from "../../src/feature-plugins/sidebar/requirements"

function context() {
  const color = RGBA.fromInts(200, 200, 200)
  return {
    theme: { text: { base: color, muted: color, feedback: { warning: { base: color } } } },
    data: { session: { get: () => ({ location: { directory: "/work" } }) } },
  } as unknown as Context
}

// A feed the test drives: records who subscribed and with what, and whether they left.
function feed() {
  const subscribers: { context: unknown; emit: (value: RequirementsView) => void; gone: boolean }[] = []
  const source: RequirementsFeed = {
    subscribe(context, emit) {
      const entry = { context, emit, gone: false }
      subscribers.push(entry)
      return () => (entry.gone = true)
    },
  }
  return { source, subscribers }
}

async function render(source: RequirementsFeed) {
  const app = await testRender(
    () => (
      <box width={40}>
        <SidebarRequirements context={context()} sessionID="one" source={source} />
      </box>
    ),
    { width: 40, height: 12 },
  )
  await app.renderOnce()
  return app
}

test("the sidebar subscribes for the session's own directory and shows what the source sends", async () => {
  const { source, subscribers } = feed()
  const app = await render(source)
  try {
    expect(subscribers.map((entry) => entry.context)).toEqual([{ session: "one", directory: "/work" }])
    expect(app.captureCharFrame()).toContain("Requirements")
    subscribers[0]!.emit({ state: "available", lines: ["signed: block / supported"], details: [] })
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("signed: block / supported")
    subscribers[0]!.emit({
      state: "unavailable",
      lines: ["Repository or credential changed; refreshing."],
      details: [],
    })
    await app.renderOnce()
    const frame = app.captureCharFrame()
    expect(frame).toContain("credential changed")
    expect(frame).not.toContain("signed: block")
  } finally {
    app.renderer.destroy()
  }
  expect(subscribers[0]!.gone).toBe(true)
})

test("a disabled source shows nothing", async () => {
  const { source, subscribers } = feed()
  const app = await render(source)
  try {
    subscribers[0]!.emit({ state: "disabled", lines: [""], details: [] })
    await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("Requirements")
  } finally {
    app.renderer.destroy()
  }
})
