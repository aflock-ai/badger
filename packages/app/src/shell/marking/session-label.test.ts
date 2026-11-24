import { expect, test } from "bun:test"
import { SecurityMarking } from "@opencode/util/security-marking"
import { combineMarkings, type ReportedScheme } from "./combine"
import { MarkingReads } from "./reads"

// The banner shows the session label (T3b, design 5.5): the join of each server's deployment
// marking and its workspace label, under the scheme the servers report. Level words come from the
// scheme, so the same assertions read the same in any deployment.

const own = (): ReportedScheme => {
  const s = SecurityMarking.scheme()
  return { name: s.name, sha256: s.digest, levels: SecurityMarking.levels() }
}
const corporate = () => SecurityMarking.presetReports().find((report) => report.name === "corporate")!
const server = (marking: string | null, label: string | null, scheme?: ReportedScheme) => ({
  type: "marking" as const,
  marking,
  label,
  ...(scheme ? { scheme } : {}),
})

test("a server's label above its deployment marking is what the banner shows", () => {
  const [lowest, controlled] = SecurityMarking.levels()
  expect(combineMarkings([server(controlled!, "SECRET")])).toEqual({ type: "marking", marking: "SECRET" })
  expect(combineMarkings([server(lowest!, "CONFIDENTIAL", own())])).toEqual({ type: "marking", marking: "CONFIDENTIAL" })
  // A deployment without a marking still shows the label: content above the lowest is in the workspace.
  expect(combineMarkings([server(null, "CONFIDENTIAL")])).toEqual({ type: "marking", marking: "CONFIDENTIAL" })
})

test("a label at or below the deployment marking leaves the deployment marking", () => {
  const [lowest, controlled] = SecurityMarking.levels()
  expect(combineMarkings([server(controlled!, lowest!)])).toEqual({ type: "marking", marking: controlled })
  expect(combineMarkings([server(controlled!, null)])).toEqual({ type: "marking", marking: controlled })
})

test("one server's label raises the banner for the window, whatever the others hold", () => {
  const [, controlled] = SecurityMarking.levels()
  expect(combineMarkings([server(controlled!, null), server(controlled!, "SECRET")])).toEqual({ type: "marking", marking: "SECRET" })
  expect(combineMarkings([server(controlled!, "SECRET"), server(null, "CONFIDENTIAL")])).toEqual({ type: "marking", marking: "SECRET" })
})

test("the join is the scheme's, not the higher of two banners", () => {
  // Two incomparable labels: the banner holds both, never one of them.
  expect(
    combineMarkings([server(null, "SECRET//REL TO USA, AUS, GBR"), server(null, "SECRET//REL TO USA, CAN, GBR")]),
  ).toEqual({ type: "marking", marking: "SECRET//REL TO USA, GBR" })
})

test("a label on another preset is joined under that preset", () => {
  const scheme = corporate()
  const top = scheme.levels.at(-1)!
  expect(combineMarkings([server(scheme.levels[0]!, top, scheme)])).toEqual({ type: "marking", marking: top })
})

test("a label that does not parse, or one the app cannot join, makes the banner unavailable", () => {
  const [, controlled] = SecurityMarking.levels()
  expect(combineMarkings([server(controlled!, "NOT A BANNER")])).toEqual({ type: "unavailable" })
  // A custom scheme the app holds no table for: its deployment markings can be ordered from the
  // report, but a label can only be joined with the table, so it is never guessed at.
  const custom = { name: "custom", sha256: "sha256:" + "0".repeat(64), levels: ["LOW", "HIGH"] }
  expect(combineMarkings([server("LOW", null, custom)])).toEqual({ type: "marking", marking: "LOW" })
  expect(combineMarkings([server("LOW", "HIGH", custom)])).toEqual({ type: "unavailable" })
  // Labels on two schemes are never compared.
  expect(combineMarkings([server(null, "SECRET"), server(null, corporate().levels.at(-1)!, corporate())])).toEqual({
    type: "unavailable",
  })
})

test("a raise reads the server again: loading until it answers, then the new label", async () => {
  const pending: { resolve: (answer: { marking: string | null; label: string | null }) => void }[] = []
  const reads = MarkingReads.make(
    () => new Promise<{ marking: string | null; label: string | null }>((resolve) => pending.push({ resolve })),
    () => {},
  )
  const live = [{ key: "a", live: true }]
  reads.sync(live)
  pending.shift()!.resolve({ marking: null, label: "CONFIDENTIAL" })
  await Promise.resolve()
  await Promise.resolve()
  expect(reads.marking(live)).toEqual({ type: "marking", marking: "CONFIDENTIAL" })
  reads.refresh("a")
  // Never the old, lower label while the new one is read.
  expect(reads.marking(live)).toEqual({ type: "loading" })
  const stale = pending.shift()!
  reads.refresh("a")
  stale.resolve({ marking: null, label: "CONFIDENTIAL" })
  pending.shift()!.resolve({ marking: null, label: "SECRET" })
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(reads.marking(live)).toEqual({ type: "marking", marking: "SECRET" })
  // A server that is not being read is not read on a raise: it is read when it is back.
  reads.refresh("gone")
  expect(pending).toHaveLength(0)
})
