import { expect, test } from "bun:test"
import { SecurityMarking } from "@opencode/util/security-marking"
import { bannerText, combineMarkings } from "./combine"

const marked = (marking: string | null) => ({ type: "marking" as const, marking })

test("no servers, or none that sets a marking, shows no banner", () => {
  expect(combineMarkings([])).toEqual({ type: "none" })
  expect(combineMarkings([marked(null), marked(null)])).toEqual({ type: "none" })
})

test("the banner shows the highest marking among connected servers", () => {
  expect(combineMarkings([marked("UNCLASSIFIED")])).toEqual({ type: "marking", marking: "UNCLASSIFIED" })
  expect(combineMarkings([marked("UNCLASSIFIED"), marked("CUI"), marked(null)])).toEqual({ type: "marking", marking: "CUI" })
  expect(combineMarkings([marked("CUI"), marked("UNCLASSIFIED")])).toEqual({ type: "marking", marking: "CUI" })
})

test("a server whose marking cannot be read makes the marking unavailable, even next to a known one", () => {
  expect(combineMarkings([marked("CUI"), { type: "unavailable" }])).toEqual({ type: "unavailable" })
  expect(combineMarkings([marked(null), { type: "unavailable" }])).toEqual({ type: "unavailable" })
})

test("an unread marking shows as loading until every server has answered", () => {
  expect(combineMarkings([marked("CUI"), { type: "loading" }])).toEqual({ type: "loading" })
  expect(combineMarkings([{ type: "loading" }, { type: "unavailable" }])).toEqual({ type: "unavailable" })
})

test("banner text: the marking itself, or why there is none to show; null means no banner", () => {
  const t = (key: string) => key
  expect(bannerText({ type: "marking", marking: "CUI" }, t)).toBe("CUI")
  expect(bannerText({ type: "loading" }, t)).toBe("classification.loading")
  expect(bannerText({ type: "unavailable" }, t)).toBe("classification.unavailable")
  expect(bannerText({ type: "none" }, t)).toBeNull()
})

test("a marking the app does not know makes the banner unavailable, never a lower known marking", () => {
  const [lowest, controlled] = SecurityMarking.levels()
  // The regression: the higher, unknown marking used to compare as the lowest, so the banner kept
  // showing the known one beside it, in either order.
  expect(combineMarkings([marked(controlled), marked("SECRET")])).toEqual({ type: "unavailable" })
  expect(combineMarkings([marked("SECRET"), marked(controlled)])).toEqual({ type: "unavailable" })
  expect(combineMarkings([marked(lowest), marked("TOP SECRET"), marked(null)])).toEqual({ type: "unavailable" })
  // Alone, an unknown marking is not shown as if it were one the app can order.
  expect(combineMarkings([marked("PUBLIC")])).toEqual({ type: "unavailable" })
  expect(combineMarkings([marked("")])).toEqual({ type: "unavailable" })
})

// A server reports its deployment's scheme: the banner orders and checks its marking with that
// scheme's markings, so a server on another scheme is shown with its own words.
const corporate = { name: "corporate", sha256: "sha256:corporate", levels: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] }
const usGov = () => ({ name: "us-gov", sha256: "sha256:us-gov", levels: [...SecurityMarking.levels()] })
const under = (scheme: typeof corporate, marking: string | null) => ({ type: "marking" as const, marking, scheme })

test("a server's marking is ordered and checked under the scheme it reports", () => {
  expect(combineMarkings([under(corporate, "PUBLIC")])).toEqual({ type: "marking", marking: "PUBLIC" })
  expect(combineMarkings([under(corporate, "CONFIDENTIAL"), under(corporate, "INTERNAL"), under(corporate, null)])).toEqual({
    type: "marking",
    marking: "CONFIDENTIAL",
  })
  expect(combineMarkings([under(corporate, "INTERNAL"), under(corporate, "RESTRICTED")])).toEqual({ type: "marking", marking: "RESTRICTED" })
  // A marking outside the scheme the server itself reports is unknown.
  expect(combineMarkings([under(corporate, "UNHEARD-OF")])).toEqual({ type: "unavailable" })
  expect(combineMarkings([under(corporate, "INTERNAL"), under(corporate, "INTERNAL//PII")])).toEqual({ type: "unavailable" })
})

test("servers on two schemes make the banner unavailable: their markings are never compared", () => {
  const [lowest] = SecurityMarking.levels()
  expect(combineMarkings([under(corporate, "INTERNAL"), under(usGov(), lowest)])).toEqual({ type: "unavailable" })
  expect(combineMarkings([under(usGov(), lowest), under(corporate, "RESTRICTED")])).toEqual({ type: "unavailable" })
  // Same words, another digest: still another scheme.
  expect(combineMarkings([under(corporate, "INTERNAL"), under({ ...corporate, sha256: "sha256:other" }, "INTERNAL")])).toEqual({
    type: "unavailable",
  })
  // A server with no marking has nothing to compare, whatever its scheme.
  expect(combineMarkings([under(corporate, "INTERNAL"), under(usGov(), null)])).toEqual({ type: "marking", marking: "INTERNAL" })
})

test("a server that reports no scheme is on this app's own (us-gov)", () => {
  const [lowest, higher] = SecurityMarking.levels()
  const own = { ...usGov(), sha256: SecurityMarking.scheme().digest }
  expect(combineMarkings([marked(lowest), under(own, higher)])).toEqual({ type: "marking", marking: higher })
  expect(combineMarkings([marked(higher), under(corporate, "PUBLIC")])).toEqual({ type: "unavailable" })
})

test("a server cannot lower another's marking by claiming its scheme with other markings", () => {
  const [lowest, higher] = SecurityMarking.levels()
  const own = { ...usGov(), sha256: SecurityMarking.scheme().digest }
  // The same digest with another list of markings is not that scheme: never compared, in either order.
  const forged = { ...corporate, levels: ["PUBLIC"] }
  expect(combineMarkings([under(corporate, "RESTRICTED"), under(forged, "PUBLIC")])).toEqual({ type: "unavailable" })
  expect(combineMarkings([under(forged, "PUBLIC"), under(corporate, "RESTRICTED")])).toEqual({ type: "unavailable" })
  expect(combineMarkings([under(corporate, "RESTRICTED"), under({ ...corporate, name: "other" }, "PUBLIC")])).toEqual({ type: "unavailable" })
  // This app's own scheme has the markings this app knows for it, whatever a server claims.
  expect(combineMarkings([under(own, higher), under({ ...own, levels: [lowest] }, lowest)])).toEqual({ type: "unavailable" })
  expect(combineMarkings([marked(higher), under({ ...own, levels: [lowest] }, lowest)])).toEqual({ type: "unavailable" })
  expect(combineMarkings([under({ ...own, levels: ["UNHEARD-OF", ...own.levels] }, "UNHEARD-OF")])).toEqual({ type: "unavailable" })  // A built-in preset's digest names that preset's markings, even with no genuine server beside it.
  const real = SecurityMarking.presetReports().find((r) => r.name === "corporate")!
  expect(combineMarkings([under(real, "RESTRICTED")])).toEqual({ type: "marking", marking: "RESTRICTED" })
  expect(combineMarkings([under({ ...real, levels: ["RESTRICTED", "PUBLIC"] }, "PUBLIC")])).toEqual({ type: "unavailable" })
})
