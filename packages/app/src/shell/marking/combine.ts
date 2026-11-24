import { SecurityMarking } from "@opencode/util/security-marking"

/** The classification scheme a server reports: its name, digest and deployment markings, lowest first. */
export type ReportedScheme = { readonly name: string; readonly sha256: string; readonly levels: readonly string[] }

/**
 * What one connected server reported about its deployment's data marking, and its workspace label
 * (null or absent: nothing above the lowest, or a server that keeps none). A server that reports no
 * scheme (one from before schemes) is on this app's own, us-gov.
 */
export type ServerMarking =
  | {
      readonly type: "marking"
      readonly marking: string | null
      readonly scheme?: ReportedScheme
      readonly label?: string | null
    }
  | { readonly type: "loading" }
  | { readonly type: "unavailable" }

export type BannerMarking =
  | { readonly type: "none" }
  | { readonly type: "marking"; readonly marking: string }
  | { readonly type: "loading" }
  | { readonly type: "unavailable" }

/**
 * One banner for every server this window shows: the highest marking among them, in the order of
 * the scheme the servers report. A server whose marking cannot be read, or reports a marking its
 * own scheme does not have, makes the banner say so rather than show a lower one, and so do two
 * servers with markings on different schemes, whose markings are never compared. A server still
 * answering shows loading. Only when no server sets a marking is there no banner.
 */
export function combineMarkings(servers: readonly ServerMarking[]): BannerMarking {
  if (servers.some((server) => server.type === "unavailable" || unknown(server))) return { type: "unavailable" }

  if (servers.some((server) => server.type === "loading")) return { type: "loading" }
  if (servers.some((server) => server.type === "marking" && server.label != null)) return joined(servers)
  let highest: { marking: string; scheme: ReportedScheme } | null = null

  for (const server of servers) {
    if (server.type !== "marking" || server.marking === null) continue
    const scheme = schemeOf(server)

    if (highest === null) highest = { marking: server.marking, scheme }
    else if (!same(highest.scheme, scheme)) return { type: "unavailable" }
    else if (scheme.levels.indexOf(server.marking) > scheme.levels.indexOf(highest.marking)) highest = { marking: server.marking, scheme }
  }

  return highest === null ? { type: "none" } : { type: "marking", marking: highest.marking }
}

/**
 * The banner when a server reports a workspace label: the join of every deployment marking and
 * label, under the one scheme the servers share. A label is a full banner, so it has no place in the
 * deployment markings' order and is joined with the scheme's own table; a scheme this app holds no
 * table for, two schemes, or a join that fails shows unavailable.
 */
function joined(servers: readonly ServerMarking[]): BannerMarking {
  let scheme: ReportedScheme | null = null
  const banners: string[] = []
  for (const server of servers) {
    if (server.type !== "marking") continue
    const set = [server.marking, server.label].filter((value): value is string => value != null)
    if (set.length === 0) continue
    const its = schemeOf(server)
    if (scheme === null) scheme = its
    else if (!same(scheme, its)) return { type: "unavailable" }
    banners.push(...set)
  }
  try {
    return { type: "marking", marking: SecurityMarking.joinReported(scheme!, banners) }
  } catch {
    return { type: "unavailable" }
  }
}

/** The scheme a server reported, or this app's own (us-gov) for a server that reports none. */
function schemeOf(server: { readonly scheme?: ReportedScheme }): ReportedScheme {
  return server.scheme ?? own()
}

function own(): ReportedScheme {
  const s = SecurityMarking.scheme()
  return { name: s.name, sha256: s.digest, levels: SecurityMarking.levels() }
}

/**
 * Two reports of one scheme: the same digest, name and markings in the same order. A server that
 * claims another's digest with other markings could otherwise rank its own marking above the
 * other's, so a mismatch is never compared.
 */
function same(a: ReportedScheme, b: ReportedScheme) {
  return a.sha256 === b.sha256 && a.name === b.name && a.levels.length === b.levels.length && a.levels.every((level, i) => level === b.levels[i])
}

/**
 * True when a server's marking has no place in an order this app can trust: it is outside the
 * scheme the server reports, or the server claims this app's own scheme or a built-in preset with
 * other markings than that scheme has.
 */
export function unknown(server: ServerMarking) {
  if (server.type !== "marking" || server.marking === null) return false
  const scheme = schemeOf(server)
  if ([own(), ...SecurityMarking.presetReports()].some((known) => known.sha256 === scheme.sha256 && !same(known, scheme))) return true
  return !scheme.levels.includes(server.marking)
}

/** The banner's text, or null for no banner. Loading and unreadable markings say so rather than hide. */
export function bannerText(marking: BannerMarking, t: (key: "classification.loading" | "classification.unavailable") => string) {
  if (marking.type === "none") return null

  if (marking.type === "marking") return marking.marking

  return t(marking.type === "loading" ? "classification.loading" : "classification.unavailable")
}
