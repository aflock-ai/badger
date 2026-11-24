// The deployment marking policy a scheme gives the TypeScript side (packages/util security-marking):
// which markings a deployment may be set to, and the reserved metadata fields a record stored under
// one carries. Words come from the scheme, never from literals elsewhere.

import { preset, type Scheme } from "./scheme.js"

const usGov = preset("us-gov")

export interface Deployment {
  readonly scheme: Scheme
  /** The markings a deployment may be set to, lowest first. */
  readonly levels: readonly string[]
  /** The reserved metadata fields for a record stored under `value`. They are always derived. */
  stamp(value: string): Record<string, string>
  /** Whether a stored record's `marking_scheme` field (absent: us-gov) names this scheme. */
  owns(markingScheme: unknown): boolean
  /** True when `marking` is below `deployment`; a marking outside the levels is refused. */
  lowers(marking: string, deployment: string | null): boolean
}

export function deployment(s: Scheme): Deployment {
  const isUsGov = s.digest === usGov.digest
  // us-gov: this build carries unclassified data only, so its deployment markings are the two
  // unclassified levels, and records keep the fields they have always had. Any other scheme: every
  // level, and each record names the scheme it was stamped under.
  const levels = Object.freeze(s.levels.slice(0, isUsGov ? 2 : s.levels.length).map((l) => l.name))
  const known = (value: string) => levels.includes(value)
  const stamp = (value: string): Record<string, string> => {
    if (!known(value)) throw new Error(`${JSON.stringify(value)} is not a deployment marking of the ${s.name} scheme`)
    if (isUsGov)
      return {
        deployment_marking: value,
        classification: levels[0],
        marking_source: "deployment",
        ...(value === levels[1] ? { control_marking: value } : {}),
      }
    return { deployment_marking: value, classification: value, marking_source: "deployment", marking_scheme: s.digest }
  }
  return {
    scheme: s,
    levels,
    stamp,
    owns: (markingScheme) => (markingScheme === undefined ? isUsGov : markingScheme === s.digest),
    lowers(marking, current) {
      if (current === null) return false
      if (!known(marking) || !known(current)) throw new Error("Unknown deployment marking")
      return levels.indexOf(marking) < levels.indexOf(current)
    },
  }
}
