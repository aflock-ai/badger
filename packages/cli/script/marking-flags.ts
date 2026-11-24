// The deployment's data marking policy compiled into a managed build (SecurityMarking.build).
// --data-marking is the marking in force; --allowed-markings, the comma-separated markings that may be
// chosen for a connector, defaults to the marking alone. --marking-scheme names the classification
// scheme those markings belong to: a preset, or a scheme file whose text is compiled in; without it the
// scheme is us-gov. A managed build without a marking carries none, and its connector data is refused.
// At runtime the environment may only tighten this.
import { readFileSync } from "node:fs"
import path from "node:path"
import { deployment, loadScheme, preset, presetNames } from "@testifysec/marking"

type CompiledScheme = { preset: string } | { file: string; raw: string }

export function markingFlags(
  argv: readonly string[],
  managed: boolean,
): { marking: string | null; allowed: string[]; scheme?: CompiledScheme } {
  const value = (name: string) => argv.find((arg) => arg.startsWith(`${name}=`))?.slice(name.length + 1)
  const marking = value("--data-marking")
  const list = value("--allowed-markings")
  const schemeArg = value("--marking-scheme")
  if (!managed) {
    if (marking !== undefined || list !== undefined || schemeArg !== undefined)
      throw new Error("--data-marking, --allowed-markings and --marking-scheme require --managed")
    return { marking: null, allowed: [] as string[] }
  }
  // A built-in preset is compiled in by name; anything else is a file, compiled in by its text, so the
  // build carries the scheme it was given.
  let scheme: CompiledScheme | undefined
  if (schemeArg !== undefined)
    scheme = presetNames.includes(schemeArg)
      ? { preset: schemeArg }
      : { file: path.basename(schemeArg), raw: readFileSync(schemeArg, "utf8") }
  const levels = deployment(
    scheme === undefined ? preset("us-gov") : "preset" in scheme ? preset(scheme.preset) : loadScheme(scheme.file, scheme.raw),
  ).levels
  if (marking === undefined) {
    if (list !== undefined) throw new Error("--allowed-markings requires --data-marking")
    return { marking: null, allowed: [] as string[], scheme }
  }
  const allowed = list === undefined ? [marking] : [...new Set(list.split(","))]
  if (![marking, ...allowed].every((item) => levels.includes(item)))
    throw new Error(`markings must be one of ${levels.join(", ")}`)
  if (!allowed.includes(marking)) throw new Error("--allowed-markings must include --data-marking")
  return { marking, allowed, scheme }
}
