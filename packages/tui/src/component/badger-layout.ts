import pixels from "./badger-pixels.json"

export type BadgerCapabilities = { tty: boolean; unicode: boolean; color: "rgb" | "ansi256" | "none" }
export type BadgerLayout = { kind: "full" | "compact" | "stacked" | "line" | "hidden"; width: number; height: number }
export type BadgerRun = { text: string; fg?: number; bg?: number }

export function badgerCapabilities(
  tty: boolean | undefined,
  capabilities: { rgb: boolean; ansi256: boolean } | null,
  env: Record<string, string | undefined>,
): BadgerCapabilities {
  const plain = !tty || !!env.NO_COLOR || env.TERM === "dumb"
  const locale = env.LC_ALL || env.LC_CTYPE || env.LANG
  return {
    tty: tty === true,
    unicode: env.TERM !== "dumb" && locale !== "C" && locale !== "POSIX",
    color: plain ? "none" : capabilities?.rgb ? "rgb" : capabilities?.ansi256 ? "ansi256" : "none",
  }
}

// Inputs are the measured welcome slot AFTER prompt, tips and footer layout.
// Pixel art needs one free row above it (ARTWORK_CLEARANCE): drawn edge to edge in a slot exactly
// its height, its top pixel row sits against the session tab bar and the face reads as clipped.
export const ARTWORK_CLEARANCE = 1
export function badgerLayout(width: number, height: number, capabilities: BadgerCapabilities): BadgerLayout {
  const w = Number.isFinite(width) ? Math.max(0, Math.floor(width)) : 0
  const h = Number.isFinite(height) ? Math.max(0, Math.floor(height)) : 0
  if (!w || !h) return { kind: "hidden", width: 0, height: 0 }
  if (capabilities.tty && capabilities.unicode && capabilities.color !== "none") {
    const art = h - ARTWORK_CLEARANCE
    if (w >= 256 && art >= 46) return { kind: "full", width: 256, height: 46 }
    if (w >= 63 && art >= 9) return { kind: "compact", width: 63, height: 9 }
    if (w >= 24 && art >= 11) return { kind: "stacked", width: 24, height: 11 }
  }
  return { kind: "line", width: Math.min(w, "BADGER".length), height: 1 }
}

// Six approved artwork colors; the reduced palette uses exact xterm-256 colors.
// Surrounding UI and native fallback text continue to use the selected host theme.
export const badgerPalette = pixels.palette
export const badgerAnsiPalette = [16, 234, 59, 102, 253, 221]

export function badgerRows(layout: BadgerLayout): BadgerRun[][] {
  if (layout.kind === "hidden") return []
  if (layout.kind === "line") return [[{ text: "BADGER".slice(0, layout.width) }]]
  const grid = layout.kind === "full" ? pixels.full : pixels.face
  const rows = Array.from({ length: grid.length / 2 }, (_, y) => {
    const runs: BadgerRun[] = []
    for (let x = 0; x < grid[0].length; x++) {
      const fg = Number(grid[y * 2][x])
      const bg = Number(grid[y * 2 + 1][x])
      const last = runs.at(-1)
      if (last?.fg === fg && last.bg === bg) last.text += "▀"
      else runs.push({ text: "▀", fg, bg })
    }
    if (layout.kind !== "compact") return runs
    runs.push({ text: "   " })
    if (y < 4) {
      for (let x = 0; x < 35; x++) {
        const fg = Number(pixels.word[y * 2][x])
        const bg = Number(pixels.word[y * 2 + 1][x])
        const last = runs.at(-1)
        if (last?.fg === fg && last.bg === bg) last.text += "▀"
        else runs.push({ text: "▀", fg, bg })
      }
    }
    if (y === 6) runs.push({ text: "EAT THE WORK.", fg: 4 })
    // One column of the art background after the wordmark: the R's leg is its last pixel column,
    // and flush against the box edge it reads as clipped.
    const used = runs.reduce((n, run) => n + run.text.length, 0)
    runs.push({ text: " ".repeat(63 - used) })
    return runs
  })
  if (layout.kind === "stacked")
    rows.push([{ text: "BADGER", fg: 5 }], [{ text: "EAT THE WORK.", fg: 4 }])
  return rows
}
