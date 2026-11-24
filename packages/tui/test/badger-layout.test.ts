// jade:ring local
import { describe, expect, test } from "bun:test"
import { badgerCapabilities, badgerLayout, badgerRows } from "../src/component/badger-layout"
import pixels from "../src/component/badger-pixels.json"

const color = { tty: true, unicode: true, color: "rgb" as const }

describe("Badger welcome layout", () => {
  test.each([
    [256, 47, "full"],
    [255, 47, "compact"],
    [256, 46, "compact"],
    [63, 10, "compact"],
    [62, 10, "line"],
    [62, 9, "line"],
    [24, 13, "stacked"],
    [23, 13, "line"],
    [24, 12, "stacked"],
    [24, 11, "line"],
    [160, 1, "line"],
    [1, 1, "line"],
    [0, 1, "hidden"],
    [80, 0, "hidden"],
  ] as const)("available %ix%i selects %s", (width, height, kind) => {
    expect(badgerLayout(width, height, color).kind).toBe(kind)
  })

  test("uses remaining space, not terminal width, and reselects on resize", () => {
    expect(
      [
        [256, 47],
        [80, 10],
        [40, 12],
        [160, 2],
        [3, 1],
        [256, 47],
      ].map(([w, h]) => badgerLayout(w, h, color).kind),
    ).toEqual(["full", "compact", "stacked", "line", "line", "full"])
  })

  test("all emitted rows fit even tiny and fractional dimensions", () => {
    for (const width of [0, 1, 3, 6, 19, 24, 40, 61, 62, 80, 255, 256, 300]) {
      for (const height of [0, 1, 8, 9, 11, 12, 45, 46, 60]) {
        const layout = badgerLayout(width + 0.2, height + 0.2, color)
        const rows = badgerRows(layout)
        expect(rows.length).toBe(layout.height)
        expect(rows.length).toBeLessThanOrEqual(height)
        for (const row of rows) expect(row.reduce((n, run) => n + run.text.length, 0)).toBeLessThanOrEqual(width)
      }
    }
    expect(badgerLayout(-1, 10, color).kind).toBe("hidden")
    expect(badgerLayout(NaN, Infinity, color).kind).toBe("hidden")
  })

  test("fallbacks are native ASCII without escape sequences or pixel colors", () => {
    for (const caps of [
      { ...color, tty: false },
      { ...color, unicode: false },
      { ...color, color: "none" as const },
    ]) {
      const layout = badgerLayout(256, 47, caps)
      expect(layout.kind).toBe("line")
      expect(badgerRows(layout)).toEqual([[{ text: "BADGER" }]])
    }
    expect(badgerRows(badgerLayout(3, 1, color))).toEqual([[{ text: "BAD" }]])
    expect(badgerLayout(80, 12, { ...color, color: "ansi256" }).kind).toBe("compact")
  })

  test("capabilities honor no-color, dumb, redirection and ASCII locales", () => {
    expect(badgerCapabilities(true, { rgb: true, ansi256: true }, {}).color).toBe("rgb")
    expect(badgerCapabilities(true, { rgb: false, ansi256: true }, {}).color).toBe("ansi256")
    expect(badgerCapabilities(true, null, {}).color).toBe("none")
    for (const env of [{ NO_COLOR: "1" }, { TERM: "dumb" }]) {
      expect(badgerCapabilities(true, { rgb: true, ansi256: true }, env).color).toBe("none")
    }
    expect(badgerCapabilities(true, { rgb: true, ansi256: true }, { NO_COLOR: "" }).color).toBe("rgb")
    expect(badgerCapabilities(false, { rgb: true, ansi256: true }, {}).color).toBe("none")
    expect(badgerCapabilities(true, null, { LC_ALL: "C", LANG: "en_US.UTF-8" }).unicode).toBe(false)
    expect(badgerCapabilities(true, null, { LANG: "en_US.UTF-8" }).unicode).toBe(true)
  })

  test("bundled approved grid and all pixel runs retain the six-color contract", () => {
    expect(pixels.full).toHaveLength(92)
    expect(pixels.full.every((row) => row.length === 256 && /^[0-5]+$/.test(row))).toBe(true)
    expect(pixels.palette).toEqual(["#0b1319", "#192932", "#4c616f", "#70848e", "#e0e1d7", "#f8c76b"])
    expect(pixels.source).toBe("badger-detailed-pixels.png")
    for (const row of badgerRows(badgerLayout(256, 47, color))) {
      expect(row.reduce((n, run) => n + run.text.length, 0)).toBe(256)
      for (const run of row) {
        expect(run.text).toMatch(/^▀+$/u)
        expect(run.fg).toBeGreaterThanOrEqual(0)
        expect(run.bg).toBeLessThan(6)
      }
    }
  })

  test("compact art leaves a background column after the wordmark", () => {
    const rows = badgerRows(badgerLayout(80, 10, color))
    expect(rows.length).toBe(9)
    for (const row of rows) {
      expect(row.reduce((n, run) => n + run.text.length, 0)).toBe(63)
      expect(row.at(-1)?.text.endsWith(" ")).toBe(true)
    }
  })
})
