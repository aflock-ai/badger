import { expect, test } from "bun:test"
import { workerArgs } from "./worker-args"

test("marking flags never take a positional slot", () => {
  expect(workerArgs(["out", "--data-marking=CUI"])).toEqual({
    output: "out",
    target: "bun-linux-arm64",
    fixture: false,
    markingArgs: ["--data-marking=CUI"],
  })
  expect(workerArgs(["--allowed-markings=CUI", "out", "bun-linux-x64", "--data-marking=CUI", "fixture"])).toEqual({
    output: "out",
    target: "bun-linux-x64",
    fixture: true,
    markingArgs: ["--allowed-markings=CUI", "--data-marking=CUI"],
  })
  expect(workerArgs([]).output).toBeUndefined()
})

test("--marking-scheme is a marking flag, accepted anywhere", () => {
  expect(workerArgs(["--marking-scheme=corporate", "out", "--data-marking=INTERNAL"])).toEqual({
    output: "out",
    target: "bun-linux-arm64",
    fixture: false,
    markingArgs: ["--marking-scheme=corporate", "--data-marking=INTERNAL"],
  })
})
