import { expect, test } from "bun:test"
import { deployment, loadScheme, preset } from "./marking"

test("us-gov: the deployment markings and their stamps are the ones every stored record has", () => {
  const usGov = preset("us-gov")
  const [unclassified, controlled, above] = usGov.levels.map((l) => l.name)
  const d = deployment(usGov)
  expect(d.levels).toEqual([unclassified, controlled])
  // Byte for byte what security-marking.ts wrote before the scheme existed: these key orders and values.
  expect(JSON.stringify(d.stamp(unclassified))).toBe(
    `{"deployment_marking":"${unclassified}","classification":"${unclassified}","marking_source":"deployment"}`,
  )
  expect(JSON.stringify(d.stamp(controlled))).toBe(
    `{"deployment_marking":"${controlled}","classification":"${unclassified}","marking_source":"deployment","control_marking":"${controlled}"}`,
  )
  expect(() => d.stamp(above)).toThrow("not a deployment marking")
  expect(d.owns(undefined)).toBe(true)
  expect(d.owns(preset("corporate").digest)).toBe(false)
})

test("another scheme: every level is a deployment marking, and records name the scheme", () => {
  const s = preset("corporate")
  const d = deployment(s)
  expect(d.levels).toEqual(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"])
  expect(d.stamp("CONFIDENTIAL")).toEqual({
    deployment_marking: "CONFIDENTIAL",
    classification: "CONFIDENTIAL",
    marking_source: "deployment",
    marking_scheme: s.digest,
  })
  expect(() => d.stamp(preset("us-gov").levels[1].name)).toThrow("not a deployment marking")
  // A record without a scheme was stamped under us-gov, so it is not this scheme's.
  expect(d.owns(undefined)).toBe(false)
  expect(d.owns(s.digest)).toBe(true)
  expect(d.owns("sha256:" + "0".repeat(64))).toBe(false)
  expect(d.lowers("INTERNAL", "CONFIDENTIAL")).toBe(true)
  expect(d.lowers("RESTRICTED", "CONFIDENTIAL")).toBe(false)
  expect(() => d.lowers("LOW", "CONFIDENTIAL")).toThrow("Unknown deployment marking")
})

test("a deployment scheme file's levels are its deployment markings", () => {
  const s = loadScheme(
    "t.json",
    JSON.stringify({ schema: "badger.marking-scheme/v1", name: "t", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }], groups: [] }),
  )
  expect(deployment(s).levels).toEqual(["LOW", "HIGH"])
})
