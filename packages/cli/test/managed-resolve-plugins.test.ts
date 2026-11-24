import { NodeFileSystem } from "@effect/platform-node"
import { EmbeddedHost } from "@opencode/sdk/host"
import { Global } from "@opencode/util/global"
import { afterEach, expect, spyOn, test } from "bun:test"
import { Effect } from "effect"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { ManagedConnectorProfile } from "../src/managed-connectors"
import { ServerConnection } from "../src/services/server-connection"

const spies: { mockRestore(): void }[] = []
afterEach(() => {
  for (const spy of spies.splice(0)) spy.mockRestore()
})

// The managed build's own path: ServerConnection.resolve admits the profile's connectors and
// starts the in-process server. The plugins that server is created with must include the
// connector flow plugin, or no high-water check runs.
test("a managed server is created with the connector flow plugin when connectors are admitted", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-resolve-"))
  const admitted = {
    expires: new Date("2099-01-01T00:00:00Z"),
    gateway: { classification: "SECRET" },
    connectors: [
      {
        name: "jira",
        binarySha256: "0".repeat(64),
        baseUrl: "https://jira.example.invalid",
        tokenPath: "/run/badger/tokens/jira.token",
        caPath: null,
        writes: false,
        classification: "SECRET",
        flags: {},
        permissions: {},
        executable: "/nonexistent/jira",
      },
    ],
  } as unknown as ManagedConnectorProfile.Admitted
  spies.push(spyOn(ManagedConnectorProfile, "load").mockReturnValue(Effect.succeed(admitted) as never))
  const created: string[][] = []
  const create = EmbeddedHost.create
  spies.push(
    spyOn(EmbeddedHost, "create").mockImplementation(((options: { plugins?: ReadonlyArray<{ id: string }> }, ...rest: unknown[]) => {
      created.push((options.plugins ?? []).map((plugin) => plugin.id))
      return (create as (...args: unknown[]) => unknown)(options, ...rest)
    }) as never),
  )
  const layer = Global.layerWith({
    config: path.join(root, "config"),
    state: path.join(root, "state"),
    data: path.join(root, "data"),
  })
  try {
    await Effect.runPromise(
      ServerConnection.resolve({ managed: true }).pipe(
        Effect.provide(layer),
        Effect.provide(NodeFileSystem.layer),
        Effect.scoped,
      ) as Effect.Effect<unknown, unknown, never>,
    )
    expect(created).toEqual([["badger.connectors.flow"]])
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
}, 30_000)
