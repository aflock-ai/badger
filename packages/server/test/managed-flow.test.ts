import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { describe, expect, test } from "bun:test"
import { format } from "@testifysec/marking"
import { Permission } from "@opencode/core/permission"
import { ManagedProfile } from "../src/managed"
import { ManagedFlow } from "../src/managed-flow"

// The gateway ceiling (admission) keeps every connector at or below the gateway; this policy breaks
// it on purpose so the gateway's own second check can be seen to work.
const policy = { gateway: "CONFIDENTIAL", connectors: { confluence: "SECRET", jira: "CONFIDENTIAL" } }
const high = { ...policy, gateway: "SECRET" }
const jira = (tool = "jira_add_comment", sessionID = "ses_a") => ({ sessionID, server: "jira", tool })
const confluence = (tool = "confluence_get_page", sessionID = "ses_a") => ({ sessionID, server: "confluence", tool })
const shown = (flow: ManagedFlow.Flow) => format(flow.label())

/** Runs `fn` with an audit path in a fresh private directory, removed afterwards. */
async function withAudit(fn: (audit: string, dir: string) => unknown) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-flow-"))
  try {
    await fn(path.join(dir, "connector-flow.jsonl"), dir)
  } finally {
    await fs.chmod(dir, 0o700)
    await fs.rm(dir, { recursive: true, force: true })
  }
}

describe("the label", () => {
  test("is the join of the markings of every connector called", () => {
    const flow = ManagedFlow.make({ gateway: "TOP SECRET", connectors: policy.connectors })
    expect(shown(flow)).toBe("UNCLASSIFIED")
    expect(flow.call(jira("jira_search"))).toBeUndefined()
    expect(shown(flow)).toBe("CONFIDENTIAL")
    expect(flow.call(confluence())).toBeUndefined()
    expect(shown(flow)).toBe("SECRET")
  })

  test("is shared by every session: no lineage is tracked", () => {
    const flow = ManagedFlow.make(high)
    flow.call(confluence("confluence_get_page", "ses_child"))
    // Another session, a parent, a fork or a resumed one: all the same label.
    expect(flow.call(jira("jira_search", "ses_unrelated"))).toContain("no write down")
  })

  test("does not rise on a refused call, and another server's tool is not counted", () => {
    const flow = ManagedFlow.make(high)
    flow.call(confluence())
    expect(flow.call(jira())).toContain("no write down")
    expect(shown(flow)).toBe("SECRET")
    const other = ManagedFlow.make(high)
    expect(other.call({ server: "other", tool: "x" })).toBeUndefined()
    expect(shown(other)).toBe("UNCLASSIFIED")
  })
})

describe("connector calls", () => {
  test("memory keeps only the latest decisions", () => {
    const flow = ManagedFlow.make(high)
    flow.call(confluence())
    for (let i = 0; i < 300; i++) flow.call(jira("jira_search"))
    expect(flow.decisions.length).toBe(256)
    expect(flow.decisions.at(-1)).toMatchObject({ sink: "connector:jira", allowed: false })
  })


  test("refuse a call whose label no banner prints, and keep the label", async () => {
    // The controlled-unclassified level's banner comes from the token table.
    const tables = JSON.parse(
      await fs.readFile(path.join(import.meta.dir, "../../../testifysec/connectors/internal/marking/tokens.json"), "utf8"),
    )
    const controlled = tables.levels[1].banner as string
    const flow = ManagedFlow.make({ gateway: "SECRET", connectors: { foreign: "UNCLASSIFIED//FGI GBR", controlled } })
    expect(flow.call({ server: "foreign", tool: "foreign_get" })).toBeUndefined()
    expect(flow.call({ server: "controlled", tool: "controlled_get" })).toBe(
      "controlled_get was refused: these markings cannot be combined: no banner prints controlled unclassified information with FGI, atomic-energy or non-IC markings.",
    )
    expect(shown(flow)).toBe("UNCLASSIFIED//FGI GBR")
    expect(flow.decisions.at(-1)).toMatchObject({ sink: "connector:controlled", allowed: false })
  })


  test("refuse a write to a CONFIDENTIAL connector after a SECRET read", () => {
    const flow = ManagedFlow.make(high)
    expect(flow.call(jira())).toBeUndefined()
    flow.call(confluence())
    expect(flow.call(jira())).toBe(
      "jira_add_comment was refused: this workspace holds SECRET content and connector:jira is accredited for CONFIDENTIAL, and its arguments would carry that content there (no write down). An administrator resets the label by removing the Badger state directory.",
    )
    expect(flow.call(confluence("confluence_create_page"))).toBeUndefined()
  })

  test("refuse a read-only search on a lower connector too, and record each decision", () => {
    const flow = ManagedFlow.make(high)
    flow.call(confluence())
    expect(flow.call(jira("jira_search"))).toContain("jira_search was refused")
    expect(flow.decisions.map((d) => [d.sink, d.tool, d.allowed, d.sessionID])).toEqual([
      ["connector:confluence", "confluence_get_page", true, "ses_a"],
      ["connector:jira", "jira_search", false, "ses_a"],
    ])
  })
})

describe("a call waiting for approval", () => {
  test("is not checked again: its arguments were fixed when the label was dominated", () => {
    // Arguments are the only content a call sends, and they exist before evaluation. A raise while
    // the user is asked cannot add to them, which holds only while a reply cannot edit them: a
    // reply carries a decision and optional feedback text, never new arguments.
    expect(Object.keys(Permission.ReplyInput.fields).sort()).toEqual(["message", "reply", "requestID"])
    expect(Permission.Reply.literals).toEqual(["once", "always", "reject"])
  })
})

describe("the model gateway", () => {
  test("refuses a send the gateway does not dominate, a second check under the ceiling", () => {
    const flow = ManagedFlow.make(policy)
    flow.call(jira("jira_search"))
    expect(() => flow.send("ses_a")).not.toThrow()
    flow.call(confluence())
    expect(() => flow.send("ses_b")).toThrow("this workspace holds SECRET content and gateway is accredited for CONFIDENTIAL")
    expect(flow.decisions.at(-1)).toMatchObject({ sessionID: "ses_b", sink: "gateway", allowed: false, label: "SECRET" })
    expect(() => flow.send()).toThrow(ManagedFlow.Refused)
  })

  test("the managed fetch checks before it reaches the gateway socket", async () => {
    const flow = ManagedFlow.make(policy)
    const fetch = ManagedProfile.gatewayFetch("/nonexistent/gateway.sock", { flow })
    const send = () =>
      fetch(`http://${ManagedProfile.gatewayHost}/v1/chat/completions`, { method: "POST", body: "{}" }).then(
        () => "sent",
        (error: Error) => error.name,
      )
    // Allowed: it gets as far as the (missing) socket.
    expect(await send()).not.toBe("Refused")
    flow.call(confluence())
    expect(await send()).toBe("Refused")
  })

  test("a request that waited for its turn is checked against calls made while it waited", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-flow-sock-"))
    const socket = path.join(dir, "gateway.sock")
    let open!: () => void
    const held = new Promise<void>((resolve) => (open = resolve))
    let reached = 0
    const server = Bun.serve({
      unix: socket,
      async fetch() {
        reached++
        if (reached === 1) await held
        return new Response("{}")
      },
    })
    try {
      const flow = ManagedFlow.make(policy)
      const fetch = ManagedProfile.gatewayFetch(socket, { flow })
      const send = () =>
        fetch(`http://${ManagedProfile.gatewayHost}/v1/chat/completions`, { method: "POST", body: "{}" }).then(
          async (response) => (await response.text(), "sent"),
          (error: Error) => error.name,
        )
      const first = send()
      while (reached === 0) await Bun.sleep(5)
      // The second waits for the first's turn; meanwhile a SECRET connector is called.
      const second = send()
      await Bun.sleep(20)
      flow.call(confluence())
      open()
      expect(await first).toBe("sent")
      expect(await second).toBe("Refused")
      expect(reached).toBe(1)
    } finally {
      server.stop(true)
      await fs.rm(dir, { recursive: true, force: true })
    }
  })
})

describe("the audit file", () => {
  test("rebuilds the label at start from every allowed call it records", () =>
    withAudit(async (audit) => {
      const before = ManagedFlow.make(high, { audit })
      before.call(jira("jira_search"))
      before.call(confluence())
      before.close()
      const after = ManagedFlow.make(high, { audit })
      expect(shown(after)).toBe("SECRET")
      expect(after.call(jira("jira_search", "ses_new"))).toContain("no write down")
      after.close()
    }))

  test("a refused call recorded in it does not raise the rebuilt label", () =>
    withAudit(async (audit) => {
      await fs.writeFile(
        audit,
        JSON.stringify({ time: "t", sink: "connector:confluence", label: "UNCLASSIFIED", accredited: "SECRET", allowed: false }) + "\n",
      )
      const flow = ManagedFlow.make(high, { audit })
      expect(shown(flow)).toBe("UNCLASSIFIED")
      flow.close()
    }))

  test("a call that lifts the label is refused when its decision cannot be written", () =>
    withAudit(async (audit, dir) => {
      const flow = ManagedFlow.make(high, { audit })
      await fs.chmod(dir, 0o500)
      expect(flow.call(confluence("confluence_search"))).toBe(
        "confluence_search was refused: its decision could not be written to the audit record.",
      )
      expect(shown(flow)).toBe("UNCLASSIFIED")
      flow.close()
    }))

  test("a send above the lowest label is refused when its decision cannot be written", () =>
    withAudit(async (audit, dir) => {
      const flow = ManagedFlow.make(high, { audit })
      flow.call(confluence())
      await fs.chmod(dir, 0o500)
      await fs.chmod(audit, 0o400)
      expect(() => flow.send()).toThrow("could not be written to the audit record")
      flow.close()
    }))

  test.skipIf(process.platform !== "linux")("a full disk refuses the transfer instead of keeping part of a record", () =>
    withAudit(async (audit) => {
      const flow = ManagedFlow.make(high, { audit })
      // Every write to /dev/full fails for lack of space.
      await fs.symlink("/dev/full", audit)
      expect(flow.call(confluence())).toBe("confluence_get_page was refused: its decision could not be written to the audit record.")
      expect(shown(flow)).toBe("UNCLASSIFIED")
      flow.close()
    }))

  test("after a failed write nothing more is written or allowed until a restart", () =>
    withAudit(async (audit) => {
      const flow = ManagedFlow.make(high, { audit })
      flow.call(jira("jira_search"))
      await fs.chmod(audit, 0o400)
      expect(flow.call(confluence())).toContain("could not be written")
      // Writable again: still refused, since the failed write may have left part of a line.
      await fs.chmod(audit, 0o600)
      expect(flow.call(confluence())).toContain("could not be written")
      expect(() => flow.send()).toThrow("could not be written")
      flow.close()
      // Every line is whole, and a restart reads the label back.
      const lines = (await fs.readFile(audit, "utf8")).trim().split("\n")
      for (const line of lines) JSON.parse(line)
      const after = ManagedFlow.make(high, { audit })
      expect(shown(after)).toBe("CONFIDENTIAL")
      after.close()
    }))

  test("a failed write stops calls and sends at the lowest label too", () =>
    withAudit(async (audit, dir) => {
      const flow = ManagedFlow.make({ gateway: "SECRET", connectors: { confluence: "SECRET", low: "UNCLASSIFIED" } }, { audit })
      await fs.chmod(dir, 0o500)
      expect(flow.call(confluence())).toContain("could not be written")
      await fs.chmod(dir, 0o700)
      expect(shown(flow)).toBe("UNCLASSIFIED")
      expect(flow.call({ server: "low", tool: "low_search" })).toContain("could not be written")
      expect(() => flow.send()).toThrow("could not be written")
      flow.close()
    }))

  test("one process at a time owns it, and a killed owner's lock is free at once", () =>
    withAudit(async (audit) => {
      const first = ManagedFlow.make(policy, { audit })
      expect(() => ManagedFlow.make(policy, { audit })).toThrow("is in use by another process")
      first.close()
      ManagedFlow.make(policy, { audit }).close()
      // A process holding it is killed: the kernel drops its lock, whatever the lock file holds.
      const holder = Bun.spawn(
        [
          process.execPath,
          "-e",
          `import { ManagedFlow } from ${JSON.stringify(path.join(import.meta.dir, "../src/managed-flow.ts"))}
          ManagedFlow.make(${JSON.stringify(policy)}, { audit: ${JSON.stringify(audit)} })
          console.log("own")
          await Bun.sleep(60000)`,
        ],
        { stdout: "pipe", stderr: "ignore" },
      )
      const reader = holder.stdout.getReader()
      expect(new TextDecoder().decode((await reader.read()).value)).toContain("own")
      expect(() => ManagedFlow.make(policy, { audit })).toThrow("is in use by another process")
      holder.kill("SIGKILL")
      await holder.exited
      ManagedFlow.make(policy, { audit }).close()
    }))

  test("of many processes starting at once, exactly one owns it", () =>
    withAudit(async (audit) => {
      const script = `
        import { ManagedFlow } from ${JSON.stringify(path.join(import.meta.dir, "../src/managed-flow.ts"))}
        try {
          ManagedFlow.make(${JSON.stringify(policy)}, { audit: ${JSON.stringify(audit)} })
          console.log("own")
          await Bun.sleep(3000)
        } catch {
          console.log("refused")
        }`
      const start = async () => {
        const children = Array.from({ length: 8 }, () =>
          Bun.spawn([process.execPath, "-e", script], { stdout: "pipe", stderr: "ignore" }),
        )
        return Promise.all(children.map(async (child) => (await new Response(child.stdout).text()).trim()))
      }
      const fresh = await start()
      expect(fresh.filter((line) => line === "own")).toHaveLength(1)
      expect(fresh.filter((line) => line === "refused")).toHaveLength(7)
      // Again with a lock file left holding anything: still exactly one.
      await fs.writeFile(`${audit}.lock`, "left over")
      const stale = await start()
      expect(stale.filter((line) => line === "own")).toHaveLength(1)
    }), 30_000)

  test("a file, line or directory that cannot be read stops the start", () =>
    withAudit(async (audit, dir) => {
      await fs.writeFile(audit, JSON.stringify({ sink: "connector:jira", accredited: "NOT A MARKING", allowed: true }) + "\n")
      expect(() => ManagedFlow.make(policy, { audit })).toThrow("line 1 cannot be read")
      await fs.writeFile(audit, "{\n")
      expect(() => ManagedFlow.make(policy, { audit })).toThrow("line 1 cannot be read")
      await fs.writeFile(audit, "")
      await fs.chmod(audit, 0o000)
      expect(() => ManagedFlow.make(policy, { audit })).toThrow("cannot be read")
      await fs.chmod(audit, 0o600)
      await fs.chmod(dir, 0o600)
      expect(() => ManagedFlow.make(policy, { audit })).toThrow()
    }))

  test("decisions are appended, 0600", () =>
    withAudit(async (audit) => {
      const flow = ManagedFlow.make(policy, { audit })
      flow.call(confluence())
      expect(() => flow.send("ses_a")).toThrow()
      flow.call(jira())
      const lines = (await fs.readFile(audit, "utf8")).trim().split("\n").map((line) => JSON.parse(line))
      expect(lines.map((line) => [line.sink, line.allowed])).toEqual([
        ["connector:confluence", true],
        ["gateway", false],
        ["connector:jira", false],
      ])
      expect((await fs.stat(audit)).mode & 0o777).toBe(0o600)
      flow.close()
    }))
})

// A hosted workspace that a controller manages has a raise ceiling (BADGER_RAISE_CEILING). A call
// that would lift the label above it is not run here: the user is warned and offered a copy of the
// workspace at the higher level. The label never rises silently.
describe("the raise ceiling", () => {
  const ceiled = (ceiling: string) => ({ gateway: "TOP SECRET", connectors: policy.connectors, ceiling })

  test("a raising call is refused with the warning, and the label does not move", () => {
    const flow = ManagedFlow.make(ceiled("UNCLASSIFIED"))
    expect(flow.call(jira("jira_search"))).toBe(
      "This read is CONFIDENTIAL. Continue in a CONFIDENTIAL copy of this workspace, or cancel. (jira_search was not run.)",
    )
    expect(shown(flow)).toBe("UNCLASSIFIED")
    expect(flow.pendingRaise()).toEqual({ sessionID: "ses_a", server: "jira", tool: "jira_search", level: "CONFIDENTIAL" })
  })

  test("a copy made at the higher level runs the call, and goes no further", () => {
    const flow = ManagedFlow.make(ceiled("CONFIDENTIAL"))
    expect(flow.call(jira("jira_search"))).toBeUndefined()
    expect(shown(flow)).toBe("CONFIDENTIAL")
    expect(flow.call(confluence())).toContain("Continue in a SECRET copy")
    expect(shown(flow)).toBe("CONFIDENTIAL")
  })

  test("is recorded as a refusal, so a restart does not count it", () =>
    withAudit(async (audit) => {
      const flow = ManagedFlow.make(ceiled("UNCLASSIFIED"), { audit })
      flow.call(confluence())
      flow.close()
      const lines = (await fs.readFile(audit, "utf8")).trim().split("\n").map((line) => JSON.parse(line))
      expect(lines.map((line) => [line.sink, line.allowed])).toEqual([["connector:confluence", false]])
      const again = ManagedFlow.make(ceiled("UNCLASSIFIED"), { audit })
      expect(shown(again)).toBe("UNCLASSIFIED")
      again.close()
    }))

  test("a ceiling that is not a marking stops the start", () => {
    expect(() => ManagedFlow.make(ceiled("NOT A MARKING"))).toThrow()
    expect(() => ManagedFlow.make(ceiled(""))).toThrow()
  })

  test("without a ceiling (laptop builds) the label rises as before", () => {
    const flow = ManagedFlow.make({ gateway: "TOP SECRET", connectors: policy.connectors })
    expect(flow.call(confluence())).toBeUndefined()
    expect(flow.pendingRaise()).toBeUndefined()
  })
})

// The app's banner shows the label (T3b): every rise is announced, with the new label, and nothing
// else is. A listener that throws cannot undo or block the decision.
describe("raises", () => {
  test("each rise is announced with the new label, and only a rise", () => {
    const flow = ManagedFlow.make(high)
    const seen: string[] = []
    flow.subscribe((label) => seen.push(label))
    flow.call(jira("jira_search"))
    flow.call(jira("jira_search"))
    flow.call(confluence())
    // Refused: no write down, so the label does not move and nothing is announced.
    flow.call(jira())
    expect(seen).toEqual(["CONFIDENTIAL", "SECRET"])
  })

  test("another server's tool, or a call at the ceiling, announces nothing", () => {
    const flow = ManagedFlow.make({ ...high, ceiling: "CONFIDENTIAL" })
    const seen: string[] = []
    flow.subscribe((label) => seen.push(label))
    flow.call({ server: "other", tool: "x" })
    expect(flow.call(confluence())).toContain("Continue in a SECRET copy")
    expect(seen).toEqual([])
  })

  test("a listener that throws does not undo the raise, and an unsubscribed one hears nothing", () => {
    const flow = ManagedFlow.make(high)
    const seen: string[] = []
    flow.subscribe(() => {
      throw new Error("listener failed")
    })
    const stop = flow.subscribe((label) => seen.push(label))
    expect(flow.call(jira("jira_search"))).toBeUndefined()
    expect(shown(flow)).toBe("CONFIDENTIAL")
    stop()
    flow.call(confluence())
    expect(seen).toEqual(["CONFIDENTIAL"])
  })
})
