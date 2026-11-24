import { expect, test } from "bun:test"
import { Bearer } from "@opencode/core/requirements/bearer"
import { parseResponse, targetSchema } from "@opencode/core/requirements/schema"
import { readRequirements, requestJSON } from "@opencode/core/requirements/transport"
import { snapshot, target } from "./fixtures"

const bearer = () => new Bearer("dedicated", Date.now() + 60_000)

test("exact closed DTO and disconnected target binding", () => {
  expect(parseResponse(snapshot, target, 200).state).toBe("available")
  expect(
    parseResponse(
      { version: snapshot.version, state: "disconnected", code: "connection_not_found", target },
      target,
      200,
    ).state,
  ).toBe("disconnected")
  for (const changed of [
    { ...snapshot, secret: "no" },
    { ...snapshot, version: "v2" },
    { ...snapshot, target: { ...target, commit: "b".repeat(40) } },
    { ...snapshot, connection: { generation: -1, created_at: "today" } },
    { ...snapshot, builtins: Array(17).fill(snapshot.builtins[0]) },
    { ...snapshot, last_decision: { state: "none", current_status: "passed" } },
  ])
    expect(() => parseResponse(changed, target, 200)).toThrow()
  expect(() => parseResponse(snapshot, target, 401)).toThrow()
})

test("selectors are never normalized", () => {
  for (const ref of [
    "main",
    "refs/heads/a..b",
    "refs/heads/.a",
    "refs/heads/a.lock",
    "refs/heads/a@{b",
    "refs/heads/a\u202eb",
    "refs/heads/a b",
    "refs/heads/a//b",
  ]) {
    expect(targetSchema.safeParse({ ...target, ref }).success).toBe(false)
  }
  for (const repository_id of ["01", "0", "9223372036854775808"])
    expect(targetSchema.safeParse({ ...target, repository_id }).success).toBe(false)
})

test("exact policy authority, count, availability and timestamp constraints fail closed", () => {
  const policy = {
    definition_id: "11111111-1111-4111-8111-111111111111",
    release_id: "22222222-2222-4222-8222-222222222222",
    policy_gitoid: "a".repeat(64),
    policy_digest: "b".repeat(64),
    name: "Checks",
    mode: "block",
    availability: "supported",
    unavailable_reason: null,
    policy_view_url: `https://platform.testifysec.com/archivista/download/${"a".repeat(64)}`,
    summary: {
      authoritative: false,
      requirement_count: 1,
      requirements: [
        {
          kind: "step_attestation",
          step: "test",
          attestation_type: "command-run",
          rego_policy_count: 1,
          ai_policy_count: 0,
        },
      ],
      not_fully_summarized: ["signer_constraints", "rego", "timestamps", "cross_step_dependencies", "expiry"],
    },
  }
  expect(parseResponse({ ...snapshot, policies: [policy] }, target, 200).state).toBe("available")
  for (const changed of [
    { ...policy, policy_gitoid: "A".repeat(64) },
    { ...policy, policy_view_url: "https://evil.test/policy" },
    { ...policy, availability: "unsupported" },
    { ...policy, latest: "yes" },
    { ...policy, summary: { ...policy.summary, requirement_count: 0 } },
    { ...policy, summary: { ...policy.summary, authoritative: true } },
    {
      ...policy,
      summary: {
        ...policy.summary,
        requirements: [{ ...policy.summary.requirements[0], ai_policy_count: Number.MAX_SAFE_INTEGER + 1 }],
      },
    },
  ])
    expect(() => parseResponse({ ...snapshot, policies: [changed] }, target, 200)).toThrow()
  expect(() =>
    parseResponse({ ...snapshot, connection: { generation: 1, created_at: "2026-02-30T12:00:00Z" } }, target, 200),
  ).toThrow()
})

test("HTTP boundary pins origin, refuses redirects and bounds bytes before JSON parsing", async () => {
  let calls = 0
  const fake = async (url: string, init: RequestInit) => {
    calls++
    expect(url.startsWith("https://pushgate.dev/api/requirements?")).toBe(true)
    expect(init.redirect).toBe("error")
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer dedicated")
    expect(url).not.toContain("dedicated")
    return Response.json(snapshot)
  }
  expect((await readRequirements(target, bearer(), new AbortController().signal, fake)).state).toBe("available")
  expect(calls).toBe(1)
  await expect(requestJSON("https://evil.test/api", {}, new AbortController().signal, fake)).rejects.toThrow()
  expect(calls).toBe(1)
  for (const response of [
    new Response("x".repeat(2 * 1024 * 1024 + 1)),
    new Response('{"a":1,"a":2}'),
    new Response("redirect", { status: 302 }),
  ]) {
    await expect(
      requestJSON("https://pushgate.dev/api/requirements", {}, new AbortController().signal, async () => response),
    ).rejects.toThrow()
  }
})

test("old route, malformed response, sign-in and mismatched target never become empty success", async () => {
  for (const [response, state] of [
    [new Response("old route", { status: 404 }), "unsupported"],
    [Response.json({}), "unavailable"],
    [Response.json({ ...snapshot, target: { ...target, ref: "refs/heads/other" } }), "unavailable"],
    [
      Response.json({ version: snapshot.version, state: "signin", code: "insufficient_scope" }, { status: 403 }),
      "signin",
    ],
  ] as const)
    expect(
      (await readRequirements(target, bearer(), new AbortController().signal, async () => response)).state,
    ).toBe(state)
})

test("an expired bearer is never sent and reads as unavailable", async () => {
  let called = false
  const result = await readRequirements(target, new Bearer("dedicated", Date.now() - 1), new AbortController().signal, async () => {
    called = true
    return new Response("{}")
  })
  expect(called).toBe(false)
  expect(result.state).toBe("unavailable")
})

test("a valid response that echoes the bearer anywhere is refused, never returned", async () => {
  const echo = "pgr_echo_probe_9a8b7c6d5e4f3a2b"
  const reply = (body: unknown) => async () => Response.json(body)
  const historical = {
    ...snapshot,
    last_decision: {
      state: "historical",
      current_status: "unavailable",
      assignment_match: "custom_releases_only",
      created_at: "2026-09-01T00:00:00Z",
      verdict: "accepted",
      checks: [{ name: "check", result: "pass", detail: `token was ${echo}` }],
    },
  }
  for (const body of [
    historical,
    { ...snapshot, builtins: [{ id: echo.slice(0, 64), mode: "block", availability: "supported" }] },
  ]) {
    const result = await readRequirements(target, new Bearer(echo, Date.now() + 60_000), new AbortController().signal, reply(body))
    expect(result.state).toBe("unavailable")
    expect(JSON.stringify(result)).not.toContain(echo)
  }
  // The same response with no echo is accepted, so the refusal is the echo, not the shape.
  const clean = { ...historical, last_decision: { ...historical.last_decision, checks: [{ name: "check", result: "pass", detail: "ok" }] } }
  expect((await readRequirements(target, new Bearer(echo, Date.now() + 60_000), new AbortController().signal, reply(clean))).state).toBe("available")
})
