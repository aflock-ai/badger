import { expect, test } from "bun:test"
import { ConnectCancelled, connect, signInNotice } from "@opencode/core/requirements/device"
import { platform, scopes } from "@opencode/core/requirements/schema"

test("independent device flow requests exactly read scopes, selects authoritative repository, persists only after selection", async () => {
  const seen: string[] = []
  const result = await connect({
    directory: "/work",
    signal: new AbortController().signal,
    wait: async () => {},
    onCode: async (url, userCode) => {
      expect(url).toBe(`${platform}/auth/cli/device?user_code=ABCD-EFGH`)
      expect(userCode).toBe("ABCD-EFGH")
    },
    select: async (repos) => {
      expect(repos).toEqual([{ repo: "github.com/acme/project", repository_id: "123" }])
      return 0
    },
    send: async (url, init) => {
      seen.push(url)
      expect(init.redirect).toBe("error")
      if (url.endsWith("/code")) {
        expect(JSON.parse(String(init.body))).toEqual({ client_id: "badger-requirements", scope: scopes })
        return Response.json({
          device_code: "secret-device",
          user_code: "ABCD-EFGH",
          verification_uri: `${platform}/auth/cli/device`,
          verification_uri_complete: `${platform}/auth/cli/device?user_code=ABCD-EFGH`,
          expires_in: 600,
          interval: 1,
        })
      }
      if (url.endsWith("/token"))
        return Response.json({ access_token: "new-dedicated", token_type: "Bearer", expires_in: 3600, scope: scopes })
      expect(new Headers(init.headers).get("Authorization")).toBe("Bearer new-dedicated")
      return Response.json({
        tenant_id: "11111111-1111-4111-8111-111111111111",
        github_app_connected: true,
        partial: false,
        repositories: [
          {
            id: "github.com/acme/project",
            repository_id: "123",
            full_name: "acme/project",
            clone_url: "https://github.com/acme/project.git",
            private: true,
            installation_id: "456",
            account_login: "acme",
            account_type: "Organization",
          },
        ],
      })
    },
  })
  expect(result.selection).toEqual({
    version: 1,
    enabled: true,
    directory: "/work",
    repo: "github.com/acme/project",
    repository_id: "123",
  })
  expect(result.bearer.authorization()).toBe("Bearer new-dedicated")
  expect(seen).toEqual([
    `${platform}/oauth/device/code`,
    `${platform}/oauth/device/token`,
    `${platform}/api/pushgate/repositories`,
  ])
})

test("device URI redirection is rejected before approval", async () => {
  let opened = false
  await expect(
    connect({
      directory: "/work",
      signal: new AbortController().signal,
      onCode: async () => {
        opened = true
      },
      select: async () => 0,
      send: async () =>
        Response.json({
          device_code: "secret",
          user_code: "ABCD-EFGH",
          verification_uri: "https://evil.test",
          verification_uri_complete: "https://evil.test",
          expires_in: 600,
          interval: 1,
        }),
    }),
  ).rejects.toThrow("Requirements connection failed")
  expect(opened).toBe(false)
})

test("missing or broader granted scopes never reach repository selection or credential storage", async () => {
  for (const scope of [undefined, "*", "pushgate:repo-read", `${scopes} sign:policy`]) {
    let selected = false
    let calls = 0
    await expect(
      connect({
        directory: "/work",
        signal: new AbortController().signal,
        wait: async () => {},
        onCode: async () => {},
        select: async () => {
          selected = true
          return 0
        },
        send: async () => {
          calls++
          return Response.json(
            calls === 1
              ? {
                  device_code: "secret",
                  user_code: "ABCD-EFGH",
                  verification_uri: `${platform}/auth/cli/device`,
                  verification_uri_complete: `${platform}/auth/cli/device?user_code=ABCD-EFGH`,
                  expires_in: 600,
                  interval: 1,
                }
              : { access_token: "never-leak-this", token_type: "Bearer", expires_in: 3600, scope },
          )
        },
      }),
    ).rejects.toThrow("Requirements connection failed")
    expect(calls).toBe(2)
    expect(selected).toBe(false)
  }
})

const code = {
  device_code: "secret-device",
  user_code: "ABCD-EFGH",
  verification_uri: `${platform}/auth/cli/device`,
  verification_uri_complete: `${platform}/auth/cli/device?user_code=ABCD-EFGH`,
  expires_in: 600,
  interval: 1,
}
const token = { access_token: "never-leak-this", token_type: "Bearer", expires_in: 3600, scope: scopes }
const entry = (repository_id: string) => ({
  id: "github.com/acme/project",
  repository_id,
  full_name: "acme/project",
  clone_url: "https://github.com/acme/project.git",
  private: true,
  installation_id: "456",
  account_login: "acme",
  account_type: "Organization",
})
const catalog = (patch: object) => ({
  tenant_id: "11111111-1111-4111-8111-111111111111",
  github_app_connected: true,
  partial: false,
  repositories: [entry("123")],
  ...patch,
})

async function failure(
  reply: (url: string) => Response,
  select: () => Promise<number> = async () => 0,
  signal = new AbortController().signal,
) {
  const error = await connect({
    directory: "/work",
    signal,
    wait: async () => {},
    onCode: async () => {},
    select,
    send: async (url) => reply(url),
  }).then(
    () => undefined,
    (error: Error) => error,
  )
  expect(error).toBeInstanceOf(Error)
  expect(error!.message).toStartWith("Requirements connection failed")
  expect(error!.message).toContain("No credential was saved")
  for (const leak of ["secret-device", "never-leak-this", "SERVER-PROSE", "evil.test"])
    expect(error!.message).not.toContain(leak)
  return error!.message
}

const route = (token: object | Response, list?: object | Response) => (url: string) => {
  if (url.endsWith("/code")) return Response.json(code)
  if (url.endsWith("/token")) return token instanceof Response ? token : Response.json(token)
  return list instanceof Response ? list : Response.json(list)
}
const oauthError = (error: string) =>
  Response.json({ error, error_description: "SERVER-PROSE https://evil.test" }, { status: 400 })

test("known connect failures give a fixed local reason without server prose", async () => {
  const cases: [string, Promise<string>][] = [
    [
      "platform sign-in service is unavailable",
      failure(() => Response.json({ error: "SERVER-PROSE" }, { status: 503 })),
    ],
    ["denied or refused in the browser", failure(route(oauthError("access_denied")))],
    ["code expired before it was approved", failure(route(oauthError("expired_token")))],
    ["catalog could not be read", failure(route(token, Response.json({ error: "SERVER-PROSE" }, { status: 500 })))],
    ["source-control integration is not connected", failure(route(token, catalog({ github_app_connected: false })))],
    ["no repositories are authorized", failure(route(token, catalog({ repositories: [] })))],
    ["conflicting IDs for one repository", failure(route(token, catalog({ repositories: [entry("1"), entry("2")] })))],
    ["No repository was selected", failure(route(token, catalog({})), async () => 7)],
    [
      "Connection cancelled.",
      failure(route(token, catalog({})), async () => {
        throw new ConnectCancelled()
      }),
    ],
  ]
  for (const [reason, message] of cases) expect(await message).toContain(reason)
})

test("an aborted sign-in reports cancellation, not code expiry", async () => {
  const controller = new AbortController()
  controller.abort()
  expect(await failure(route(token, catalog({})), undefined, controller.signal)).toContain("Connection cancelled.")
})

test("unclassified failures keep the generic retry message", async () => {
  const message = await failure(route({ ...token, scope: "*" }), undefined)
  expect(message).toBe(
    "Requirements connection failed. No credential was saved; retry independent sign-in from a terminal.",
  )
  const thrown = await failure(route(token, catalog({})), async () => {
    throw new Error("SERVER-PROSE")
  })
  expect(thrown).toContain("retry independent sign-in")
})

test("sign-in notice always carries the verification URL and the code to confirm", () => {
  const url = `${platform}/auth/cli/device?user_code=ABCD-EFGH`
  const notice = signInNotice(url, "ABCD-EFGH")
  expect(notice).toContain(url)
  expect(notice).toContain("code ABCD-EFGH")
  expect(notice.endsWith("\n")).toBe(true)
})

test("each slow_down adds five seconds to the poll interval, even past a minute", async () => {
  const waits: number[] = []
  const replies = [oauthError("slow_down"), oauthError("slow_down"), Response.json(token)]
  await connect({
    directory: "/work",
    signal: new AbortController().signal,
    wait: async (ms) => {
      waits.push(ms)
    },
    onCode: async () => {},
    select: async () => 0,
    send: async (url) => {
      if (url.endsWith("/code")) return Response.json({ ...code, interval: 60 })
      if (url.endsWith("/token")) return replies.shift()!
      return Response.json(catalog({}))
    },
  })
  expect(waits).toEqual([60_000, 65_000, 70_000])
})
