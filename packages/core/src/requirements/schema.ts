import z from "zod"

// A UAT build (`build.ts --fixture-requirements=<origin>`) points both origins at a local fixture
// server; every other build, and source, compiles the real ones. Never set in a release.
declare const TESTIFYSEC_FIXTURE_REQUIREMENTS: string
const fixture = typeof TESTIFYSEC_FIXTURE_REQUIREMENTS === "string" ? TESTIFYSEC_FIXTURE_REQUIREMENTS : ""
export const platform = fixture || "https://platform.testifysec.com"
export const edge = fixture || "https://pushgate.dev"
export const scopes = "pushgate:repo-read pushgate:policy-read"
const integer = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)
const text = (max: number) =>
  z
    .string()
    .max(max)
    .refine((s) => s.isWellFormed())
export const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const hex = z.string().regex(/^[0-9a-f]{64}$/)
export const numericID = z
  .string()
  .regex(/^[1-9][0-9]{0,18}$/)
  .refine((s) => BigInt(s) <= 9223372036854775807n)
export const repo = z
  .string()
  .max(300)
  .regex(/^github\.com\/[A-Za-z0-9_-][A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]+$/)
  .refine((s) => !s.split("/").some((p) => p === "." || p === ".."))
const timestamp = text(40)
  .datetime({ offset: true })
  .refine((s) => Number.isFinite(Date.parse(s)))
export const targetSchema = z
  .object({
    repo,
    repository_id: numericID,
    commit: z
      .string()
      .regex(/^[0-9a-f]{40}$/)
      .refine((s) => s !== "0".repeat(40)),
    ref: text(512)
      .regex(/^refs\/(heads|tags)\/.+/)
      .refine(
        (s) =>
          !/[\s\p{Cc}\p{Cf}~^:?*\[\\]/u.test(s) &&
          !s.includes("..") &&
          !s.includes("@{") &&
          !s.endsWith(".") &&
          s.split("/").every((p) => p.length > 0 && !p.startsWith(".") && !p.endsWith(".lock")),
      ),
  })
  .strict()
export type Target = z.infer<typeof targetSchema>
const mode = z.enum(["block", "warn"])
const availability = z.enum(["supported", "unsupported"])
const policy = z
  .object({
    definition_id: uuid,
    release_id: uuid,
    policy_gitoid: hex,
    policy_digest: hex,
    name: text(160),
    mode,
    availability,
    unavailable_reason: z
      .enum(["policy_missing", "policy_unreadable", "policy_malformed", "policy_unsupported", "policy_expired"])
      .nullable(),
    policy_view_url: text(200),
    summary: z
      .object({
        authoritative: z.literal(false),
        requirement_count: integer.max(100),
        requirements: z
          .array(
            z
              .object({
                kind: z.enum(["step_attestation", "external_attestation"]),
                step: text(160),
                attestation_type: text(300),
                rego_policy_count: integer,
                ai_policy_count: integer,
              })
              .strict(),
          )
          .max(100),
        not_fully_summarized: z.tuple([
          z.literal("signer_constraints"),
          z.literal("rego"),
          z.literal("timestamps"),
          z.literal("cross_step_dependencies"),
          z.literal("expiry"),
        ]),
      })
      .strict(),
  })
  .strict()
  .refine(
    (p) =>
      p.summary.requirement_count === p.summary.requirements.length &&
      (p.availability === "supported") === (p.unavailable_reason === null) &&
      p.policy_view_url === `${platform}/archivista/download/${p.policy_gitoid}`,
  )
const version = z.literal("pushgate.requirements.v1")
const failures = {
  invalid_query: [400, "unavailable"],
  signin_required: [401, "signin"],
  insufficient_scope: [403, "signin"],
  repository_not_authorized: [404, "unavailable"],
  method_not_allowed: [405, "unavailable"],
  assignment_stale: [409, "unavailable"],
  assignment_unavailable: [409, "unavailable"],
  upstream_api_unsupported: [503, "unsupported"],
  ...Object.fromEntries(
    [
      "platform_configuration_unavailable",
      "platform_unavailable",
      "platform_response_too_large",
      "repository_catalog_invalid",
      "repository_catalog_incomplete",
      "policy_response_invalid",
      "connection_unavailable",
      "invalid_assignment",
      "invalid_presets",
      "invalid_modes",
      "decision_invalid",
      "invalid_source",
      "requirements_unavailable",
    ].map((s) => [s, [503, "unavailable"]]),
  ),
} as Record<string, readonly [number, string]>
const responseSchema = z.union([
  z
    .object({
      version,
      state: z.literal("available"),
      target: targetSchema,
      assignment_source: z.literal("connection_snapshot"),
      applicability: z.literal("incomplete"),
      connection: z.object({ generation: integer, created_at: timestamp }).strict(),
      builtins: z.array(z.object({ id: text(64), mode, availability }).strict()).max(16),
      policies: z.array(policy).max(8),
      last_decision: z.union([
        z.object({ state: z.literal("none"), current_status: z.literal("unavailable") }).strict(),
        z
          .object({
            state: z.literal("historical"),
            current_status: z.literal("unavailable"),
            assignment_match: z.enum(["custom_releases_only", "different"]),
            created_at: timestamp,
            verdict: z.enum(["accepted", "refused"]),
            checks: z
              .array(
                z
                  .object({ name: text(160), result: z.enum(["pass", "fail", "skip", "warn"]), detail: text(1000) })
                  .strict(),
              )
              .max(100),
          })
          .strict(),
      ]),
    })
    .strict(),
  z
    .object({
      version,
      state: z.literal("disconnected"),
      code: z.literal("connection_not_found"),
      target: targetSchema,
    })
    .strict(),
  z.object({ version, state: z.enum(["signin", "unsupported", "unavailable"]), code: text(100) }).strict(),
])
export type Requirements = z.infer<typeof responseSchema>

export function sameTarget(a: Target, b: Target) {
  return a.repo === b.repo && a.repository_id === b.repository_id && a.commit === b.commit && a.ref === b.ref
}

export function parseResponse(value: unknown, target: Target, status: number): Requirements {
  targetSchema.parse(target)
  const result = responseSchema.parse(value)
  if ("target" in result) {
    if (status !== 200 || !sameTarget(result.target, target)) throw new Error("requirements-target")
    return result
  }
  const failure = Object.hasOwn(failures, result.code) ? failures[result.code] : undefined
  if (!failure || failure[0] !== status || failure[1] !== result.state) throw new Error("requirements-status")
  return result
}
