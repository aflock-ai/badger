import { describe, expect } from "bun:test"
import { Document, Info, type Entry } from "@opencode/schema/config"
import { Effect, Exit, Schema } from "effect"
import { Config } from "@opencode/core/config"
import { ConfigNormalize } from "@opencode/core/config/normalize"
import { ConfigPolicyPlugin } from "@opencode/core/config/plugin/policy"
import { ConfigProviderPlugin } from "@opencode/core/config/plugin/provider"
import { Model } from "@opencode/core/model"
import { ModelResolver } from "@opencode/core/model-resolver"
import { Plugin } from "@opencode/core/plugin"
import { PluginHost } from "@opencode/core/plugin/host"
import { Provider } from "@opencode/core/provider"
import { SessionExecution } from "@opencode/core/session/execution"
import { SessionRunnerModel } from "@opencode/core/session/runner/model"
import { SessionSchema } from "@opencode/core/session/schema"
import { testEffect } from "./lib/effect"
import { PluginTestLayer } from "./plugin/fixture"

// Model selection must honor the configured model and the provider allow/deny lists, and refuse rather
// than fall back to some other model, in particular a keyless built-in one.
const it = testEffect(PluginTestLayer)

const gateway = Provider.ID.make("gw")
const approved = Model.ID.make("approved")
const builtin = Provider.ID.opencode
const free = Model.ID.make("free")

function document(input: Record<string, unknown>): Document {
  const result = ConfigNormalize.normalize({
    providers: {
      gw: {
        package: "@opencode/ai/providers/openai-compatible",
        settings: { baseURL: "https://gw.example/v1" },
        models: { approved: {}, retired: { disabled: true } },
      },
    },
    ...input,
  })
  if (result.type !== "normalized") throw new Error("expected normalized config")
  return new Document({
    type: "document",
    info: Schema.decodeUnknownSync(Info, { errors: "all", onExcessProperty: "ignore" })(result.encoded),
  })
}

// A keyless built-in provider is in the catalog before config applies, the way the bundled public one is.
const seedBuiltin = Effect.gen(function* () {
  const providers = yield* Provider.Service
  yield* providers.transform((editor) => {
    editor.update(builtin, (provider) => {
      provider.package = "@opencode/ai/providers/openai-compatible"
      provider.settings = { baseURL: "https://builtin.example/v1" }
    })
    editor.models.update(builtin, free, (model) => {
      model.time.released = Date.now()
    })
  })
})

const configure = Effect.fn(function* (entries: Entry[]) {
  yield* seedBuiltin
  const plugin = yield* Plugin.Service
  const host = yield* PluginHost.make(plugin)
  yield* ConfigProviderPlugin.Plugin.effect(host).pipe(Effect.provide(Config.testLayer(entries)))
  yield* ConfigPolicyPlugin.Plugin.effect(host).pipe(Effect.provide(Config.testLayer(entries)))
})

const resolveDefault = ModelResolver.Service.use((resolver) => resolver.resolve()).pipe(
  Effect.provide(ModelResolver.layer),
)

const resolveRequested = (providerID: Provider.ID, id: Model.ID) =>
  ModelResolver.Service.use((resolver) => resolver.resolve(Model.Ref.make({ providerID, id }))).pipe(
    Effect.provide(ModelResolver.layer),
  )

const session = (model?: { providerID: Provider.ID; id: Model.ID }) =>
  ({ id: SessionSchema.ID.make("ses_model_selection"), ...(model ? { model: Model.Ref.make(model) } : {}) }) as
    SessionSchema.Info

const resolveSession = (info: SessionSchema.Info) =>
  Effect.gen(function* () {
    const models = yield* Model.Service
    return yield* SessionRunnerModel.Service.use((runner) => runner.resolve(info, models.available))
  }).pipe(Effect.provide(SessionRunnerModel.layer), Effect.provide(ModelResolver.layer))

describe("model selection", () => {
  it.effect("a prompt with no model resolves to the configured model on the enabled provider", () =>
    Effect.gen(function* () {
      yield* configure([document({ model: "gw/approved", enabled_providers: ["gw"] })])
      expect((yield* resolveDefault)?.ref).toMatchObject({ providerID: gateway, id: approved })
      expect((yield* resolveSession(session())).ref).toMatchObject({ providerID: gateway, id: approved })
    }),
  )

  it.effect("a configured model the catalog does not have is refused, not replaced", () =>
    Effect.gen(function* () {
      yield* configure([document({ model: "gw/missing" })])
      const models = yield* Model.Service
      expect(yield* models.default()).toBeUndefined()
      expect(yield* resolveDefault.pipe(Effect.flip)).toMatchObject({
        _tag: "SessionRunnerModel.ConfiguredModelUnavailableError",
        providerID: gateway,
        modelID: Model.ID.make("missing"),
      })
      const refused = yield* resolveSession(session()).pipe(Effect.flip)
      expect(refused).toMatchObject({ _tag: "SessionRunnerModel.ConfiguredModelUnavailableError" })
      // The refusal ends the turn as a failed execution the client sees, not a silent drop.
      expect(SessionExecution.terminal(Exit.fail(refused))).toEqual({
        type: "failed",
        error: {
          type: "provider.no-route",
          message: "Configured model gw/missing is not available; refusing to use another model",
        },
      })
    }),
  )

  it.effect("a configured model on a provider outside enabled_providers is refused", () =>
    Effect.gen(function* () {
      yield* configure([document({ model: "opencode/free", enabled_providers: ["gw"] })])
      expect(yield* resolveDefault.pipe(Effect.flip)).toMatchObject({
        _tag: "SessionRunnerModel.ConfiguredModelUnavailableError",
        providerID: builtin,
      })
    }),
  )

  it.effect("a configured model on a disabled_providers entry is refused", () =>
    Effect.gen(function* () {
      yield* configure([document({ model: "gw/approved", disabled_providers: ["gw"] })])
      expect(yield* resolveDefault.pipe(Effect.flip)).toMatchObject({
        _tag: "SessionRunnerModel.ConfiguredModelUnavailableError",
        providerID: gateway,
      })
    }),
  )

  it.effect("a configured model that config disables is refused", () =>
    Effect.gen(function* () {
      yield* configure([document({ model: "gw/retired" })])
      expect(yield* resolveDefault.pipe(Effect.flip)).toMatchObject({
        _tag: "SessionRunnerModel.ConfiguredModelUnavailableError",
        modelID: Model.ID.make("retired"),
      })
    }),
  )

  it.effect("with no configured model, the choice stays inside enabled_providers", () =>
    Effect.gen(function* () {
      yield* configure([document({ enabled_providers: ["gw"] })])
      const models = yield* Model.Service
      expect((yield* models.available()).map((model) => model.providerID)).not.toContain(builtin)
      expect((yield* resolveDefault)?.ref.providerID).toBe(gateway)
    }),
  )

  it.effect("with nothing allowed, a prompt is refused instead of reaching a built-in provider", () =>
    Effect.gen(function* () {
      yield* configure([document({ enabled_providers: [] })])
      expect(yield* resolveDefault).toBeUndefined()
      expect(yield* resolveSession(session()).pipe(Effect.flip)).toMatchObject({
        _tag: "SessionRunnerModel.ModelNotSelectedError",
      })
    }),
  )

  it.effect("a session naming a provider outside enabled_providers is refused", () =>
    Effect.gen(function* () {
      yield* configure([document({ model: "gw/approved", enabled_providers: ["gw"] })])
      expect(yield* resolveSession(session({ providerID: builtin, id: free })).pipe(Effect.flip)).toMatchObject({
        _tag: "SessionRunnerModel.ModelUnavailableError",
        providerID: builtin,
      })
    }),
  )

  it.effect("an explicitly requested model that is denied or disabled does not resolve", () =>
    Effect.gen(function* () {
      yield* configure([document({ model: "gw/approved", enabled_providers: ["gw"] })])
      expect(yield* resolveRequested(builtin, free)).toBeUndefined()
      expect(yield* resolveRequested(gateway, Model.ID.make("retired"))).toBeUndefined()
      expect((yield* resolveRequested(gateway, approved))?.ref).toMatchObject({ providerID: gateway, id: approved })
    }),
  )
})
