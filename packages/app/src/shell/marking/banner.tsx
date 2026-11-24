import { createEffect, createSignal, onCleanup, Show, type Accessor } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { ServerConnection } from "@/runtime/server/registry"
import { useGlobal } from "@/runtime/server/runtime"
import { bannerText, type BannerMarking } from "./combine"
import { MarkingReads, type ServerState } from "./reads"
import "./banner.css"

/**
 * The marking banner for this window: every healthy server's deployment marking and workspace
 * label, combined. A server's marking is read while its event connection is up, read again after it
 * reconnects, so a server that restarts with a higher marking is never shown under its old one, and
 * read again each time it announces that its label rose (marking.label.raised).
 */
export function useBannerMarking(): Accessor<BannerMarking> {
  const global = useGlobal()
  const [version, setVersion] = createSignal(0)
  const [servers, setServers] = createSignal<ServerState<ServerConnection.Key>[]>([])

  const reads = MarkingReads.make(
    (key: ServerConnection.Key) => {
      const ctx = global.serverCtx(key)

      if (!ctx) return Promise.reject(new Error("server unavailable"))

      return ctx.sdk.api.server
        .marking()
        .then((policy) => ({ marking: policy.marking, scheme: policy.scheme, label: policy.label }))
    },
    () => setVersion((value) => value + 1),
  )

  // One raise subscription per server shown, on its current event source, dropped when it leaves.
  const raises = new Map<ServerConnection.Key, { readonly source: object; readonly stop: VoidFunction }>()
  onCleanup(() => {
    for (const raise of raises.values()) raise.stop()
    raises.clear()
  })

  createEffect(() => {
    const healthy = global.servers
      .list()
      .map((conn) => ServerConnection.key(conn))
      .filter((key) => global.servers.health[key]?.healthy)
      .map((key): ServerState<ServerConnection.Key> => {
        const ctx = global.serverCtx(key)

        return { key, live: ctx ? ctx.sdk.connection.status() === "connected" : true }
      })

    for (const [key, raise] of raises)
      if (global.serverCtx(key)?.sdk.event !== raise.source || !healthy.some((server) => server.key === key)) {
        raise.stop()
        raises.delete(key)
      }
    for (const { key } of healthy) {
      const source = global.serverCtx(key)?.sdk.event
      if (!source || raises.has(key)) continue
      raises.set(key, { source, stop: source.on("marking.label.raised", () => reads.refresh(key)) })
    }

    reads.sync(healthy)
    setServers(healthy)
  })

  return () => {
    version()

    return reads.marking(servers())
  }
}

export function MarkingBanner(props: { marking: BannerMarking }) {
  const language = useLanguage()
  const text = () => bannerText(props.marking, (key) => language.t(key))

  return (
    <Show when={text()}>
      {(value) => (
        <div class="classification-banner" data-marking-banner role="note" aria-label={language.t("classification.banner")}>
          {value()}
        </div>
      )}
    </Show>
  )
}
