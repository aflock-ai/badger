import { Plugin } from "@opencode/plugin/tui"
import { createEffect, createSignal, For, onCleanup, Show } from "solid-js"

/** The credential-free display a Requirements source sends; it never carries the bearer. */
export type RequirementsView = { state: string; lines: readonly string[]; details: readonly string[] }
export type RequirementsFeed = {
  subscribe(
    context: { session: string; directory: string; workspace?: string },
    emit: (value: RequirementsView) => void,
  ): () => void
}

export function SidebarRequirements(props: { context: Plugin.Context; sessionID: string; source: RequirementsFeed }) {
  const theme = props.context.theme
  const [view, setView] = createSignal<RequirementsView>({ state: "loading", lines: [], details: [] })
  // One subscription per session location; the source shares a monitor per context and stops it
  // when the last subscriber leaves.
  createEffect(() => {
    const location = props.context.data.session.get(props.sessionID)?.location
    if (!location) return
    const leave = props.source.subscribe({ session: props.sessionID, directory: location.directory }, setView)
    onCleanup(leave)
  })

  return (
    <Show when={view().state !== "disabled"}>
      <box>
        <text fg={theme.text.base}>
          <b>Requirements</b>
        </text>
        <For each={view().lines}>
          {(line) => (
            <text fg={view().state === "available" ? theme.text.muted : theme.text.feedback.warning.base}>{line}</text>
          )}
        </For>
      </box>
    </Show>
  )
}

/** The sidebar section, for a launch that signed in to Requirements. Remote text arrives sanitized. */
export function requirementsSidebar(source: RequirementsFeed) {
  return Plugin.define({
    id: "badger.sidebar.requirements",
    setup(context) {
      context.ui.slot({
        append: "sidebar.content",
        render: (props) => <SidebarRequirements context={context} sessionID={props.sessionID} source={source} />,
      })
    },
  })
}
