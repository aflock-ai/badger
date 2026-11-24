import { RGBA } from "@opentui/core"
import { useRenderer } from "@opentui/solid"
import { createMemo, createSignal, For, onCleanup, type Accessor, type JSX } from "solid-js"
import {
  ARTWORK_CLEARANCE,
  badgerAnsiPalette,
  badgerCapabilities,
  badgerLayout,
  badgerPalette,
  badgerRows,
} from "./badger-layout"

/** The space left for the welcome art after the prompt and footer are laid out. */
export function WelcomeSpace(props: { children: (size: Accessor<{ width: number; height: number }>) => JSX.Element }) {
  const [size, setSize] = createSignal({ width: 0, height: 0 })
  return (
    <box
      width="100%"
      // Two shares of the free height to the one below the prompt: the art keeps its clearance
      // in a 29-row editor panel instead of dropping to the one-line fallback.
      flexGrow={2}
      flexBasis={0}
      minHeight={0}
      overflow="hidden"
      alignItems="center"
      justifyContent="center"
      onSizeChange={function () {
        setSize({ width: this.width, height: this.height })
      }}
    >
      {props.children(size)}
    </box>
  )
}

/** The Badger welcome art, sized to the space it is given and the terminal's capabilities. */
export function BadgerWelcome(props: { width: number; height: number }) {
  const renderer = useRenderer()
  const [capabilities, setCapabilities] = createSignal(renderer.capabilities)
  const update = () => setCapabilities(renderer.capabilities)
  renderer.on("capabilities", update)
  onCleanup(() => renderer.off("capabilities", update))
  const caps = createMemo(() => badgerCapabilities(process.stdout.isTTY, capabilities(), process.env))
  const layout = createMemo(() => badgerLayout(props.width, props.height, caps()))
  const rows = createMemo(() => badgerRows(layout()))
  const palette = createMemo(() =>
    caps().color === "ansi256"
      ? badgerAnsiPalette.map((index) => RGBA.fromIndex(index))
      : badgerPalette.map((color) => RGBA.fromHex(color)),
  )
  const art = createMemo(() => layout().kind !== "line" && layout().kind !== "hidden")
  return (
    <box flexShrink={0} paddingTop={art() ? ARTWORK_CLEARANCE : 0}>
      <box
        width={layout().width}
        height={layout().height}
        flexShrink={0}
        overflow="hidden"
        backgroundColor={art() ? palette()[0] : undefined}
      >
        <For each={rows()}>
          {(row) => (
            <text height={1} wrapMode="none" selectable={false}>
              <For each={row}>
                {(run) => (
                  <span
                    style={{
                      fg: run.fg === undefined ? undefined : palette()[run.fg],
                      bg:
                        run.bg === undefined
                          ? layout().kind === "line"
                            ? undefined
                            : palette()[0]
                          : palette()[run.bg],
                    }}
                  >
                    {run.text}
                  </span>
                )}
              </For>
            </text>
          )}
        </For>
      </box>
    </box>
  )
}
