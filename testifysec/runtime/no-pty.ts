// jade:ring local
// UAT probes compiled from testifysec/ can reach core's persistent-pty/pty-binding.ts, which resolves the
// platform's @opencode-ai/pty package when it loads. Inside a compiled binary that resolve fails, so the
// probe dies before it runs. packages/cli/script/build.ts replaces the module the same way when it embeds
// no PTY binary; the probes never start a PTY.
import type { BunPlugin } from "bun"

export const noPty: BunPlugin = {
  name: "no-pty-binary",
  setup(build) {
    build.onLoad({ filter: /persistent-pty[/\\]pty-binding\.ts$/ }, () => ({
      loader: "js",
      contents: "export default undefined",
    }))
  },
}
