// The build fetches every platform's native packages so it can cross-compile. `--no-save` matters:
// `bun install <names>` otherwise saves them like `bun add` and rewrites package.json and the
// lockfile, so a build in a clean checkout would leave tracked files modified.
export function crossPlatformInstall(versions: { "@opentui/core": string; "@opencode-ai/pty": string }) {
  return [
    "bun",
    "install",
    "--no-save",
    "--os=*",
    "--cpu=*",
    `@opentui/core@${versions["@opentui/core"]}`,
    `@opencode-ai/pty@${versions["@opencode-ai/pty"]}`,
  ]
}
