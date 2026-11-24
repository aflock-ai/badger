import path from "path"

/**
 * The environment every core test runs in: a throwaway home with its XDG roots and temp directory
 * inside it, opencode config pointed there, and provider credentials scrubbed. Shared by
 * script/test.ts (which spawns the suite in it) and the preload (which applies it to a plain
 * `bun test` run that did not come through the script).
 */
export function isolatedEnvironment(source: Record<string, string | undefined>, home: string) {
  const temporary = path.join(home, "tmp")
  return {
    ...Object.fromEntries(
      Object.entries(source).filter(([name]) => {
        if (source.RECORD === "true" && name === "OPENAI_API_KEY") return true
        if (
          /^(?:AWS|AZURE|GOOGLE|GCP|GCLOUD|VERTEX|OPENAI|ANTHROPIC|GEMINI|XAI|CLOUDFLARE|CF_AIG|SNOWFLAKE|AICORE|GITLAB|NPM_CONFIG)_/i.test(
            name,
          )
        ) {
          return false
        }
        return !/(?:^|_)(?:API_KEY|AUTHORIZATION|TOKEN|SECRET|PASSWORD|CREDENTIALS?)$/i.test(name)
      }),
    ),
    HOME: home,
    OPENCODE_TEST_HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    XDG_STATE_HOME: path.join(home, ".local", "state"),
    OPENCODE_CONFIG_DIR: path.join(home, ".config", "opencode"),
    OPENCODE_CONFIG: undefined,
    OPENCODE_CONFIG_CONTENT: undefined,
    TMPDIR: temporary,
    ...(process.platform === "win32" ? { USERPROFILE: home, TMP: temporary, TEMP: temporary } : {}),
  } as Record<string, string | undefined>
}
