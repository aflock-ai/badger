import { Argument, Flag, GlobalFlag } from "effect/cli"
import { Schema } from "effect"
import { CliBrand } from "../brand"
import { Spec } from "../framework/spec"
import { Updater } from "../services/updater"
import { trustModes } from "../../../../testifysec/commands/trust-mode"

export const PrintLogs = GlobalFlag.Setting("print-logs")({
  flag: Flag.Boolean("print-logs").pipe(
    Flag.withDescription("Print logs to stderr (server logs require --standalone)"),
    Flag.withDefault(false),
  ),
})

const ServerParams = {
  standalone: Flag.Boolean("standalone").pipe(
    Flag.withDescription("Run with a private server instead of the background service"),
    Flag.withDefault(false),
  ),
  server: Flag.String("server").pipe(
    Flag.withDescription("Connect to a server URL instead of the background service"),
    Flag.optional,
  ),
}

const RequirementsParams = {
  // Unset: as this directory chose before. --requirements opts in; --no-requirements opts out.
  requirements: Flag.Boolean("requirements").pipe(
    Flag.withDescription(
      "Sign in to Pushgate Requirements and choose this directory's repository (--no-requirements: stop)",
    ),
    Flag.optional,
  ),
}

const PermissionParams = {
  auto: Flag.Boolean("auto").pipe(
    Flag.withDescription("Auto-approve permissions that are not explicitly denied"),
    Flag.withDefault(false),
  ),
  yolo: Flag.Boolean("yolo").pipe(Flag.withDefault(false), Flag.withHidden),
  dangerouslySkipPermissions: Flag.Boolean("dangerously-skip-permissions").pipe(
    Flag.withDefault(false),
    Flag.withHidden,
  ),
}

// Enrollment and attestation, as in 1.x: only in a branded build. The help names no vendor.
const AttestationParams = {
  trustMode: Flag.Literals("trust-mode", trustModes).pipe(
    Flag.withDescription("trust mode (AFLOCK_TRUST_MODE, user settings, then platform)"),
    Flag.optional,
  ),
  settings: Flag.String("settings").pipe(
    Flag.withDescription("operator settings file (default: user Badger settings)"),
    Flag.optional,
  ),
  platform: Flag.String("platform").pipe(Flag.withDescription("attestation platform HTTPS origin"), Flag.optional),
  stateDir: Flag.String("state-dir").pipe(Flag.withDescription("private Badger state directory"), Flag.optional),
}

const Root = Spec.make(CliBrand.name, {
  description: CliBrand.description,
  params: {
    ...ServerParams,
    ...PermissionParams,
    ...RequirementsParams,
    directory: Argument.String("directory").pipe(
      Argument.withDescription(CliBrand.directory),
      Argument.optional,
    ),
    continue: Flag.Boolean("continue").pipe(
      Flag.withAlias("c"),
      Flag.withDescription("Continue the last session"),
      Flag.withDefault(false),
    ),
    session: Flag.String("session").pipe(
      Flag.withAlias("s"),
      Flag.withDescription("Session ID to continue, or to create if it does not exist"),
      Flag.optional,
    ),
    prompt: Flag.String("prompt").pipe(Flag.withDescription("Prompt to use"), Flag.optional),
  },
  commands: [
    Spec.make("about", { description: CliBrand.aboutDescription }),
    Spec.make("enroll", {
      description: "enroll this Badger agent with the attestation platform",
      when: CliBrand.attestation,
      params: {
        ...AttestationParams,
        name: Flag.String("name").pipe(
          Flag.withDescription("agent name proposed in the platform ceremony"),
          Flag.optional,
        ),
        repository: Flag.String("repository").pipe(
          Flag.withDescription("repository proposed in the platform ceremony (owner/repository)"),
          Flag.optional,
        ),
        ttlSeconds: Flag.Int("ttl-seconds").pipe(
          Flag.withDescription("proposed platform enrollment lifetime"),
          Flag.optional,
        ),
        browser: Flag.Boolean("browser").pipe(
          Flag.withDescription("open the enrollment browser (--no-browser requires an interactive terminal)"),
          Flag.withDefault(true),
        ),
        json: Flag.Boolean("json").pipe(
          Flag.withDescription("emit public command events as JSONL (ceremony link omitted)"),
          Flag.withDefault(false),
        ),
      },
    }),
    Spec.make("attest", {
      description: "sign finalized session evidence and upload it to the attestation platform",
      when: CliBrand.attestation,
      params: {
        ...AttestationParams,
        session: Flag.String("session").pipe(
          Flag.withDescription("finalized session identifier (default: current workspace's finalized session)"),
          Flag.optional,
        ),
        json: Flag.Boolean("json").pipe(
          Flag.withDescription("emit public command events as JSONL"),
          Flag.withDefault(false),
        ),
      },
    }),
    Spec.make("upgrade", {
      description: "Upgrade OpenCode to the latest or a specific version",
      aliases: ["update"],
      params: {
        target: Argument.String("target").pipe(
          Argument.withDescription("Version to upgrade to (with or without a leading v)"),
          Argument.optional,
        ),
        method: Flag.Literals("method", Updater.methods).pipe(
          Flag.withAlias("m"),
          Flag.withDescription("Installation method to use"),
          Flag.optional,
        ),
      },
    }),
    Spec.make("uninstall", {
      description: "Uninstall OpenCode, keeping session data, configuration, and state",
      params: {
        dryRun: Flag.Boolean("dry-run").pipe(
          Flag.withDescription("Show what would be removed without removing"),
          Flag.withDefault(false),
        ),
        force: Flag.Boolean("force").pipe(
          Flag.withAlias("f"),
          Flag.withDescription("Skip confirmation prompts"),
          Flag.withDefault(false),
        ),
      },
    }),
    Spec.make("acp", {
      description: "Start an Agent Client Protocol server",
      params: {
        login: Flag.Boolean("login").pipe(
          Flag.withDescription("Run auth login instead of starting the server"),
          Flag.withDefault(false),
        ),
      },
    }),
    Spec.make("api", {
      description: "Make a request to the running server",
      params: {
        ...ServerParams,
        request: Argument.String("operation | method path").pipe(
          Argument.withDescription("OpenAPI operation ID, or an HTTP method followed by a path"),
          Argument.variadic({ min: 1, max: 2 }),
        ),
        data: Flag.String("data").pipe(Flag.withAlias("d"), Flag.withDescription("Request body"), Flag.optional),
        header: Flag.String("header").pipe(
          Flag.withAlias("H"),
          Flag.withDescription("Request header in name:value form"),
          Flag.atMost(100),
        ),
        param: Flag.KeyValuePair("param").pipe(Flag.withDescription("OpenAPI path or query parameter"), Flag.optional),
      },
    }),
    Spec.make("debug", {
      description: "Debugging and troubleshooting tools",
      commands: [
        Spec.make("agents", { description: "List all agents" }),
        Spec.make("config", { description: "List configuration sources" }),
        Spec.make("paths", {
          description: "Show global paths (data, config, cache, state)",
          params: {
            name: Argument.Literals("name", [
              "db",
              "home",
              "data",
              "config",
              "cache",
              "state",
              "tmp",
              "bin",
              "log",
              "repos",
            ]).pipe(
              Argument.withDescription(
                "Print only one path: db, home, data, config, cache, state, tmp, bin, log, repos",
              ),
              Argument.optional,
            ),
          },
        }),
      ],
    }),
    Spec.make("auth", {
      description: "manage integrations and credentials",
      commands: [
        Spec.make("list", {
          description: "list integrations and credentials",
          params: {
            ...ServerParams,
            format: Flag.Literals("format", ["default", "json"]).pipe(
              Flag.withDescription("Output format"),
              Flag.withDefault("default"),
            ),
          },
        }),
        Spec.make("login", {
          description: "connect an integration",
          params: {
            ...ServerParams,
            target: Argument.String("target").pipe(
              Argument.withDescription("Integration ID, name, or well-known provider URL"),
              Argument.optional,
            ),
            method: Flag.String("method").pipe(Flag.withDescription("Authentication method ID"), Flag.optional),
            answer: Flag.String("answer").pipe(
              Flag.withDescription("Provider form answer (key=value; repeat for multiple fields)"),
              Flag.atMost(100),
            ),
          },
        }),
        Spec.make("logout", {
          description: "log out of a saved account",
          params: {
            ...ServerParams,
            target: Argument.String("target").pipe(
              Argument.withDescription("Integration ID or name"),
              Argument.optional,
            ),
            credential: Argument.String("credential").pipe(
              Argument.withDescription("Credential ID or label (opens an account picker when omitted)"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("export", {
          description: "print stored credentials, including secrets, as JSON",
          params: {
            ...ServerParams,
            target: Argument.String("target").pipe(
              Argument.withDescription("Integration ID or name (exports every integration when omitted)"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("import", {
          description: "import credentials exported by auth export",
          params: {
            ...ServerParams,
            file: Argument.String("file").pipe(
              Argument.withDescription("JSON file to import (reads stdin when omitted)"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("switch", {
          description: "switch the active account for an integration",
          params: {
            ...ServerParams,
            target: Argument.String("target").pipe(
              Argument.withDescription("Integration ID or name"),
              Argument.optional,
            ),
            credential: Argument.String("credential").pipe(
              Argument.withDescription("Credential ID or label (opens an account picker when omitted)"),
              Argument.optional,
            ),
          },
        }),
      ],
    }),
    Spec.make("mcp", {
      description: "Manage MCP (Model Context Protocol) servers",
      commands: [
        Spec.make("list", { description: "List configured MCP servers and their status" }),
        Spec.make("add", {
          description: "Add an MCP server to your configuration",
          params: {
            name: Argument.String("name").pipe(Argument.withDescription("Name of the MCP server")),
            command: Argument.String("command").pipe(
              Argument.withDescription("Command and arguments for a local server, passed after --"),
              Argument.variadic({ min: 0 }),
            ),
            url: Flag.String("url").pipe(Flag.withDescription("URL for a remote MCP server"), Flag.optional),
            header: Flag.KeyValuePair("header").pipe(
              Flag.withDescription("HTTP header for a remote server, as name=value"),
              Flag.optional,
            ),
            env: Flag.KeyValuePair("env").pipe(
              Flag.withDescription("Environment variable for a local server, as name=value"),
              Flag.optional,
            ),
            global: Flag.Boolean("global").pipe(
              Flag.withDescription("Write to the global config instead of the project config"),
              Flag.withDefault(false),
            ),
          },
        }),
        Spec.make("auth", {
          description: "Authenticate with an OAuth-capable remote MCP server",
          params: {
            name: Argument.String("name").pipe(Argument.withDescription("Name of the MCP server"), Argument.optional),
          },
        }),
        Spec.make("logout", {
          description: "Remove stored OAuth credentials for an MCP server",
          params: { name: Argument.String("name").pipe(Argument.withDescription("Name of the MCP server")) },
        }),
      ],
    }),
    Spec.make("plugin", {
      description: "Manage plugins",
      commands: [
        Spec.make("list", {
          description: "List plugins",
          params: {
            builtin: Flag.Boolean("builtin").pipe(
              Flag.withDescription("Include built-in server plugins"),
              Flag.withDefault(false),
            ),
          },
        }),
        Spec.make("add", {
          description: "Install a plugin and add it to the global configuration",
          params: {
            package: Argument.String("package").pipe(Argument.withDescription("npm registry or Git package specifier")),
          },
        }),
        Spec.make("check", {
          description: "Check package plugins for updates",
          params: {
            target: Argument.String("target").pipe(
              Argument.withDescription("Configured package target"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("update", {
          description: "Update package plugins",
          params: {
            target: Argument.String("target").pipe(
              Argument.withDescription("Configured package target; omit to update all outdated plugins"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("remove", {
          description: "Remove a plugin from global configuration",
          params: {
            package: Argument.String("package").pipe(Argument.withDescription("configured package specifier")),
          },
        }),
      ],
    }),
    Spec.make("models", {
      description: "List all available models",
      params: ServerParams,
    }),
    Spec.make("stats", {
      description: "Show shareable usage statistics",
      params: {
        ...ServerParams,
        days: Flag.Int("days").pipe(
          Flag.withSchema(Schema.Int.check(Schema.isGreaterThanOrEqualTo(0))),
          Flag.withDescription("Show the last N days; 0 means today"),
          Flag.optional,
        ),
        year: Flag.Int("year").pipe(
          Flag.withSchema(Schema.Int.check(Schema.isBetween({ minimum: 1970, maximum: 9_999 }))),
          Flag.withDescription("Show a calendar year"),
          Flag.optional,
        ),
        all: Flag.Boolean("all").pipe(Flag.withDescription("Show lifetime statistics"), Flag.withDefault(false)),
        project: Flag.String("project").pipe(
          Flag.withDescription('Filter by project ID, or use "." for the current project'),
          Flag.optional,
        ),
        models: Flag.Boolean("models").pipe(Flag.withDescription("Show model usage"), Flag.withDefault(false)),
        tools: Flag.Boolean("tools").pipe(Flag.withDescription("Show tool reliability"), Flag.withDefault(false)),
        cost: Flag.Boolean("cost").pipe(Flag.withDescription("Show cost and token details"), Flag.withDefault(false)),
        full: Flag.Boolean("full").pipe(Flag.withDescription("Show every detailed section"), Flag.withDefault(false)),
        limit: Flag.Int("limit").pipe(
          Flag.withSchema(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1))),
          Flag.withDescription("Number of rows in detailed sections"),
          Flag.withDefault(5),
        ),
        json: Flag.Boolean("json").pipe(Flag.withDescription("Output statistics as JSON"), Flag.withDefault(false)),
      },
    }),
    Spec.make("mini", {
      description: "Start the minimal interactive interface",
      params: {
        ...ServerParams,
        continue: Flag.Boolean("continue").pipe(
          Flag.withAlias("c"),
          Flag.withDescription("Continue the last session"),
          Flag.withDefault(false),
        ),
        session: Flag.String("session").pipe(
          Flag.withAlias("s"),
          Flag.withDescription("Session ID to continue, or to create if it does not exist"),
          Flag.optional,
        ),
        fork: Flag.Boolean("fork").pipe(
          Flag.withDescription("Fork the session when continuing"),
          Flag.withDefault(false),
        ),
        replay: Flag.Boolean("replay").pipe(
          Flag.withDescription("Restore session history on resume and resize (disable with --no-replay)"),
          Flag.optional,
        ),
        replayLimit: Flag.Int("replay-limit").pipe(
          Flag.withDescription("Limit replay to the newest N messages (default: 200)"),
          Flag.optional,
        ),
        model: Flag.String("model").pipe(
          Flag.withAlias("m"),
          Flag.withDescription("Model to use in the format provider/model"),
          Flag.optional,
        ),
        agent: Flag.String("agent").pipe(Flag.withDescription("Agent to use"), Flag.optional),
        prompt: Flag.String("prompt").pipe(Flag.withDescription("Prompt to use"), Flag.optional),
        demo: Flag.Boolean("demo").pipe(Flag.withDefault(false), Flag.withHidden),
      },
    }),
    Spec.make("run", {
      description: "Run OpenCode with a message",
      params: {
        ...ServerParams,
        ...RequirementsParams,
        message: Argument.String("message").pipe(
          Argument.withDescription("Message to send"),
          Argument.variadic({ min: 0 }),
        ),
        continue: Flag.Boolean("continue").pipe(
          Flag.withAlias("c"),
          Flag.withDescription("Continue the last session"),
          Flag.withDefault(false),
        ),
        session: Flag.String("session").pipe(
          Flag.withAlias("s"),
          Flag.withDescription("Session ID to continue, or to create if it does not exist"),
          Flag.optional,
        ),
        fork: Flag.Boolean("fork").pipe(
          Flag.withDescription("Fork the session before continuing"),
          Flag.withDefault(false),
        ),
        model: Flag.String("model").pipe(
          Flag.withAlias("m"),
          Flag.withDescription("Model to use in the format provider/model#variant"),
          Flag.optional,
        ),
        agent: Flag.String("agent").pipe(Flag.withDescription("Agent to use"), Flag.optional),
        format: Flag.Literals("format", ["default", "json"]).pipe(
          Flag.withDescription("Output format"),
          Flag.withDefault("default"),
        ),
        file: Flag.String("file").pipe(
          Flag.withAlias("f"),
          Flag.withDescription("File to attach to the message"),
          Flag.atMost(100),
        ),
        title: Flag.String("title").pipe(Flag.withDescription("Session title"), Flag.optional),
        thinking: Flag.Boolean("thinking").pipe(Flag.withDescription("Show thinking blocks"), Flag.withDefault(false)),
        ...PermissionParams,
      },
    }),
    Spec.make("session", {
      description: "Manage sessions",
      commands: [
        Spec.make("list", {
          description: "List top-level sessions in the current project, newest first",
          params: {
            ...ServerParams,
            maxCount: Flag.Int("max-count").pipe(
              Flag.withAlias("n"),
              Flag.withSchema(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1))),
              Flag.withDescription("Limit to N most recent sessions (default: 100)"),
              Flag.optional,
            ),
            format: Flag.Literals("format", ["table", "json"]).pipe(
              Flag.withDescription("Output format"),
              Flag.withDefault("table"),
            ),
          },
        }),
        Spec.make("delete", {
          description: "Delete a session and its child sessions",
          params: {
            ...ServerParams,
            sessionID: Argument.String("sessionID").pipe(Argument.withDescription("Session ID to delete")),
          },
        }),
        Spec.make("export", {
          description: "Export session data as JSON",
          params: {
            ...ServerParams,
            session: Argument.String("session").pipe(
              Argument.withDescription("Session ID to export"),
              Argument.optional,
            ),
            sanitize: Flag.Boolean("sanitize").pipe(
              Flag.withDescription("Redact sensitive transcript and file data"),
              Flag.withDefault(false),
            ),
          },
        }),
        Spec.make("import", {
          description: "Import session data from a JSON file or URL",
          params: {
            ...ServerParams,
            file: Argument.String("file").pipe(Argument.withDescription("JSON file or URL to import")),
            directory: Flag.String("directory").pipe(
              Flag.withDescription("Directory in which to import the session"),
              Flag.optional,
            ),
          },
        }),
      ],
    }),
    Spec.make("service", {
      description: "Manage the background server",
      commands: [
        Spec.make("start", { description: "Start the background server" }),
        Spec.make("restart", { description: "Restart the background server" }),
        Spec.make("status", { description: "Show background server status" }),
        Spec.make("stop", { description: "Stop the background server" }),
        Spec.make("get", {
          description: "Get service configuration",
          params: {
            key: Argument.String("key").pipe(Argument.withDescription("Service setting or env"), Argument.optional),
            name: Argument.String("name").pipe(
              Argument.withDescription("Environment variable name"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("set", {
          description: "Set service configuration",
          params: {
            key: Argument.String("key").pipe(Argument.withDescription("Service setting or env")),
            value: Argument.String("value").pipe(
              Argument.withDescription("Setting value or environment variable name"),
            ),
            nestedValue: Argument.String("env-value").pipe(
              Argument.withDescription("Environment variable value"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("unset", {
          description: "Unset service configuration",
          params: {
            key: Argument.String("key").pipe(Argument.withDescription("Service setting or env")),
            name: Argument.String("name").pipe(
              Argument.withDescription("Environment variable name"),
              Argument.optional,
            ),
          },
        }),
      ],
    }),
    Spec.make("reload", {
      description: "Reload configuration",
      params: {
        ...ServerParams,
      },
    }),
    Spec.make("pair", {
      description: "Print one-time links to connect a browser or app",
      params: {
        url: Flag.String("url").pipe(
          Flag.withDescription("Use an external HTTP(S) server URL in pairing links"),
          Flag.mapTryCatch(
            (value) => {
              const url = new URL(value)
              if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash)
                throw new Error("Invalid pairing URL")
              return url.href.replace(/\/+$/, "")
            },
            () => "Expected an HTTP(S) server URL without credentials, query parameters, or a fragment",
          ),
          Flag.optional,
        ),
        remote: Flag.Boolean("remote").pipe(
          Flag.withDescription(
            "Pair through the OpenTunnel remote address, enabling remote access if needed (exposes the server to the internet)",
          ),
          Flag.withDefault(false),
        ),
        yes: Flag.Boolean("yes").pipe(
          Flag.withAlias("y"),
          Flag.withDescription(
            "Accept exposing the server to the internet when --remote enables remote access for the first time (required without an interactive terminal)",
          ),
          Flag.withDefault(false),
        ),
      },
    }),
    Spec.make("serve", {
      description: "Start the v2 API and web server",
      params: {
        hostname: Flag.String("hostname").pipe(Flag.optional),
        port: Flag.Int("port").pipe(Flag.optional),
        cors: Flag.String("cors").pipe(
          Flag.withSchema(Schema.NonEmptyString),
          Flag.withDescription("Additional allowed CORS origin (repeat for multiple origins)"),
          Flag.atLeast(0),
        ),
        service: Flag.Boolean("service").pipe(Flag.withDefault(false)),
        stdio: Flag.Boolean("stdio").pipe(Flag.withDefault(false)),
      },
    }),
  ],
})

export const Commands = Root
