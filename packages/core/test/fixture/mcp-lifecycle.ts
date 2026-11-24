import { appendFileSync } from "node:fs"
import { Server } from "@modelcontextprotocol/server"
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio"

// A stdio MCP server for lifecycle tests. MCP_START_FILE gets one line per start; MCP_SLOW_MS delays
// the start; MCP_EXIT_AFTER_MS ends the process that long after it starts, closing the stream.
const starts = process.env.MCP_START_FILE
if (starts) appendFileSync(starts, "start\n")
const slow = Number(process.env.MCP_SLOW_MS ?? 0)
if (slow > 0) await new Promise((resolve) => setTimeout(resolve, slow))

const server = new Server({ name: "lifecycle", version: "1.0.0" }, { capabilities: { tools: {} } })
server.setRequestHandler("tools/list", () =>
  Promise.resolve({ tools: [{ name: "lookup", inputSchema: { type: "object" } }] }),
)
await server.connect(new StdioServerTransport())

const exit = Number(process.env.MCP_EXIT_AFTER_MS ?? 0)
if (exit > 0) setTimeout(() => process.exit(0), exit)
