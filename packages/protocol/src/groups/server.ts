import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/http-api"
import { UnauthorizedError } from "../errors.js"

export const ServerInfo = Schema.Struct({
  version: Schema.String,
  // 0 means the runtime has no OS process identity (e.g. workerd).
  pid: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)),
  urls: Schema.Array(Schema.String),
  paths: Schema.Struct({
    tmp: Schema.String,
  }),
  // Optional at every level so clients still decode servers that predate a capability.
  capabilities: Schema.optional(
    Schema.Struct({
      persistentPty: Schema.optional(Schema.Boolean),
    }),
  ),
}).annotate({ identifier: "ServerInfo" })
export type ServerInfo = typeof ServerInfo.Type

// The deployment's classification scheme: its name, digest and the markings a deployment on it may
// be set to, lowest first. A client orders and checks this server's markings with it.
export const MarkingScheme = Schema.Struct({
  name: Schema.String,
  sha256: Schema.String,
  levels: Schema.Array(Schema.String),
}).annotate({ identifier: "MarkingScheme" })
export type MarkingScheme = typeof MarkingScheme.Type

// The deployment's data marking (set by the operator, never by a request). marking and
// classification are null when the deployment sets no marking. scheme is absent only from a server
// that predates schemes, which is on us-gov. label is this workspace's label, a banner in that
// scheme: the join of every connector it has called. It is null while there is nothing to add to
// the deployment's marking, and absent from a server that predates it. It only rises; the server
// announces each rise with a marking.label.raised event.
export const DataMarking = Schema.Struct({
  marking: Schema.NullOr(Schema.String),
  classification: Schema.NullOr(Schema.String),
  allowed: Schema.Array(Schema.String),
  scheme: Schema.optional(MarkingScheme),
  label: Schema.optional(Schema.NullOr(Schema.String)),
}).annotate({ identifier: "DataMarking" })
export type DataMarking = typeof DataMarking.Type

export const PairingCode = Schema.Struct({
  code: Schema.String,
  expires_in: Schema.Int,
}).annotate({ identifier: "PairingCode" })
export type PairingCode = typeof PairingCode.Type

export const PairingSession = Schema.Struct({
  token: Schema.String,
}).annotate({ identifier: "PairingSession" })
export type PairingSession = typeof PairingSession.Type

export const PAIRING_CONNECT_PATH = "/auth/connect/:code"

const PAIRING_CONNECT_URL = /^\/auth\/connect\/[^/]+$/

export function isPairingConnectURL(url: URL) {
  return PAIRING_CONNECT_URL.test(url.pathname)
}

export const ServerGroup = HttpApiGroup.make("server.server")
  .add(
    HttpApiEndpoint.get("server.info", "/api/info", {
      success: ServerInfo,
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "server.info",
        summary: "Get server info",
        description: "Return the server identity, connection URLs, paths, and readiness status.",
      }),
    ),
  )
  .add(
    HttpApiEndpoint.get("server.marking", "/api/marking", {
      success: DataMarking,
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "server.marking",
        summary: "Get deployment data marking",
        description: "Return the deployment's data marking and the markings it allows. Null when none is set.",
      }),
    ),
  )
  .add(
    HttpApiEndpoint.post("server.pair", "/api/pair", {
      success: PairingCode,
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "server.pair",
        summary: "Create pairing code",
        description: "Create a short-lived, single-use code for a /auth/connect/:code pairing link.",
      }),
    ),
  )
  .add(
    HttpApiEndpoint.get("server.connect", PAIRING_CONNECT_PATH, {
      params: { code: Schema.String },
      success: PairingSession,
      error: UnauthorizedError,
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "server.connect",
        summary: "Redeem pairing code",
        description:
          "Redeem a pairing code. Browsers receive a session cookie and a redirect to the web app; requests that accept JSON receive a session token to use as the password.",
      }),
    ),
  )
  .annotateMerge(OpenApi.annotations({ title: "server" }))
