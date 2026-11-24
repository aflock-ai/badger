---
title: Configuration reference
description: Every key in the JSON configuration of the model gateway, the platform session check, badger-broker and the connector gateway, with its type and source.
sidebarLabel: Configuration
sidebarPosition: 15
---

# Configuration reference

The tables below are generated from the Go source, so they list exactly the keys each component
decodes. They do not say which keys a given deployment needs or how they combine; the
administrator pages do that:

- [Configure the model gateway](../admin/install-gateway.md) for `hardened-gateway` and its
  platform session check.
- [Configure a connector with a marking](../admin/connectors.md) for connector flags.

A key typed `struct` holds the keys listed under it with its name as a prefix. A key ending in `[]`
is a list of objects, and `.*` stands for any map key.

<!-- BEGIN GENERATED: config-reference -->
Generated from the Go structs each component decodes its configuration into. A default is shown where the source comment states one; otherwise the loader decides, and the source cited is where to look.

### Model gateway (hardened-gateway)

Component `gateway`.

| Key | Type | Default | Description | Source |
|---|---|---|---|---|
| `schema` | `string` |  |  | `Config.Schema` in `testifysec/gateway/config.go` |
| `socket` | `string` |  |  | `Config.Socket` in `testifysec/gateway/config.go` |
| `spool` | `string` |  |  | `Config.Spool` in `testifysec/gateway/config.go` |
| `providerURL` | `string` |  |  | `Config.ProviderURL` in `testifysec/gateway/config.go` |
| `protocol` | `string` (optional) |  |  | `Config.Protocol` in `testifysec/gateway/config.go` |
| `providerTokenFile` | `string` (optional) |  |  | `Config.ProviderTokenFile` in `testifysec/gateway/config.go` |
| `providerTokenFd` | `int` (optional) |  |  | `Config.ProviderTokenFD` in `testifysec/gateway/config.go` |
| `providerCertSha256` | `string` (optional) |  | ProviderCertSHA256 pins the provider's certificate key (SHA-256 of its SubjectPublicKeyInfo, lowercase hex), for a provider whose certificate no system root signs. | `Config.ProviderCertSHA256` in `testifysec/gateway/config.go` |
| `collectorURL` | `string` |  |  | `Config.CollectorURL` in `testifysec/gateway/config.go` |
| `collectorTokenFile` | `string` |  |  | `Config.CollectorTokenFile` in `testifysec/gateway/config.go` |
| `model` | `string` |  |  | `Config.Model` in `testifysec/gateway/config.go` |
| `tenant` | `string` |  |  | `Config.Tenant` in `testifysec/gateway/config.go` |
| `session` | `string` |  |  | `Config.Session` in `testifysec/gateway/config.go` |
| `agent` | `string` |  |  | `Config.Agent` in `testifysec/gateway/config.go` |
| `profileDigest` | `string` |  |  | `Config.ProfileDigest` in `testifysec/gateway/config.go` |
| `maxRecords` | `int` |  |  | `Config.MaxRecords` in `testifysec/gateway/config.go` |
| `maxOfflineSeconds` | `int` |  |  | `Config.MaxOfflineSeconds` in `testifysec/gateway/config.go` |
| `timeoutSeconds` | `int` |  |  | `Config.TimeoutSeconds` in `testifysec/gateway/config.go` |
| `developmentLoopback` | `bool` |  |  | `Config.DevelopmentLoopback` in `testifysec/gateway/config.go` |
| `administratorIdentity` | `bool` (optional) |  | AdministratorIdentity runs a v3 gateway with no platform: the agent is who the administrator provisioned (the signed profile it admits and the provider credential it holds), and every endpoint is HTTPS. For a network that cannot reach the TestifySec platform. | `Config.AdministratorIdentity` in `testifysec/gateway/config.go` |
| `platformConfigFile` | `string` (optional) |  |  | `Config.PlatformConfigFile` in `testifysec/gateway/config.go` |
| `signedProfileFile` | `string` (optional) |  |  | `Config.SignedProfileFile` in `testifysec/gateway/config.go` |
| `profileFile` | `string` (optional) |  | ProfileFile is an unsigned profile (models.go): read by the gateway itself, pinned by profileDigest, with no admission executable. Gateway v3 only, instead of signedProfileFile. | `Config.ProfileFile` in `testifysec/gateway/config.go` |
| `admissionExecutable` | `string` (optional) |  |  | `Config.AdmissionExecutable` in `testifysec/gateway/config.go` |
| `admissionSha256` | `string` (optional) |  |  | `Config.AdmissionSHA256` in `testifysec/gateway/config.go` |
| `backend` | `*BackendAssignment` (optional) |  |  | `Config.Backend` in `testifysec/gateway/config.go` |
| `backend.kind` | `string` |  |  | `BackendAssignment.Kind` in `testifysec/gateway/profile_v2.go` |
| `backend.manifestSha256` | `string` |  |  | `BackendAssignment.ManifestSHA256` in `testifysec/gateway/profile_v2.go` |

### Platform session check (the gateway's platformConfigFile)

Component `platform`.

| Key | Type | Default | Description | Source |
|---|---|---|---|---|
| `endpoint` | `string` |  |  | `Config.Endpoint` in `testifysec/platform/client.go` |
| `caFile` | `string` |  |  | `Config.CAFile` in `testifysec/platform/client.go` |
| `credentialFile` | `string` |  |  | `Config.CredentialFile` in `testifysec/platform/client.go` |
| `tenantID` | `string` |  |  | `Config.TenantID` in `testifysec/platform/client.go` |
| `agentID` | `string` |  |  | `Config.AgentID` in `testifysec/platform/client.go` |
| `repositoryID` | `string` |  |  | `Config.RepositoryID` in `testifysec/platform/client.go` |
| `trustDomain` | `string` |  |  | `Config.TrustDomain` in `testifysec/platform/client.go` |
| `minimumEnrollmentAAL` | `string` |  |  | `Config.MinimumEnrollmentAAL` in `testifysec/platform/client.go` |
| `requireCurrentHumanAAL` | `string` |  |  | `Config.RequireCurrentHumanAAL` in `testifysec/platform/client.go` |

### Model broker and portal (badger-broker)

Component `badger-broker`.

| Key | Type | Default | Description | Source |
|---|---|---|---|---|
| `listen` | `struct` |  |  | `FileConfig.Listen` in `testifysec/model-broker/config.go` |
| `listen.internal` | `string` |  |  | `FileConfig.Listen` in `testifysec/model-broker/config.go` |
| `listen.edge` | `string` |  |  | `FileConfig.Listen` in `testifysec/model-broker/config.go` |
| `listen.provision` | `string` |  |  | `FileConfig.Listen` in `testifysec/model-broker/config.go` |
| `listen.admin` | `string` |  | Admin serves the admin API and anything mounted beside it, and no model route. | `FileConfig.Listen` in `testifysec/model-broker/config.go` |
| `issuers` | `[]IssuerConfig` |  | Issuers are the OIDC issuers whose workload tokens the edge verifies (federation.go). | `FileConfig.Issuers` in `testifysec/model-broker/config.go` |
| `issuers[].id` | `string` |  |  | `IssuerConfig.ID` in `testifysec/model-broker/federation.go` |
| `issuers[].issuer` | `string` |  |  | `IssuerConfig.Issuer` in `testifysec/model-broker/federation.go` |
| `issuers[].audience` | `string` |  |  | `IssuerConfig.Audience` in `testifysec/model-broker/federation.go` |
| `issuers[].claims_header` | `string` |  | ClaimsHeader is the header the edge's provider for this issuer forwards the payload in. | `IssuerConfig.ClaimsHeader` in `testifysec/model-broker/federation.go` |
| `issuers[].max_token_lifetime_seconds` | `int` |  | MaxTokenLifetimeSeconds bounds exp - iat. 0 is allowed only for a gitlab issuer, whose edge provider enforces max_lifetime itself (the configuration before federation). | `IssuerConfig.MaxTokenLifetimeSeconds` in `testifysec/model-broker/federation.go` |
| `issuers[].type` | `string` |  | Type is "gitlab" (built-in claim mapping) or "generic" (Mapping below). | `IssuerConfig.Type` in `testifysec/model-broker/federation.go` |
| `issuers[].primary` | `bool` |  |  | `IssuerConfig.Primary` in `testifysec/model-broker/federation.go` |
| `issuers[].mapping` | `map[string]ClaimRef` |  |  | `IssuerConfig.Mapping` in `testifysec/model-broker/federation.go` |
| `issuers[].require` | `map[string]string` |  | Require: claims every token from this issuer must carry with exactly this string value. | `IssuerConfig.Require` in `testifysec/model-broker/federation.go` |
| `issuers[].ref_prefix` | `string` |  | RefPrefix is stripped from the mapped ref and must be present (GitHub: "refs/heads/"). | `IssuerConfig.RefPrefix` in `testifysec/model-broker/federation.go` |
| `issuers[].config_ref_template` | `string` |  | ConfigRefTemplate is the only CI config an entry accepts: {project_path} then {ref}. | `IssuerConfig.ConfigRefTemplate` in `testifysec/model-broker/federation.go` |
| `clock_skew_seconds` | `int` |  |  | `FileConfig.ClockSkewSeconds` in `testifysec/model-broker/config.go` |
| `sources` | `[]string` |  |  | `FileConfig.Sources` in `testifysec/model-broker/config.go` |
| `headers` | `struct` |  |  | `FileConfig.Headers` in `testifysec/model-broker/config.go` |
| `headers.principal` | `string` |  |  | `FileConfig.Headers` in `testifysec/model-broker/config.go` |
| `headers.admin_id` | `string` |  |  | `FileConfig.Headers` in `testifysec/model-broker/config.go` |
| `headers.admin_name` | `string` |  |  | `FileConfig.Headers` in `testifysec/model-broker/config.go` |
| `headers.admin_role` | `string` |  |  | `FileConfig.Headers` in `testifysec/model-broker/config.go` |
| `human_principals` | `[]string` |  |  | `FileConfig.HumanPrincipals` in `testifysec/model-broker/config.go` |
| `admin_roles` | `[]string` |  |  | `FileConfig.AdminRoles` in `testifysec/model-broker/config.go` |
| `two_person_rule` | `*bool` |  |  | `FileConfig.TwoPersonRule` in `testifysec/model-broker/config.go` |
| `max_named_branch_ttl_hours` | `int` |  |  | `FileConfig.MaxNamedBranchTTLHours` in `testifysec/model-broker/config.go` |
| `allowed_origins` | `[]string` |  |  | `FileConfig.AllowedOrigins` in `testifysec/model-broker/config.go` |
| `database` | `DatabaseConfig` |  | Database is where every piece of the service's state lives (README "State"). | `FileConfig.Database` in `testifysec/model-broker/config.go` |
| `database.dsn_file` | `string` |  | DSNFile holds the service role's connection string: grants only, no superuser, no BYPASSRLS. | `DatabaseConfig.DSNFile` in `testifysec/model-broker/config.go` |
| `database.owner_dsn_file` | `string` (optional) |  | OwnerDSNFile holds the owner role's connection string. When set, the service migrates the schema at start with it; when empty, migrations are run separately before start. | `DatabaseConfig.OwnerDSNFile` in `testifysec/model-broker/config.go` |
| `database.service_role` | `string` |  |  | `DatabaseConfig.ServiceRole` in `testifysec/model-broker/config.go` |
| `ceiling_marking` | `string` |  | CeilingMarking is the deployment's accreditation ceiling, a banner the marking package parses. Admin sessions, pipelines and the provisioner run at it; a workspace runs at its own label, never above it. | `FileConfig.CeilingMarking` in `testifysec/model-broker/config.go` |
| `import_state_dir` | `string` (optional) |  | ImportStateDir is a broker state directory from before the database (policy versions, audit log, owners, quotas, tokens, usage ledger), imported once into an empty database at start. | `FileConfig.ImportStateDir` in `testifysec/model-broker/config.go` |
| `seed_policy_file` | `string` |  |  | `FileConfig.SeedPolicyFile` in `testifysec/model-broker/config.go` |
| `max_concurrent_upstream` | `int` |  |  | `FileConfig.MaxConcurrentUpstream` in `testifysec/model-broker/config.go` |
| `upstream` | `UpstreamConfig` |  | Upstream timeouts. Reasoning models can think for minutes before the first byte. | `FileConfig.Upstream` in `testifysec/model-broker/config.go` |
| `upstream.response_header_seconds` | `int` |  |  | `UpstreamConfig.ResponseHeaderSeconds` in `testifysec/model-broker/config.go` |
| `upstream.request_seconds` | `int` |  |  | `UpstreamConfig.RequestSeconds` in `testifysec/model-broker/config.go` |
| `upstream.server_write_seconds` | `int` |  |  | `UpstreamConfig.ServerWriteSeconds` in `testifysec/model-broker/config.go` |
| `provisioner_key_file` | `string` |  | Workspace tokens (tokens.go): the provisioner's key file and each token's lifetime. | `FileConfig.ProvisionerKeyFile` in `testifysec/model-broker/config.go` |
| `workspace_token_ttl_hours` | `int` |  |  | `FileConfig.WorkspaceTokenTTLHours` in `testifysec/model-broker/config.go` |
| `device_login` | `bool` |  | Device sign-in (device.go): off unless enabled. A person approves a device at the edge and the device gets its own token for DeviceTokenTTLHours, at most MaxDeviceTokens per person. | `FileConfig.DeviceLogin` in `testifysec/model-broker/config.go` |
| `device_token_ttl_hours` | `int` |  |  | `FileConfig.DeviceTokenTTLHours` in `testifysec/model-broker/config.go` |
| `max_device_tokens` | `int` |  |  | `FileConfig.MaxDeviceTokens` in `testifysec/model-broker/config.go` |
| `routes` | `[]RouteConfig` |  |  | `FileConfig.Routes` in `testifysec/model-broker/config.go` |
| `routes[].model` | `string` |  |  | `RouteConfig.Model` in `testifysec/model-broker/config.go` |
| `routes[].upstream_url` | `string` |  |  | `RouteConfig.UpstreamURL` in `testifysec/model-broker/config.go` |
| `routes[].auth_header` | `string` |  | AuthHeader carries the key: "api-key" (Azure OpenAI), "Ocp-Apim-Subscription-Key" (Azure API Management) or "Authorization" (sent as "Bearer &lt;key&gt;"). | `RouteConfig.AuthHeader` in `testifysec/model-broker/config.go` |
| `routes[].key_file` | `string` |  |  | `RouteConfig.KeyFile` in `testifysec/model-broker/config.go` |
| `routes[].api_version` | `string` |  |  | `RouteConfig.APIVersion` in `testifysec/model-broker/config.go` |
| `routes[].reasoning_map` | `map[string]string` |  | ReasoningMap rewrites reasoning_effort values the deployment rejects. | `RouteConfig.ReasoningMap` in `testifysec/model-broker/config.go` |
| `routes[].no_reasoning_with_tools` | `bool` |  | NoReasoningWithTools drops reasoning_effort when the request carries tools. | `RouteConfig.NoReasoningWithTools` in `testifysec/model-broker/config.go` |
| `routes[].price_usd_per_million` | `*Price` (optional) |  | Price is what the provider bills for this model. Without it usage is counted in tokens only. | `RouteConfig.Price` in `testifysec/model-broker/config.go` |
| `routes[].price_usd_per_million.input` | `float64` |  |  | `Price.Input` in `testifysec/model-broker/config.go` |
| `routes[].price_usd_per_million.cached_input` | `float64` |  |  | `Price.CachedInput` in `testifysec/model-broker/config.go` |
| `routes[].price_usd_per_million.output` | `float64` |  |  | `Price.Output` in `testifysec/model-broker/config.go` |
| `routes[].max_call_usd` | `*float64` (optional) |  | MaxCallUSD is the most one call can cost. A call in flight is counted at it against a quota, so calls running at once cannot pass a limit together; without it a call in flight counts as unbounded and a limited principal's next call is refused while it runs. | `RouteConfig.MaxCallUSD` in `testifysec/model-broker/config.go` |
| `seed_limits` | `*SeedLimits` (optional) | `for` | SeedLimits are the first defaults for the limits an admin sets in the portal (quota.go): each field is applied once, when the broker first sees it, and never over an admin's value. | `FileConfig.SeedLimits` in `testifysec/model-broker/config.go` |
| `seed_limits.default_usd` | `*float64` |  |  | `SeedLimits.DefaultUSD` in `testifysec/model-broker/quota.go` |
| `seed_limits.defaults` | `Limits` |  |  | `SeedLimits.Defaults` in `testifysec/model-broker/quota.go` |
| `seed_limits.defaults.daily_usd` | `*float64` (optional) |  |  | `Limits.DailyUSD` in `testifysec/model-broker/quota.go` |
| `seed_limits.defaults.call_usd` | `*float64` (optional) |  |  | `Limits.CallUSD` in `testifysec/model-broker/quota.go` |
| `seed_limits.defaults.steps` | `*int` (optional) |  |  | `Limits.Steps` in `testifysec/model-broker/quota.go` |
| `seed_limits.defaults.context` | `*int` (optional) |  |  | `Limits.Context` in `testifysec/model-broker/quota.go` |
| `seed_limits.defaults.output` | `*int` (optional) |  |  | `Limits.Output` in `testifysec/model-broker/quota.go` |
| `seed_limits.defaults.timeout_seconds` | `*int` (optional) |  |  | `Limits.TimeoutSeconds` in `testifysec/model-broker/quota.go` |
| `admin_ui` | `struct` |  | AdminUI is display-only chrome for the admin console: the product name in its header and links to sibling admin pages (each href a same-origin path). It grants nothing. | `FileConfig.AdminUI` in `testifysec/model-broker/config.go` |
| `admin_ui.brand` | `string` |  |  | `FileConfig.AdminUI` in `testifysec/model-broker/config.go` |
| `admin_ui.nav` | `[]NavLink` |  |  | `FileConfig.AdminUI` in `testifysec/model-broker/config.go` |
| `admin_ui.nav[].label` | `string` |  |  | `NavLink.Label` in `testifysec/model-broker/config.go` |
| `admin_ui.nav[].href` | `string` |  |  | `NavLink.Href` in `testifysec/model-broker/config.go` |
| `portal` | `json.RawMessage` (optional) |  | Portal configures the management portal the command mounts on the admin listener. The broker does not read it; the command parses it strictly. | `FileConfig.Portal` in `testifysec/model-broker/config.go` |
| `portal.signing_key_file` | `string` |  | SigningKeyFile is the profile signing key, mounted from the key vault. | `portalConfig.SigningKeyFile` in `testifysec/portal/cmd/badger-broker/main.go` |
| `portal.tenant_id` | `string` |  |  | `portalConfig.TenantID` in `testifysec/portal/cmd/badger-broker/main.go` |
| `portal.minimum_sequence` | `uint64` |  |  | `portalConfig.MinimumSequence` in `testifysec/portal/cmd/badger-broker/main.go` |
| `portal.bootstrap` | `map[string]auth.Role` |  | Bootstrap gives these IdP subjects a role only until a provisioned user holds it, so the first admin and approver can grant real roles. It is never the directory. | `portalConfig.Bootstrap` in `testifysec/portal/cmd/badger-broker/main.go` |
| `portal.import_data_dir` | `string` (optional) |  | ImportDataDir is a portal data directory from before the database (profiles, assignments, audit log, users, role requests, bootstrap markers), imported once into an empty database at start. Required when import_state_dir moves the broker's state. | `portalConfig.ImportDataDir` in `testifysec/portal/cmd/badger-broker/main.go` |
| `portal.import` | `string` (optional) |  | Import "none" declares there is no portal data to import (the portal never ran file-backed here): import_state_dir moves the broker's state alone, and the declaration is recorded as the portal's import. The only value; never together with ImportDataDir. | `portalConfig.Import` in `testifysec/portal/cmd/badger-broker/main.go` |
| `portal.data_dir` | `string` (optional) |  | DataDir is refused: the portal's state is in the database now. | `portalConfig.DataDir` in `testifysec/portal/cmd/badger-broker/main.go` |

### Connector gateway (conngw)

Component `conngw`.

| Key | Type | Default | Description | Source |
|---|---|---|---|---|
| `listen` | `string` |  | e.g. ":8443" | `config.Listen` in `testifysec/connectors/cmd/conngw/main.go` |
| `certFile` | `string` |  | the TLS certificate workspaces pin with --ca-file | `config.CertFile` in `testifysec/connectors/cmd/conngw/main.go` |
| `keyFile` | `string` |  |  | `config.KeyFile` in `testifysec/connectors/cmd/conngw/main.go` |
| `audience` | `string` |  | the projected token's audience | `config.Audience` in `testifysec/connectors/cmd/conngw/main.go` |
| `namespaces` | `[]string` |  | Namespaces hold the workspaces' service accounts; one gateway serves all of them, and a workspace is "&lt;namespace&gt;/&lt;account&gt;". | `config.Namespaces` in `testifysec/connectors/cmd/conngw/main.go` |
| `labelsFile` | `string` |  | LabelsFile keeps each workspace's high-water across restarts. It must be on a persistent volume; it is created once with --init-labels and the pod refuses to start without it. | `config.LabelsFile` in `testifysec/connectors/cmd/conngw/main.go` |
| `maxStreams` | `int` | `64` | Stream bounds; zero takes the default. default 64 | `config.MaxStreams` in `testifysec/connectors/cmd/conngw/main.go` |
| `maxStreamsPerWorkspace` | `int` | `8` | default 8 | `config.MaxStreamsPerWorkspace` in `testifysec/connectors/cmd/conngw/main.go` |
| `idleMinutes` | `*int` | `30` | absent: 30; 0: never close an idle stream | `config.IdleMinutes` in `testifysec/connectors/cmd/conngw/main.go` |
| `floor` | `string` |  | Floor turns on the admin API for a workspace controller (admin.go): the level every workspace it registers may reach without a copy. Admins are the controllers' identities, "&lt;namespace&gt;/&lt;account&gt;". InboxDir turns on send-up (sendup.go); it belongs on the labels volume. | `config.Floor` in `testifysec/connectors/cmd/conngw/main.go` |
| `admins` | `[]string` |  |  | `config.Admins` in `testifysec/connectors/cmd/conngw/main.go` |
| `inboxDir` | `string` |  |  | `config.InboxDir` in `testifysec/connectors/cmd/conngw/main.go` |
| `hostDigest` | `string` |  | HostDigest is the image every plugin container runs: the platform's plughost, built from reviewed code. A vendor's image is never run; its executable is mounted into this one and copied and checked against the connector's digest before it starts (internal/launch.Stage). | `config.HostDigest` in `testifysec/connectors/cmd/conngw/main.go` |
| `signers` | `map[string]string` |  | Signers are the plugin signers this profile trusts: name -&gt; base64 ed25519 public key. | `config.Signers` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors` | `[]source` |  |  | `config.Sources` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].name` | `string` |  | also the name of the plugin's container in the pod | `source.Name` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].bundle` | `string` |  | directory holding manifest.json and manifest.sig | `source.Bundle` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].digest` | `string` |  | the plugin executable's sha256, pinned by the profile and named by its manifest | `source.Digest` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].signer` | `string` |  | key in the profile's signers that signs the manifest | `source.Signer` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].socket` | `string` |  | the plugin host's socket, on a volume only it and the gateway mount | `source.Socket` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].baseUrl` | `string` |  |  | `source.BaseURL` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].tokenPath` | `string` |  | in the plugin's container | `source.TokenPath` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].caPath` | `string` |  | in the plugin's container | `source.CAPath` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].writes` | `bool` |  | whether any grant may give write tools | `source.Writes` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].classification` | `string` |  |  | `source.Classification` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].flags` | `map[string]string` |  |  | `source.Flags` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].grants` | `[]grant` |  |  | `source.Grants` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].grants[].workspaces` | `[]string` |  |  | `grant.Workspaces` in `testifysec/connectors/cmd/conngw/plugin.go` |
| `connectors[].grants[].tools` | `[]string` |  |  | `grant.Tools` in `testifysec/connectors/cmd/conngw/plugin.go` |
| `connectors[].grants[].writeTools` | `[]string` |  |  | `grant.WriteTools` in `testifysec/connectors/cmd/conngw/plugin.go` |
| `connectors[].uid` | `int` |  | UID and GID of the plugin's container: its own, not root, not another connector's and not the gateway's. The socket must be answered by them. | `source.UID` in `testifysec/connectors/cmd/conngw/main.go` |
| `connectors[].gid` | `int` |  |  | `source.GID` in `testifysec/connectors/cmd/conngw/main.go` |
| `markingScheme` | `*schemeRef` |  | MarkingScheme is the deployment's classification scheme, pinned by digest: a preset, or a scheme file at an absolute path. Absent is the us-gov preset, the scheme of every existing deployment. The labels file and every caller's declaration must name the same scheme. | `config.MarkingScheme` in `testifysec/connectors/cmd/conngw/main.go` |
| `markingScheme.preset` | `string` |  |  | `schemeRef.Preset` in `testifysec/connectors/cmd/conngw/main.go` |
| `markingScheme.file` | `string` |  |  | `schemeRef.File` in `testifysec/connectors/cmd/conngw/main.go` |
| `markingScheme.sha256` | `string` |  |  | `schemeRef.SHA256` in `testifysec/connectors/cmd/conngw/main.go` |
| `markingPolicy` | `json.RawMessage` |  | MarkingPolicy is a badger.marking-policy/v1 document on the profile's scheme. Its classify globs give each tool its own marking, as connector:&lt;name&gt;/&lt;tool&gt;; every tool a connector's manifest lists must have one at start, and its flowRules refuse calls. With a policy, no connector sets classification: its marking is the join of its tools'. | `config.MarkingPolicy` in `testifysec/connectors/cmd/conngw/main.go` |
<!-- END GENERATED: config-reference -->
