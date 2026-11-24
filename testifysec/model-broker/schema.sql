-- The broker's state (component "broker"). Each table says why it is marked or not.
CREATE SCHEMA broker;
GRANT USAGE ON SCHEMA broker TO {{service}};

-- Policy versions: immutable, one row per version, written once. Unmarked: the policy is the
-- operator's configuration over CI identities, not content from any data source.
CREATE TABLE broker.policy_versions (
    n           bigint PRIMARY KEY CHECK (n > 0),
    entries     jsonb NOT NULL,
    author      text NOT NULL,
    author_name text NOT NULL DEFAULT '',
    approver    text NOT NULL DEFAULT '',
    comment     text NOT NULL DEFAULT '',
    created     timestamptz NOT NULL,
    sha256      text NOT NULL
);
GRANT SELECT, INSERT ON broker.policy_versions TO {{service}};

-- Proposals awaiting a second admin. Unmarked, as policy versions.
CREATE TABLE broker.proposals (
    id          bigint PRIMARY KEY CHECK (id > 0),
    base        bigint NOT NULL,
    entries     jsonb NOT NULL,
    author      text NOT NULL,
    author_name text NOT NULL DEFAULT '',
    comment     text NOT NULL DEFAULT '',
    created     timestamptz NOT NULL,
    open        boolean NOT NULL
);
GRANT SELECT, INSERT, UPDATE (open) ON broker.proposals TO {{service}};

-- The audit log: append-only, each record carrying the SHA-256 of the one before it. Marked:
-- an audit record is written at its session's label and read only by sessions that dominate it.
CREATE TABLE broker.audit (
    seq     bigint PRIMARY KEY CHECK (seq > 0),
    prev    text NOT NULL,
    hash    text NOT NULL,
    record  text NOT NULL, -- the exact JSON the hash covers
    marking text NOT NULL CHECK (marking <> ''),
    label   badger.label NOT NULL
);
GRANT SELECT, INSERT ON broker.audit TO {{service}};
-- Approval reads a proposal's records (propose, approve, reject) by id.
CREATE INDEX audit_proposal ON broker.audit (((record::jsonb->>'proposal')::bigint));

-- The audit chain's head, so a writer at any label extends the one chain. Unmarked: a sequence
-- number and a hash say nothing about any record.
CREATE TABLE broker.audit_head (
    one  boolean PRIMARY KEY DEFAULT true CHECK (one),
    seq  bigint NOT NULL,
    hash text NOT NULL
);
INSERT INTO broker.audit_head (seq, hash) VALUES (0, '');
GRANT SELECT, UPDATE ON broker.audit_head TO {{service}};

-- Workspace and device tokens, by SHA-256 only. Unmarked: credentials metadata. marking is the
-- label a workspace's own requests run at (its high-water label, set by the provisioner).
CREATE TABLE broker.tokens (
    workspace text PRIMARY KEY,
    hash      text NOT NULL UNIQUE,
    principal text NOT NULL,
    expires   timestamptz NOT NULL,
    device    boolean NOT NULL DEFAULT false,
    marking   text NOT NULL
);
GRANT SELECT, INSERT, DELETE ON broker.tokens TO {{service}};

-- Versioned settings documents: "quotas" and "owners". Unmarked: limits and accountable people.
CREATE TABLE broker.documents (
    name    text PRIMARY KEY CHECK (name IN ('quotas', 'owners')),
    version bigint NOT NULL CHECK (version > 0),
    body    jsonb NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON broker.documents TO {{service}};

-- The usage ledger: one row per model call, written pending before the call and finished after
-- it, so a call whose result never arrives counts as unknown spend. Unmarked: who called which
-- model and the token counts, never prompt or answer content. label is the session label the call
-- was accounted at (a workspace's own, the ceiling for pipelines), taken from the transaction:
-- a row cannot be written without one.
CREATE TABLE broker.usage_calls (
    id           text PRIMARY KEY,
    day          date NOT NULL,
    t            timestamptz NOT NULL,
    principal    text NOT NULL,
    model        text NOT NULL,
    pending      boolean NOT NULL,
    prompt       bigint NOT NULL DEFAULT 0,
    cached       bigint NOT NULL DEFAULT 0,
    completion   bigint NOT NULL DEFAULT 0,
    owner        text NOT NULL DEFAULT '',
    triggered_by text NOT NULL DEFAULT '',
    unknown      boolean NOT NULL DEFAULT false,
    charged_usd  double precision,
    label        badger.label NOT NULL DEFAULT badger.session_label(),
    pod          text NOT NULL DEFAULT '', -- the process that began the call: its pod and its boot
    boot         text NOT NULL DEFAULT '', -- id, so a restarted pod releases what its last run left
    released     boolean NOT NULL DEFAULT false, -- released by a restart; a late result still lands
    reserved_usd double precision -- the most the call can cost (route max_call_usd); NULL: unbounded
);
CREATE INDEX usage_calls_principal_day ON broker.usage_calls (principal, day);
CREATE INDEX usage_calls_day ON broker.usage_calls (day);
GRANT SELECT, INSERT, UPDATE ON broker.usage_calls TO {{service}};

-- Facts about the store itself: when usage counting began, and the import that seeded it.
CREATE TABLE broker.meta (
    key   text PRIMARY KEY,
    value text NOT NULL
);
GRANT SELECT, INSERT ON broker.meta TO {{service}};
