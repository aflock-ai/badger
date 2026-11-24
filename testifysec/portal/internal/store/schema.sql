-- The management portal's profiles, assignments and audit log (component "portal").
CREATE SCHEMA portal;
GRANT USAGE ON SCHEMA portal TO {{service}};

-- Signed profile versions: written once per (profile, sequence). Marked: a profile is a
-- deployment's signed configuration and is read only by sessions that dominate its label.
CREATE TABLE portal.profile_versions (
    profile_id text NOT NULL,
    sequence   bigint NOT NULL CHECK (sequence > 0),
    body       text NOT NULL, -- the exact JSON: the envelope inside it is served byte for byte
    marking    text NOT NULL CHECK (marking <> ''),
    label      badger.label NOT NULL,
    PRIMARY KEY (profile_id, sequence)
);
GRANT SELECT, INSERT ON portal.profile_versions TO {{service}};

-- Which profile version each deployment runs. Unmarked: a pointer (deployment, profile,
-- sequence), with who set it and when.
CREATE TABLE portal.assignments (
    deployment_id text PRIMARY KEY,
    body          jsonb NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON portal.assignments TO {{service}};

-- The portal's audit log, chained like the broker's. Marked, written at the session label.
CREATE TABLE portal.audit (
    seq     bigint PRIMARY KEY CHECK (seq > 0),
    prev    text NOT NULL,
    hash    text NOT NULL,
    record  text NOT NULL, -- the exact JSON the next record's prev covers
    marking text NOT NULL CHECK (marking <> ''),
    label   badger.label NOT NULL
);
GRANT SELECT, INSERT ON portal.audit TO {{service}};

-- The chain's head. Unmarked: a sequence number and a digest.
CREATE TABLE portal.audit_head (
    one  boolean PRIMARY KEY DEFAULT true CHECK (one),
    seq  bigint NOT NULL,
    hash text NOT NULL
);
INSERT INTO portal.audit_head (seq, hash) VALUES (0, repeat('0', 64));
GRANT SELECT, UPDATE ON portal.audit_head TO {{service}};

-- The directory (users package): people by IdP subject, role requests, and the bootstrap
-- markers. Unmarked: identities, roles and approvals, never content from a data source.
CREATE TABLE portal.users (
    id   text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{64}$'),
    body jsonb NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON portal.users TO {{service}};

CREATE TABLE portal.role_requests (
    id   text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    body jsonb NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON portal.role_requests TO {{service}};

-- A bootstrap marker: the holder whose arrival ends a role's bootstrap; final once in effect.
CREATE TABLE portal.bootstrap_ended (
    role   text PRIMARY KEY CHECK (role IN ('admin', 'approver', 'auditor')),
    holder text NOT NULL CHECK (holder ~ '^[0-9a-f]{64}$'),
    final  boolean NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON portal.bootstrap_ended TO {{service}};

-- Facts about the portal's state itself: the one-time import from a file-backed data directory.
CREATE TABLE portal.meta (
    key   text PRIMARY KEY,
    value text NOT NULL
);
GRANT SELECT, INSERT ON portal.meta TO {{service}};
