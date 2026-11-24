---
title: Classification markings and the no-write-down rule
description: How Badger labels sessions and connector results, how markings compare, and which parts of the no-write-down rule are built.
sidebarLabel: Classification markings
sidebarPosition: 20
---

# Classification markings and the no-write-down rule

Badger carries a classification marking with the data it handles so that it can refuse to move
data somewhere accredited below it. That rule, no write down, is the goal. Today Badger is part
of the way there, and this page separates the three stages.

| Stage | What it does | Status |
|---|---|---|
| Deployment marking | A marking compiled into the managed build, stamped on every session record | Available on `main` |
| Connector marking | Each connector has one marking, set by the administrator, and every result it returns carries that marking | Available on `main` |
| Flow check | Refuses a flow to a destination whose accreditation does not dominate what the session has read | Available on `main` for connectors and the model gateway; pushes not covered |

> [!NOTE]
> A marking is a label. It records what the data is and lets software refuse a flow; it does not
> stop a process that already holds the data from copying it. The isolation that does that is the
> deployment's VM or container boundary, described in [architecture](architecture.md).

## Deployment marking (available)

A managed build is compiled with a data marking and the set of markings it allows:

```sh
bun run script/build.ts --managed --data-marking=UNCLASSIFIED --allowed-markings=UNCLASSIFIED
```

The compiled marking is the floor. At run time the `BADGER_DATA_MARKING` and
`BADGER_ALLOWED_MARKINGS` environment variables may only raise the marking or narrow the allowed
set; a value outside the compiled set stops the process. Today the build accepts only the two
unclassified levels; classified levels arrive with the grammar below.

What the build does with the marking:

- Every new session record carries the deployment marking and its source.
- A session forked or transferred from another never takes a marking lower than the current
  deployment marking.
- Logs carry the marking, and the user interface shows it as a banner.
- In a managed build, a connector tool that has no marking is refused. Lowering a connector's
  marking requires a marking administrator role; with no role source configured, nobody can lower
  one. A stored marking that cannot be read is treated as the higher unclassified level.

Source: `packages/util/src/security-marking.ts`, `packages/core/src/connector-marking.ts`,
`packages/cli/script/marking-flags.ts`.

## Connector marking (available)

A connector has exactly one classification: the marking the administrator gives it with
`--classification`, the highest marking the service it reads is accredited to hold. A connector
without a valid marking does not start.

Every result, including errors and truncated output, carries that marking as a banner on its first
and last line, outside the block that wraps untrusted content:

```text
CONFIDENTIAL
<untrusted-external-content source="jira" tool="jira_get_issue">
...
</untrusted-external-content>
CONFIDENTIAL
```

The same banner is in the MCP result's `_meta` under `com.testifysec/classification`, so
software does not have to parse text.

The marking describes the connector, not the item. Badger does not read markings from issue
fields, labels or banners inside the content, and does not raise, lower or withhold a result
item by item. Choosing the connector's marking is the administrator's decision: set it to what
the whole service is accredited for.

The [marking grammar](../reference/marking-grammar.md) lists the markings `--classification`
accepts.

## How markings compare

Marking A **dominates** marking B when data marked B may flow to a place accredited for A. In
the grammar from PR #179, A dominates B when all of these hold:

- A's level is at least B's, in the order of the level table in `tokens.json` (for example
  `UNCLASSIFIED` < `CONFIDENTIAL`; the full list is in the
  [marking grammar](../reference/marking-grammar.md#vocabulary)).
- A holds every compartment, special access program, atomic energy marking and dissemination
  control that B holds.
- A is released to no country that B is not released to. A classified marking with no `REL TO`
  list is released to the United States only.

So a level with no release list dominates the same level with one: data releasable to partners may
go to a system only the home country's users can read, and the reverse fails, because data with no
release list may not go to a place partners can read. `CONFIDENTIAL` dominates `UNCLASSIFIED`.

The **join** of two markings is the high-water mark used when a session has read both. Joining
two `REL TO` lists with no country in common yields a marking releasable to the United States
only.

## The no-write-down rule

The rule: a session keeps a high-water marking, the join of every marking it has read. A flow to a
sink, such as a connector call, a model request or a push, is denied unless the sink's accredited
marking dominates the high-water mark. Three checks implement it on `main`:

- **The gateway ceiling, at admission.** A signed profile cannot admit a connector whose marking
  the model gateway's marking does not dominate, so nothing a connector returns is above what the
  gateway may send to the model. A v3 gateway refuses every request while such a profile is
  admitted.
- **The worker's high-water check.** The managed build keeps one label per state directory: the
  join of the markings of every connector it has called. The label rises when a call is allowed,
  before the connector runs, and never goes down; a cancelled or declined call still raises it. Any
  call, read or write, to a connector whose marking does not dominate the label is refused, since a
  search query carries content too. Decisions are written to `connector-flow.jsonl` before they take
  effect, and the label is rebuilt from it at start. This check runs inside the workspace, so it is
  defense in depth: changing the state directory resets it.
- **The connector gateway's label.** `conngw` keeps the authoritative label per workspace,
  outside the workspace's reach, in a durable labels file, and answers any call to a connector
  below the label itself, without reaching the connector.

Only an administrator resets a label, by replacing the state directory or the labels file. The
workspace's label starts at the lowest marking: content that arrives other than through a
connector (repository files, user input, model output) is not labelled, and keeping it within what
the lowest connector may receive is the deployment's responsibility.

Not covered yet: a per-connector network allowance for the worker, and a repository marking for
pushes through Pushgate. The full rules are in
[CONNECTORS.md](https://github.com/aflock-ai/badger/blob/main/testifysec/CONNECTORS.md).

The Lean model in PR #182 proves `no_write_down` over the specified lattice and over a
transcription of the Go code, and checks 441 dominance cases and 441 join cases against the Go
implementation. Building the model found one defect that was fixed in PR #179 (dominance across
foreign government information was not transitive) and one that is in the safe direction (the
join of two disjoint `REL TO` lists can be stricter than the least upper bound).
