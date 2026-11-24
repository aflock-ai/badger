---
title: Marking grammar
description: The classification markings Badger connectors accept, the order their parts must appear in, and how two markings compare.
sidebarLabel: Marking grammar
sidebarPosition: 40
---

# Marking grammar

Status: available on `main`, in `testifysec/connectors/internal/marking/`.

A connector's `--classification` value is parsed by this grammar. A marking that does not parse is an error; the parser never guesses.

## Vocabulary

The tokens the parser knows live in one data file,
`testifysec/connectors/internal/marking/tokens.json`, each with the regulation or manual it comes
from. Adding a token means adding it there with its source. This page describes the structure;
the file is the list. The Go engine reads its levels and groups from a classification
scheme (`scheme.go`): the presets in `internal/marking/schemes/` (`us-gov`, the default, and
`corporate`) or a deployment's own file. In this release no setting chooses a scheme: the Go
components (connectors, `conngw`, the gateway, the broker and the portal) use `us-gov`, and the
managed build's TypeScript port reads `tokens.json` only. The table below is that default.

The levels, generated from that file:

<!-- BEGIN GENERATED: marking-levels -->
From `testifysec/connectors/internal/marking/tokens.json`, lowest first. Each level dominates the ones above it in this table.

| Level | Banner | Portion mark |
|---|---|---|
| 0 | `UNCLASSIFIED` | `U` |
| 1 | the controlled unclassified level (banner and portion mark in `tokens.json`) | same |
| 2 | `CONFIDENTIAL` | `C` |
| 3 | `SECRET` | `S` |
| 4 | `TOP SECRET` | `TS` |
<!-- END GENERATED: marking-levels -->

## Characters

The input is upper-cased and must match `^[A-Z0-9 ,/-]{1,512}$`: letters, digits, space, comma,
slash and hyphen, at most 512 characters. A newline, `<`, `.` or anything else is refused.

## Structure

A marking is groups separated by `//`. The first group is the level; the rest follow in a fixed
order, and a group may appear once.

| Order | Group | Example values | Allowed with |
|---|---|---|---|
| 0 | Level | one of the levels above | always first |
| 1 | Compartments (SCI) | a control system, optionally with `-SUFFIX` sub-compartments | classified levels |
| 2 | Special access programs | `SAR-` followed by an identifier | classified levels |
| 3 | Atomic energy markings | restricted data and its variants | any |
| 4 | Foreign government information | `FGI`, optionally followed by country codes | any |
| 5 | Controlled unclassified categories | the categories for the controlled unclassified level | that level only |
| 6 | Dissemination controls | originator and imagery controls, foreign-release limits, proprietary | see below |
| 7 | Non-intelligence controls | limited, exclusive and no distribution, and agency-specific labels | any |

`REL TO` and `DISPLAY ONLY` lists sit in the dissemination group. Inside any other group, values
are separated by `/` and may come in any order; the parser prints them in a canonical order.

Below `CONFIDENTIAL` only the limited-dissemination controls defined for the controlled
unclassified level are allowed; a classified-only control on an unclassified marking is refused.

### Release lists

`REL TO` lists start with `USA`, then ISO 3166-1 alpha-3 country codes in alphabetical order, then
coalition codes (`ACGU`, `FVEY`, `NATO`), which expand to their members when markings are
compared. A list may appear once. A code that exists only in another standard is refused. A
marking cannot carry both a release list and the control that forbids foreign release.

### Banner form only

`--classification` takes the banner form only, such as `CONFIDENTIAL`. Portion marks such as `(C)`,
abbreviated control names and retired legacy markings are refused.

## Examples

| Input | Result |
|---|---|
| `UNCLASSIFIED` | parses |
| `confidential` | parses; upper-cased to `CONFIDENTIAL` |
| `PUBLIC` | refused: unknown classification level (the level table is fixed at build time) |
| `UNCLASSIFIED//` | refused: the empty group after `//` is an unknown token |
| `(C)` | refused: portion marks are not accepted |

These examples were run against the parser (`parse` in `testifysec/marking/marking.ts`, the
TypeScript port of `marking.go`); `CONFIDENTIAL` dominates `UNCLASSIFIED` and not the reverse.

The grammar also parses US-style banner markings with release lists, for example
`SECRET//REL TO USA, FVEY`.

## Comparing markings

The rules for **dominance** (may data with marking B flow to a place accredited for A?) and
**join** (the high-water mark of two markings) are in
[classification markings](../concepts/classification.md#how-markings-compare). In code they are
`Dominates` and `Join` in `dominance.go`; the Lean model in
PR #182 checks both against 441 pairs each.
