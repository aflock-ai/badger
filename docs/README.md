# Badger documentation source

The pages under `docs/` are the Badger documentation. They are written here, beside the code
they describe, and published at testifysec.com/docs/badger. The website imports them from a
pinned commit of this repository and renders them in its own documentation shell; nothing in this
directory is HTML.

## Page format

Every page except this file is a Markdown file that starts with front matter holding exactly
these four keys, in this order:

```yaml
---
title: Classification markings
description: How Badger labels connector results and what the no-write-down rule will enforce.
sidebarLabel: Classification markings
sidebarPosition: 20
---
```

- `title` is the page title on the website. Repeat it as the page's single `# ` heading.
- `description` is one sentence, used for search results and link previews.
- `sidebarLabel` is the short name in the sidebar.
- `sidebarPosition` is an integer that orders the page inside its section.

The directory decides the section and the URL: `docs/concepts/connectors.md` is published at
`/docs/badger/concepts/connectors` in the "Concepts" section, and `docs/index.md` is
`/docs/badger`.

Write plain GitHub Markdown: headings, lists, tables, fenced code blocks, and links. Raw HTML is
refused because the website does not render it. Two extensions are carried through:

- GitHub alerts (`> [!NOTE]`, `> [!WARNING]`) become the website's callouts.
- An `.svg` image in `docs/assets/` is inlined as a figure.

Link to other pages with relative paths to the `.md` file (`../concepts/connectors.md`). The
importer turns them into website routes.

## Status

Every page says what is built. Describe behaviour that is merged on `main` as current. Put a
`> [!WARNING]` callout at the top of any page, or section, that covers work still in a pull
request, naming the pull request, and write that part in the future tense. Never describe unbuilt
behaviour as working.

## Generated sections

Reference that can be read from source is generated, not written. A generated section sits
between `<!-- BEGIN GENERATED: name -->` and `<!-- END GENERATED: name -->`.

`bun docs/tools/generate.ts --check` writes nothing and fails if a generated section is stale, if a code reference does not resolve,
if a page's front matter is wrong, if a page holds raw HTML, if a relative link does not
resolve, or if a generated-section marker is unpaired. The docs workspace's `test` script runs it
and the tests in `docs/tools` (`cd docs && bun run test`).

The generator never writes into the page tree. When the only problem is a stale section, the check prints the
command that regenerates it, which prints the regenerated pages as a patch and lets git write them:

```sh
bun docs/tools/generate.ts --diff | git apply
```

The printed command names the generator and the checkout by absolute path, so it runs from any
directory.

## Citing code

Cite code with a reference marker, never with a line number typed by hand:

| Marker | Resolves to |
|---|---|
| `{{ref testifysec/gateway/config.go#Config}}` | The declaration of `Config`: a Go func, type, var or const, or a TypeScript export |
| `{{ref testifysec/gateway/config.go#Config.Model}}` | A struct field, a method on a type, or a member of a TypeScript class or interface |
| `{{ref testifysec/CONNECTORS.md}}` | The whole file |

### Supported forms

The resolver parses the cited file with the language's own parser (`go/parser` through
`docs/tools/goref`, the TypeScript compiler API) and takes the span from the declaration's node: from
the line that declares the name (its doc comment is outside the span) to the line where the node
ends. A symbol that names no declaration, or more than one (an overloaded function, a getter and
setter pair), fails the check, and so does a file that does not parse and a span whose first line
does not name the symbol (a decorator above a class). It never resolves to a guessed span. Cite the
enclosing symbol or the whole file instead. The check and a render therefore need the workspace's
packages installed (`bun install`, for `typescript`) and, to cite Go, the `go` command on `PATH`;
without it a Go citation fails with an error saying so. The docs MCP server only reads the bundle
these produce and runs neither.

- **Go**: top-level `func`, `type`, `var` and `const` (also `var a, b int` and inside groups);
  `T.M` for a method on `T` (`func (r *T[P]) M`), a struct field, named or embedded (`*Reader`,
  `io.Writer`), or an interface method.
- **TypeScript**: top-level `function`, `const`/`let`/`var`, `class`, `interface`, `type`, `enum`
  and `namespace`; `T.m` for a member of a class, interface or enum, or a property of a `const`
  holding an object literal (`as const` and `satisfies` included).
- **Any file**: `{{ref path}}` cites the whole file.

Not supported, and reported as errors: nested members (`A.B.C`), symbols inside a function body,
anonymous default exports, and symbols in any language other than Go and TypeScript.

The marker stays in the page. Rendering replaces it with the file and the declaration's lines,
linked to the commit, for example ``[`testifysec/gateway/config.go:18-48`](https://github.com/...)``,
and ends every page with "Generated from badger <version> at <commit> on <date>". The date is the
commit's, so two renders of one commit are identical. A symbol that is missing or declared more
than once fails the check, and so does a hand-typed `file.go:123`. Markers inside fenced code are
left alone.

```sh
bun docs/tools/generate.ts --list            # every published page and asset path
bun docs/tools/generate.ts --render <path>   # one of them, markers resolved and footer added
bun docs/tools/generate.ts --bundle          # every page in one JSON document, for the docs MCP server
```

The generator writes no file. Each mode prints one output on standard output, and placing it is
the caller's job, for example
`for p in $(bun docs/tools/generate.ts --list); do mkdir -p "site/$(dirname "$p")"; bun docs/tools/generate.ts --render "$p" > "site/$p"; done`.

Everything is read from git at each checkout's commit (`HEAD`), never from the working tree: cited
code, `VERSION`, the pages and the assets, in every mode. Every mode refuses a page tree with
uncommitted changes to pages or assets, ignored pages, or one in no checkout, so commit a page (and
the code it cites) before you check it. A page tree in a checkout of its own (a nested checkout or a
submodule) is refused unless `--root` names that checkout. A submodule or nested checkout inside the page tree is
refused; check it as a page tree of its own. Git reads only local objects, so in a partial clone a
missing object fails the check instead of being fetched. A cited symlink, a symlink in the page tree and a `VERSION` that is not a
regular file are refused.

A private page tree is checked and rendered with the same rules by
`--docs <dir>`, and cites another checkout as `{{ref name:path#Symbol}}` with
`--root name=<checkout>`; that checkout's commit is named in the footer, without a link.

> [!WARNING]
> The testifysec.com importer still reads the source pages, not the rendered ones. Until it renders
> them, a marker would be published as written, so pages on `main` carry no markers yet.

## Docs MCP server

`badger-docs` (`testifysec/docsmcp`) serves the docs of the commit it was built from as a read-only
MCP server on standard input and output (`list_topics`, `search`, `read`, `get_config_reference`,
`version`). Generate the bundle it embeds, then build it:
`bun docs/tools/bundle.ts testifysec/docsmcp/bundle/docs.json`, then `go build` in
`testifysec/docsmcp`. It refuses to start if the bundle names another commit than the binary's.
`badger-docs mcp --overlay <dir>` adds a private bundle's topics under `overlay/<dir name>/`; an
overlay never replaces a public topic.

## Public text

This repository is headed for publication. Do not write internal hostnames, addresses, customer
or program names, or credentials, even in examples. Use `example.invalid` hosts. In marking
examples use the levels `UNCLASSIFIED` and `CONFIDENTIAL` from `tokens.json`, with no release
lists; only the marking grammar reference shows a US-style banner, once. The leak check refuses
other control markings.
