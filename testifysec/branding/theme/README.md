# Badger theme

`theme.css` is the one stylesheet for every Badger web surface we own: the portal, the model
broker pages, edge sign-in and error pages, and the login theme of the identity provider used in
development. It is plain CSS with no fonts, images or imports, so it works air-gapped and under a
`default-src 'none'; style-src 'unsafe-inline'` policy. Inline it in a `<style>` element or serve
it from the same origin.

Light is the default. Dark follows `prefers-color-scheme`. No page carries its own mode switch, so
every page behaves the same; an embedding app may pin a mode with `data-theme="light|dark"` on
`<html>`.

Every color pair below meets WCAG AA (4.5:1 for text, 3:1 for control borders and focus) in both
modes. Focus is a 2px outline in `--c-focus`.

Classification and marking banners are never styled by this file. A banner keeps its official
colors in both modes; place it outside any themed container if its own CSS is not explicit.

## Tokens

| Token | Light | Dark | Use |
|---|---|---|---|
| `--c-bg` | `#f6f7f9` | `#111418` | page background |
| `--c-surface` | `#ffffff` | `#181c21` | cards, inputs, top bar |
| `--c-surface-2` | `#eef1f4` | `#21262d` | code, hover rows |
| `--c-text` | `#1b1f24` | `#e6e9ed` | body text |
| `--c-text-muted` | `#535c67` | `#a2abb6` | secondary text, table headers |
| `--c-border` | `#d5dae1` | `#2f363f` | dividers, card edges |
| `--c-control` | `#7d8794` | `#6b7684` | input and button borders |
| `--c-accent` / `--c-accent-hover` | `#1d5fc4` / `#174d9f` | `#7eaaf7` / `#a3c3fa` | links, primary buttons |
| `--c-on-accent` | `#ffffff` | `#0d1420` | text on accent |
| `--c-focus` | `#1d5fc4` | `#7eaaf7` | focus outline |
| `--c-danger` / `--c-danger-bg` | `#b3261e` / `#fdecea` | `#ff8f85` / `#3a1d1b` | errors, refusals |
| `--c-warning` / `--c-warning-bg` | `#8a5300` / `#fdf3e2` | `#f0b450` / `#352a14` | warnings |
| `--c-success` / `--c-success-bg` | `#1b7a3d` / `#e8f5ec` | `#63cb8c` / `#16301f` | success |
| `--c-info-bg` | `#e9f0fb` | `#182538` | neutral notices |

Type: `--font-sans` (system stack), `--font-mono`; sizes `--fs-1`..`--fs-6` = 12, 14, 16, 18, 22,
28px; line height `--lh` 1.5. Spacing `--sp-1`..`--sp-7` = 4, 8, 12, 16, 24, 32, 48px. Radius
`--r-1`..`--r-3` = 4, 6, 10px. Page width `--page-max` 1100px.

## Classes

`.page` (centered column), `.topbar` with `.brand`, `nav`, `.spacer`, `.who`; `.card`; `.table-wrap`;
`.muted`, `.small`, `.mono`, `.eyebrow`; `.badge` and `.notice` with `.is-ok`, `.is-warning`,
`.is-danger`, `.is-info`; `.btn`, `.btn-primary`, `.btn-danger`, `.btn-link`; `.center` for
single-message pages; `.nowrap`.

Forms: `.form` (grid), `.field` holding a `label`, the control, optional `.help` and
`.field-error`; `.required` on a label; `.check` for a checkbox row; `.actions` for the button row.
Mark an invalid control `aria-invalid="true"` and point its `aria-describedby` at the
`.field-error`; both come from the server, so errors need no script. A form-level error is a
`.notice.is-danger` with `role="alert"`.

## Copies

Go packages cannot embed a file outside their directory, so the portal and the model broker carry
a byte-identical copy, and a test in each fails if it drifts from this file. Edit here, then run
`testifysec/branding/theme/sync.sh`.
