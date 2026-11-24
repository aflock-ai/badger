import type { ComponentProps } from "solid-js"
import { AppBrand } from "./brand"

// A managed build aliases @opencode/ui/logo here (see vite.js), with the same exports and data-component names so
// existing styles still size each mark. Everything is drawn inline in currentColor: the product name and a plain
// monogram, no vendor mark and no image request.
const monogram =
  "M4 2h8a5 5 0 0 1 3.6 8.5A5.5 5.5 0 0 1 12.5 20H4zM8 5.8v3.7h3.6a1.85 1.85 0 0 0 0-3.7zM8 12.8v3.4h4a1.7 1.7 0 0 0 0-3.4z"

export function Mark(props: { class?: string }) {
  return (
    <svg class={props.class} data-component="logo-mark" viewBox="0 0 20 22" role="img" aria-label={AppBrand.name}>
      <path d={monogram} fill="currentColor" fill-rule="evenodd" />
    </svg>
  )
}

export function Splash(props: Pick<ComponentProps<"svg">, "ref" | "class">) {
  return (
    <svg
      ref={props.ref}
      class={props.class}
      data-component="logo-splash"
      viewBox="0 0 20 22"
      role="img"
      aria-label={AppBrand.name}
    >
      <path d={monogram} fill="currentColor" fill-rule="evenodd" />
    </svg>
  )
}

export function Logo(props: { class?: string }) {
  return (
    <svg class={props.class} viewBox="0 0 720 129" role="img" aria-label={AppBrand.name}>
      <text
        x="360"
        y="104"
        fill="currentColor"
        font-family="inherit"
        font-size="118"
        font-weight="700"
        text-anchor="middle"
        textLength="700"
        lengthAdjust="spacingAndGlyphs"
      >
        {AppBrand.name.toUpperCase()}
      </text>
    </svg>
  )
}
