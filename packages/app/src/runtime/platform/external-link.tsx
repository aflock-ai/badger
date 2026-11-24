import { ComponentProps, splitProps } from "solid-js"

declare const HARDENED_BUILD: boolean

export interface ExternalLinkProps extends Omit<ComponentProps<"a">, "href"> {
  /** Absent where a managed build drops the outside address at compile time. */
  href?: string
}

// A managed deployment reaches nothing outside itself, so its build shows every outside reference as plain text.
export function ExternalLink(props: ExternalLinkProps) {
  const [local, rest] = splitProps(props, ["href", "children", "class", "target", "rel"])

  if (typeof HARDENED_BUILD !== "undefined" && HARDENED_BUILD || !local.href) return <span class={local.class}>{local.children}</span>

  return (
    <a
      href={local.href}
      class={`text-text-strong underline ${local.class ?? ""}`}
      target={local.target ?? "_blank"}
      rel={local.rel ?? "noopener noreferrer"}
      {...rest}
    >
      {local.children}
    </a>
  )
}
