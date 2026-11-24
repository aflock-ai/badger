export * as AppBrand from "./brand"

declare const HARDENED_BUILD: boolean
declare const HARDENED_PRODUCT_NAME: string

// Display only. The app's vite plugin sets both at build time from testifysec/branding/product.json;
// an upstream build keeps OpenCode's name. This grants no authority.
export const enabled = typeof HARDENED_BUILD !== "undefined" && HARDENED_BUILD
export const name = enabled && typeof HARDENED_PRODUCT_NAME === "string" ? HARDENED_PRODUCT_NAME : "OpenCode"
// The managed build opens on the neutral Badger theme; a theme the person picked still wins.
export const defaultTheme = enabled ? "badger" : undefined

// OpenCode's own services and the upstream project keep their names: the Go, Zen, Console and Free
// offerings, the provider sign-in flow, the version a server runs, the documentation link (it opens
// OpenCode's docs), and Settings > About, which credits OpenCode's authors and carries its trademark.
const kept =
  /^(?:provider\.connect\.(?:opencode|console|remote)\.|dialog\.model\.unpaid\.freeModels\.|settings\.about\.|desktop\.menu\.documentation$)/
// Upstream's own support channels (its team on Discord, its website). A managed deployment's people are
// supported by their administrators, so these read empty; the error page says to contact them instead.
const withheld = /^(?:error\.page\.report\.(?:prefix|discord)|settings\.about\.website)$/
const product = /\b(?:(an?) )?OpenCode\b(?! (?:Zen|Go|Console|Free|V2)\b| \{\{version\}\})/g

/** Renames the product in owned UI copy, before interpolation. Never applied to model output or user content. */
export function withProductBrand<T extends Record<string, string>>(dictionary: T): T {
  if (!enabled) return dictionary
  const article = /^[aeiou]/i.test(name) ? "an" : "a"
  return Object.fromEntries(
    Object.entries(dictionary).map(([key, text]) => [
      key,
      withheld.test(key) ? "" : kept.test(key) ? text : text.replace(product, (_, before?: string) => (before ? `${article} ${name}` : name)),
    ]),
  ) as T
}
