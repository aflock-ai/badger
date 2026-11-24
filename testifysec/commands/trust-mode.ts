export const TRUST_MODE_ENV = "AFLOCK_TRUST_MODE"
export const trustModes = ["platform", "local-self-signed"] as const
export type TrustMode = (typeof trustModes)[number]

export function trustMode(option: string | undefined, environment: Record<string, string | undefined>, setting?: TrustMode): TrustMode {
  const value = option ?? environment[TRUST_MODE_ENV] ?? setting ?? "platform"
  if (value === "platform" || value === "local-self-signed") return value
  throw new Error(`${TRUST_MODE_ENV} / --trust-mode must be platform or local-self-signed`)
}
