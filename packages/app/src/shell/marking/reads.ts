import { combineMarkings, unknown, type BannerMarking, type ReportedScheme, type ServerMarking } from "./combine"

export * as MarkingReads from "./reads"

/** A healthy server, and whether its event connection is up. */
export type ServerState<K extends string = string> = { readonly key: K; readonly live: boolean }

/**
 * Each server's marking, read while its connection is up. A server that disconnects, restarts or
 * leaves loses its read and is read again when it is back, so a server that returns with a higher
 * marking is never shown under its old one. A read still in flight from before is ignored.
 */
export function make<K extends string>(
  read: (
    key: K,
  ) => Promise<
    string | null | { readonly marking: string | null; readonly scheme?: ReportedScheme; readonly label?: string | null }
  >,
  changed: () => void,
) {
  const reads = new Map<K, ServerMarking>()
  const generations = new Map<K, number>()

  function forget(key: K) {
    generations.set(key, (generations.get(key) ?? 0) + 1)

    if (reads.delete(key)) changed()
  }

  function sync(servers: readonly ServerState<K>[]) {
    const listed = new Set(servers.map((server) => server.key))

    for (const key of [...reads.keys()]) if (!listed.has(key)) forget(key)

    for (const server of servers) {
      if (!server.live) {
        forget(server.key)
        continue
      }

      if (reads.has(server.key)) continue

      start(server.key)
    }
  }

  /** Reads one server, replacing any read in flight; it shows as loading until it answers. */
  function start(key: K) {
    const generation = (generations.get(key) ?? 0) + 1
    generations.set(key, generation)
    reads.set(key, { type: "loading" })
    changed()

    const settle = (marking: ServerMarking) => {
      if (generations.get(key) !== generation) return

      reads.set(key, marking)
      changed()
    }

    read(key).then(
      (answer) => {
        const read: ServerMarking =
          answer !== null && typeof answer === "object"
            ? { type: "marking", marking: answer.marking, scheme: answer.scheme, label: answer.label }
            : { type: "marking", marking: answer }
        // An unknown marking makes the banner unavailable (combineMarkings); say which server.
        if (unknown(read))
          console.warn("[marking] server reported an unknown marking; the banner shows unavailable", key)
        settle(read)
      },
      () => settle({ type: "unavailable" }),
    )
  }

  /**
   * A server announced that its workspace label rose: read it again. Until it answers it shows as
   * loading, never under its old, lower label. A server not being read is read when it is back.
   */
  function refresh(key: K) {
    if (reads.has(key)) start(key)
  }

  /** A server that is not live, or not read yet, counts as loading: never as a lower marking. */
  function marking(servers: readonly ServerState<K>[]): BannerMarking {
    return combineMarkings(
      servers.map((server) => (server.live ? (reads.get(server.key) ?? { type: "loading" }) : { type: "loading" })),
    )
  }

  return { sync, marking, refresh }
}
