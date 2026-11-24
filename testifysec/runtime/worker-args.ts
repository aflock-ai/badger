// build-worker.ts arguments: OUTPUT [TARGET] [fixture] in that order, with the marking flags
// (--data-marking=, --allowed-markings=, --marking-scheme=) accepted anywhere and kept out of the
// positional slots.
export function workerArgs(argv: string[]) {
  const markingArgs = argv.filter((arg) =>
    ["--data-marking=", "--allowed-markings=", "--marking-scheme="].some((flag) => arg.startsWith(flag)),
  )
  const [output, target = "bun-linux-arm64", mode] = argv.filter((arg) => !markingArgs.includes(arg))
  return { output, target, fixture: mode === "fixture", markingArgs }
}
