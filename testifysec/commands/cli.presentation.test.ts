// jade:ring local
import { expect, test } from "bun:test"
import path from "node:path"

const state = "fixture-state-must-stay-private"
const sealing = "fixture-seal-pub-must-stay-private"
const ceremony = {
  schema: "testifysec.hardened-code.command-event/v1", event: "ceremony", trustMode: "platform",
  platformURL: "https://platform.example.test", browserOpened: false,
  url: `https://platform.example.test/auth/agent-enroll?state=${state}&seal_pub=${sealing}`,
}

// A real anonymous PTY exercises the actual stdout.isTTY branch. This opens no
// terminal application, browser or ceremony; every URL/parameter is synthetic.
const pty = String.raw`
import errno,os,pty,select,subprocess,sys,time
master,slave=pty.openpty()
process=None
try:
 process=subprocess.Popen(sys.argv[1:],stdin=subprocess.DEVNULL,stdout=slave,stderr=subprocess.PIPE)
 os.close(slave);slave=-1
 output=bytearray();deadline=time.monotonic()+5
 while time.monotonic()<deadline:
  if not select.select([master],[],[],0.1)[0]:continue
  try:chunk=os.read(master,4096)
  except OSError as error:
   if error.errno==errno.EIO:break
   raise
  if not chunk:break
  output.extend(chunk)
  if len(output)>16384:raise RuntimeError('fixture output exceeded bound')
 else:raise RuntimeError('fixture PTY deadline')
 _,errors=process.communicate(timeout=1)
 sys.stdout.buffer.write(output);sys.stderr.buffer.write(errors)
 sys.exit(process.returncode)
finally:
 if process is not None and process.poll() is None:process.kill();process.wait(timeout=2)
 os.close(master)
 if slave!=-1:os.close(slave)
`

async function present(event: Record<string, unknown>, json: boolean, terminal: boolean, role = "enroll", mode = "platform") {
  const script = `import { presentCommandEvent } from ${JSON.stringify(path.join(import.meta.dir, "cli.ts"))};
    if ((process.stdout.isTTY === true) !== ${terminal}) throw new Error("fixture TTY not established");
    presentCommandEvent(${JSON.stringify(role)}, ${JSON.stringify(mode)}, ${JSON.stringify(event)}, ${json});`
  const command = [process.execPath, "--eval", script]
  const child = Bun.spawn({
    cmd: terminal ? ["/usr/bin/python3", "-c", pty, ...command] : command,
    env: { PATH: "/usr/bin:/bin", LANG: "C", TMPDIR: "/tmp" },
    stdin: "ignore", stdout: "pipe", stderr: "pipe",
  })
  const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited])
  expect(code).toBe(0)
  expect(stderr).toBe("")
  return stdout.replaceAll("\r\n", "\n")
}

for (const terminal of [false, true]) {
  for (const json of [false, true]) {
    for (const browserOpened of [false, true]) {
      test(`ceremony URL presentation: terminal=${terminal} json=${json} browserOpened=${browserOpened}`, async () => {
        const output = await present({ ...ceremony, browserOpened }, json, terminal)
        if (terminal && !json && !browserOpened) {
          expect(output).toContain(ceremony.url)
          return
        }
        expect(output).not.toContain(state)
        expect(output).not.toContain(sealing)
        expect(output).not.toContain("state=")
        expect(output).not.toContain("seal_pub=")
        if (json) {
          const event = JSON.parse(output)
          expect(event.event).toBe("ceremony")
          expect(event.browserOpened).toBe(browserOpened)
          expect(event.platformURL).toBe(ceremony.platformURL)
          expect(event).not.toHaveProperty("url")
          if (!browserOpened) expect(event.message).toContain("interactive terminal")
        } else if (!browserOpened) expect(output).toContain("interactive terminal")
        else expect(output).toContain("in your browser")
      })
    }
  }
}

test("JSON omits ceremony links and unknown secret fields from all event kinds", async () => {
  const output = await present({ ...ceremony, event: "enrolled", identityReference: "spiffe://fixture/agent/1",
    refreshCredential: "fixture-refresh-must-stay-private", privateKey: "fixture-key-must-stay-private" }, true, false)
  const event = JSON.parse(output)
  expect(event.identityReference).toBe("spiffe://fixture/agent/1")
  for (const field of ["url", "refreshCredential", "privateKey"]) expect(event).not.toHaveProperty(field)
  for (const secret of [state, sealing, "fixture-refresh-must-stay-private", "fixture-key-must-stay-private"]) expect(output).not.toContain(secret)
})

test("attestation presentation retains distinct platform and untrusted local outcomes", async () => {
  const event = { schema: ceremony.schema, event: "attested", evidenceGitoid: "gitoid:fixture", envelopeFile: "/fixture/evidence.json" }
  expect(await present({ ...event, status: "platform-upload-acknowledged" }, false, false, "attest"))
    .toContain("Platform acknowledged the attestation upload")
  expect(await present(event, false, false, "attest", "local-self-signed"))
    .toContain("not platform trusted")
})
