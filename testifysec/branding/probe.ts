// jade:ring local
// Compiled by branding/uat.py with HARDENED_BUILD true, false or unset; prints what each build would show.
import { Branding } from "./product"
import { CliBrand } from "../../packages/cli/src/brand"
import { ManagedProfile } from "../../packages/server/src/managed"

const document = ManagedProfile.document
const managed = document.providers?.managed
process.stdout.write(JSON.stringify({
  enabled: Branding.enabled,
  name: Branding.name,
  command: CliBrand.name,
  description: CliBrand.description,
  version: CliBrand.version("fixture-upstream"),
  about: CliBrand.about("fixture-upstream"),
  provider: managed?.name,
  model: managed?.models?.approved?.name,
  modelID: `${document.model?.providerID}/${document.model?.model}`,
  providers: Object.keys(document.providers ?? {}),
  package: managed?.package,
}) + "\n")
