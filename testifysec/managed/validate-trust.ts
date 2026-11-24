import { admissionContract } from "./profile-contract"
import { strictJSON } from "./strict-json"

admissionContract(strictJSON(await Bun.stdin.text()))
