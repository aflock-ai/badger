// jade:ring local
import fs from "node:fs/promises"
import path from "node:path"
import { nativeAssets,nativeAssetsPlugin } from "../assets-build"
const [output,manifest,target,tamper] = process.argv.slice(2)
const selected=await nativeAssets(manifest==="none"?undefined:manifest,target)
if(tamper==="pin") selected.assets[0].sha256="0".repeat(64)
if(tamper==="duplicate") selected.assets=[selected.assets[0],selected.assets[0]]
const stage=await fs.mkdtemp(path.join(path.dirname(output),"stage-"));await fs.chmod(stage,0o700)
try {
 const plugins = [await nativeAssetsPlugin(selected,stage)]
 // Compile-time fault injection only: the shipping runner has no environment,
 // request or build-manifest switch for overriding its cleanup decisions.
 const faults: Record<string, [string,string][]> = {
  "unobserved-exit": [
   ['child!.once("exit", (code, signal) => { exitObserved = true; resolve(code ?? 128 + (signal ? os.constants.signals[signal] : 0)) })','child!.once("exit", () => { /* fixture suppresses exit observation */ })'],
   ['await within(exited, selected.timeoutSeconds * 1000 + 5000)','await within(exited, 100)'],
   ['if (!exitObserved && exited) await within(exited, 2000)','if (!exitObserved && exited) await within(exited, 100)'],
  ],
  "kill-failure": [['if (ownedPid === undefined) return','if (ownedPid === undefined) return; throw new NativeCommandError("fixture-kill-failure")']],
  "pipe-drain-failure": [
   ['drained = Promise.all([output, errors]).then(() => true)','drained = new Promise<boolean>(() => {}); void Promise.all([output, errors])'],
   ['await within(drained, 2000)','await within(drained, 100)'],
  ],
  "mkdir-collision": [['directory = path.join(parent, "aflock-command-" + randomBytes(24).toString("hex"))','directory = path.join(process.argv[3], "mkdir-collision")']],
  "directory-open-failure": [['directoryHandle = await fs.open(directory, constants.O_RDONLY | constants.O_NOFOLLOW)','await fs.writeFile(path.join(process.argv[3], "fault-directory.json"), JSON.stringify({directory})); throw new NativeCommandError("fixture-directory-open-failure")']],
 }
 if(faults[tamper]) plugins.push({name:"compiled-lifecycle-fault",setup(build){build.onLoad({filter:/[\\/]commands[\\/]embedded\.ts$/},async args=>{
  if(path.resolve(args.path)!==path.resolve(import.meta.dir,"../embedded.ts"))return undefined
  let source=await fs.readFile(args.path,"utf8")
  for(const [before,after] of faults[tamper]) {
   if(!source.includes(before))throw new Error("fixture source injection no longer matches")
   source=source.replaceAll(before,after)
  }
  return {loader:"ts",contents:source}
 })}})
 const build=await Bun.build({entrypoints:[path.join(import.meta.dir,"entry.ts")],plugins,
  compile:{target:target as "bun-darwin-arm64",outfile:output,autoloadBunfig:false,autoloadDotenv:false,autoloadTsconfig:false,autoloadPackageJson:false,execArgv:["--"]}})
 if(!build.success)throw new Error(String(build.logs))
}finally{await fs.rm(stage,{recursive:true,force:true})}
