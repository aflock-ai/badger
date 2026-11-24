#!/usr/bin/env python3
# jade:ring local
"""Compile a Bun artifact containing real native Go fixtures; no credentials/network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import time

SOURCE=Path(__file__).resolve().parent
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',required=True,type=Path)
    parser.add_argument('--bun',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if platform.system()!='Darwin':raise RuntimeError('This execution harness currently covers macOS only')
    out=args.output.absolute();out.mkdir(mode=0o700)
    inputs=['embedded.ts','assets-build.ts','native-assets.ts','assets.ts','EMBEDDED.md','fixtures/entry.ts','fixtures/build.ts','fixtures/fixture.go','uat-embedded.py']
    source_hashes=lambda:{name:digest(SOURCE/name) for name in inputs}
    report={'schema':'testifysec.hardened-code.embedded-commands-uat/v1','passed':False,'checks':[],'cases':[],
            'sourceFiles':source_hashes(),'strictJSONSha256':digest(SOURCE.parent/'managed/strict-json.ts'),
            'runtimeOS':'darwin','runtimeArch':platform.machine(),'releaseQualified':False,'liveEnrollment':False,
            'limitations':['Native fixtures only; actual enrollment/attestation semantics have separate acceptance tests.',
                           'Same-user command runner, not sandbox isolation or signing authority.',
                           'Windows execution explicitly refused pending native custody integration. Linux runtime not executed by this harness.']}
    def check(name,condition):
        report['checks'].append({'name':name,'passed':bool(condition)})
        if not condition:raise AssertionError(name)
    guard=['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)']
    try:
        source_run=subprocess.run(guard+[str(args.bun),str(SOURCE/'fixtures/entry.ts'),'normal',str(out)],cwd=SOURCE,capture_output=True,timeout=10)
        check('ordinary-source-import-needs-no-build-plugin',source_run.returncode==1 and json.loads(source_run.stdout).get('code')=='helper-not-bundled' and not source_run.stderr)
        native=out/'fixture-native'
        env=dict(os.environ,GOTOOLCHAIN='local',GOWORK='off',GOPROXY='off',GOSUMDB='off',CGO_ENABLED='0',GOMAXPROCS='2')
        subprocess.run([str(args.go),'build','-trimpath','-buildvcs=false','-o',str(native),str(SOURCE/'fixtures/fixture.go')],env=env,capture_output=True,check=True,timeout=120)
        report['nativeSha256']=digest(native)
        arch='arm64' if platform.machine()=='arm64' else 'amd64';target='bun-darwin-'+('arm64' if arch=='arm64' else 'x64')
        asset={'file':str(native),'os':'darwin','arch':arch,'sha256':digest(native),'size':native.stat().st_size,'timeoutSeconds':2}
        spec={'schema':'testifysec.hardened-code.native-assets/v1','assets':[dict(asset,role=role) for role in ['enroll','attest']]}
        manifest=out/'assets.json';manifest.write_text(json.dumps(spec))
        def build(name,manifest_path=manifest,tamper=''):
            output=out/name
            result=subprocess.run(guard+[str(args.bun),str(SOURCE/'fixtures/build.ts'),str(output),str(manifest_path),target,tamper],cwd=SOURCE,capture_output=True,timeout=120)
            return output,result
        for name,value in [('duplicate-role',dict(spec,assets=[spec['assets'][0],spec['assets'][0]])),
                           ('missing-role',dict(spec,assets=[spec['assets'][0]])),
                           ('wrong-pin',dict(spec,assets=[dict(spec['assets'][0],sha256='0'*64),spec['assets'][1]])),
                           ('wrong-target',dict(spec,assets=[dict(item,os='linux') for item in spec['assets']]))]:
            bad=out/(name+'.json');bad.write_text(json.dumps(value));binary,result=build(name,bad)
            check('build-refuses-'+name,result.returncode!=0 and not binary.exists())
        duplicate=out/'duplicate-key.json';duplicate.write_text(json.dumps(spec).replace('"schema":','"schema":"other","schema":',1))
        binary,result=build('duplicate-key',duplicate);check('build-refuses-duplicate-json',result.returncode!=0 and not binary.exists())
        compiled={}
        lifecycle_faults=['unobserved-exit','kill-failure','pipe-drain-failure','mkdir-collision','directory-open-failure']
        report['compiledFaultFixtures']=lifecycle_faults
        for name,selected,tamper in [('normal',manifest,''),('wrong-runtime-pin',manifest,'pin'),('duplicate-runtime-role',manifest,'duplicate'),('missing-helper','none','')]+[(fault,manifest,fault) for fault in lifecycle_faults]:
            binary,result=build(name,selected,tamper)
            check('compiled-'+name,result.returncode==0)
            compiled[name]=binary
        native.unlink();manifest.unlink()
        check('original-native-inputs-removed',not native.exists() and not manifest.exists())
        report['binarySha256']={name:digest(file) for name,file in compiled.items()}
        poison=out/'poison';poison.mkdir(mode=0o700);trap=out/'path-trap'
        for name in ['node','npm','bun','go','enroll','attest']:
            file=poison/name;file.write_text('#!/bin/sh\n: > '+shlex.quote(str(trap))+'\nexit 99\n');file.chmod(0o700)
        def execute(name,mode,binary='normal',expected=True,code=None,retained=False):
            state=out/('state-'+name);state.mkdir(mode=0o700)
            start=time.monotonic()
            result=subprocess.run(guard+[str(compiled[binary]),mode,str(state)],cwd=state,env={'PATH':str(poison),'HOME':str(state),'TMPDIR':str(poison)},capture_output=True,timeout=12)
            value=json.loads(result.stdout)
            report['cases'].append({'name':name,'result':value,'exitCode':result.returncode,'elapsedSeconds':time.monotonic()-start,'stdoutSha256':hashlib.sha256(result.stdout).hexdigest(),'stderrSha256':hashlib.sha256(result.stderr).hexdigest()})
            check(name+'-result',value['passed'] is expected and result.returncode==(0 if expected else 1) and (code is None or value.get('code')==code))
            check(name+'-no-raw-output',not result.stderr and b'fixture-secret-must-never-print' not in result.stdout and b'synthetic-poison' not in result.stdout)
            marker=state/'started.json'
            if marker.exists():
                facts=json.loads(marker.read_bytes())
                check(name+'-fixed-role-argv',facts['args']==(['attest'] if mode=='attest' else ['enroll']))
                environment=dict(item.split('=',1) for item in facts['environment'])
                check(name+'-scrubbed-native-environment',set(environment)==({'PATH','HOME','TMPDIR','LANG','CILOCK_STATE_DIR'} if mode=='platform' else {'PATH','HOME','TMPDIR','LANG'}) and environment['PATH']=='/usr/bin:/bin' and 'synthetic-poison' not in json.dumps(environment))
                if mode=='platform':check('bound-platform-state-directory',environment['CILOCK_STATE_DIR']==str(state/'platform'))
                if retained:
                    payload=Path(facts['executable']);directory=Path(facts['cwd'])
                    check(name+'-private-payload-retained',payload.is_file() and digest(payload)==report['nativeSha256'] and directory.stat().st_mode&0o777==0o700)
                    try:os.kill(facts['pid'],0)
                    except ProcessLookupError:check(name+'-real-native-exited',True)
                    else:raise AssertionError('fault fixture native process remains live')
                    # Harness owns this exact fixture directory. The runner
                    # intentionally retained it; cleanup below is not its claim.
                    check(name+'-retained-fixture-path',directory.parent==Path('/private/tmp') and directory.name.startswith('aflock-command-') and payload==directory/'command')
                    shutil.rmtree(directory)
                    check(name+'-harness-removed-retained-fixture',not directory.exists())
                else:check(name+'-private-payload-removed',not Path(facts['executable']).exists() and not Path(facts['cwd']).exists())
                if 'childPid' in facts:
                    deadline=time.monotonic()+2
                    while time.monotonic()<deadline:
                        try:os.kill(facts['childPid'],0)
                        except ProcessLookupError:break
                        time.sleep(.02)
                    else:raise AssertionError('fixture descendant not removed')
                    check('owned-descendant-removed',True)
            else:check(name+'-before-native-start',not expected)
            if mode=='mkdir-collision':
                collision=state/'mkdir-collision'
                check('mkdir-collision-unowned-target-retained',(collision/'unowned-sentinel').read_text()=='fixture-owned before runner mkdir')
            if mode=='directory-open-failure':
                directory=Path(json.loads((state/'fault-directory.json').read_bytes())['directory'])
                check('directory-open-failure-created-directory-retained',directory.parent==Path('/private/tmp') and directory.name.startswith('aflock-command-') and directory.stat().st_mode&0o777==0o700 and not any(directory.iterdir()))
                directory.rmdir()
                check('directory-open-failure-harness-removed-retained-fixture',not directory.exists())
            check(name+'-no-path-or-install-fallback',not trap.exists())
            return value
        for mode in ['normal','attest','platform','descendant']:execute(mode,mode)
        value=execute('nonzero','nonzero');check('native-nonzero-preserved',value['exitCode']==7)
        for mode,code in [('invalid-utf8','event-refused'),('duplicate','event-refused'),('unknown-event','event-refused'),('wrong-role','event-refused'),('truncated','event-refused'),('overflow','event-refused'),('stderr','stderr-limit'),('callback','event-refused'),('hang','deadline'),('cancel','cancelled'),('signal','cancelled'),('cancel-before','cancelled'),('request-size','request-encoding'),('request-accessor','request-accessor'),('unknown-role','unknown-role')]:execute(mode,mode,expected=False,code=code)
        execute('wrong-pin','normal','wrong-runtime-pin',False,'embedded-integrity')
        # A duplicate embedded manifest is rejected before materialization. Its
        # generic validation error remains private, never native stderr.
        execute('duplicate-runtime','normal','duplicate-runtime-role',False,'unclassified')
        execute('missing-helper','normal','missing-helper',False,'helper-not-bundled')
        for mode in ['unobserved-exit','kill-failure','pipe-drain-failure']:
            execute(mode,mode,mode,False,'cleanup-incomplete',retained=True)
        execute('mkdir-collision','mkdir-collision','mkdir-collision',False,'EEXIST')
        execute('directory-open-failure','directory-open-failure','directory-open-failure',False,'cleanup-incomplete')
        check('source-snapshot-unchanged',source_hashes()==report['sourceFiles'])
        check('compiled-inputs-unchanged',all(digest(compiled[name])==sha for name,sha in report['binarySha256'].items()))
        report['passed']=True
    finally:(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),'report':str(out/'report.json'),'sha256':digest(out/'report.json')}))
if __name__=='__main__':main()
