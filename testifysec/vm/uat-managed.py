#!/usr/bin/env python3
# jade:ring local
"""V3 regular-file/result UAT: real VZ, native fault workers and compiled OpenCode."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import uuid

SOURCE = Path(__file__).resolve().parent

def sha(raw): return hashlib.sha256(raw).hexdigest()
def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda:f.read(1<<20),b''): h.update(part)
    return h.hexdigest()
def compact(value): return json.dumps(value,separators=(',',':'),ensure_ascii=True).encode()
def save(path,value): path.write_bytes(compact(value));path.chmod(0o600)
def sources(root): return {str(p.relative_to(root)):digest(p) for p in sorted(root.rglob('*')) if p.is_file() and p.suffix in ('.go','.mod','.sum','.swift','.py','.md','.plist')}
def material(name,raw,executable=False): return {'path':name,'sha256':sha(raw),'size':len(raw),'executable':executable,'contentBase64':base64.b64encode(raw).decode()}
def manifest(files):
    # Match the documented Go descriptor order and HTML escaping of '&'.
    values=[{k:f[k] for k in ('path','sha256','size','executable')} for f in files]
    return sha(compact(values).replace(b'&',b'\\u0026'))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--worker',required=True,type=Path)
    parser.add_argument('--worker-inputs',required=True,type=Path)
    args=parser.parse_args()
    out=args.output.absolute();out.mkdir(mode=0o700)
    before=sources(SOURCE)
    report={'schema':'testifysec.vm-managed-uat/v1','passed':False,'checks':[],'cases':[],
            'sourceFiles':before,'revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=SOURCE,text=True).strip(),
            'worktreeDirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=SOURCE)),
            'scope':'developer-assigned V3 VM job and regular-file observations; no signed VM authorization or finalized signing record',
            'admissionIntegrated':False,'releaseQualified':False,'dockerInvocations':0,'liveProviderCalls':False}
    spec=importlib.util.spec_from_file_location('relay_io',SOURCE/'uat-relay-io.py');io=importlib.util.module_from_spec(spec);spec.loader.exec_module(io)
    server=None;thread=None;gateway=None;gateway_log=None
    def check(name,ok):
        report['checks'].append({'name':name,'passed':bool(ok)})
        if not ok: raise RuntimeError(name)
    def run(argv,name,timeout=180,limit=1<<20):
        result=io.run(argv,out,timeout,output_limit=limit)
        (out/(name+'.stdout')).write_bytes(result['stdout']);(out/(name+'.stderr')).write_bytes(result['stderr'])
        check(name+'-bounded-observed-exit',result['exitObserved'] and not result['forcedKill'] and result['error'] is None)
        return result
    env=['/usr/bin/env','GOWORK=off','GOTOOLCHAIN=local','GOPROXY=off','GOSUMDB=off','GOMAXPROCS=2',
         'GOCACHE='+str(out/'go-cache'),'GOOS=linux','GOARCH=arm64','CGO_ENABLED=0']
    def build(name,root,reuse=None):
        command=[sys.executable,'-B',SOURCE/'build.py','--go',args.go,'--output',out/name,'--mode','worker','--protocol','3','--worker-root',root]
        if reuse:command+=['--reuse',reuse]
        result=run(command,name+'-build',300)
        check(name+'-build',result['exitCode']==0)
        m=json.loads((out/name/'manifest.json').read_bytes());report.setdefault('builds',{})[name]=m
        return out/name
    def execute(name,build,prompt,expected=0,reason=None,initial=None,mutate=None,gateway_config=None):
        case=out/('case-'+str(len(report['cases'])));case.mkdir(mode=0o700)
        config=json.loads((build/'config.json').read_bytes())
        initial=initial if initial is not None else [material('delete.txt',b'remove\n'),material('keep.txt',b'original\n'),material('nested/run.sh',b'old\n')]
        request={'prompt':prompt,'timeoutSeconds':2 if prompt=='timeout' else 45}
        binding={**config['binding'],'sessionId':uuid.uuid4().hex,'requestSha256':sha(compact(request)),'materialsSha256':sha(compact(initial))}
        job={'schema':'testifysec.vm-job/v3','binding':binding,'request':request,'materials':initial}
        save(case/'job.json',job)
        config.update(binding=binding,jobFile=str(case/'job.json'),jobSha256=digest(case/'job.json'))
        if gateway_config:
            gateway_config['session']=binding['sessionId'];save(case/'gateway.json',gateway_config)
            config.update(gatewayConfigFile=str(case/'gateway.json'),gatewayConfigSha256=digest(case/'gateway.json'))
        if mutate:mutate(config,job,case)
        save(case/'config.json',config)
        if gateway_config:start_gateway(case/'gateway.json',Path(gateway_config['socket']))
        result=run([build/'hc-vm',case/'config.json'],name,75,2<<20)
        observation=json.loads(result['stdout']) if result['stdout'] else None
        record={'name':name,'exitCode':result['exitCode'],'observation':observation,'configSha256':digest(case/'config.json'),
                'jobSha256':digest(case/'job.json'),'stdoutSha256':sha(result['stdout']),'stderrSha256':sha(result['stderr'])}
        report['cases'].append(record);save(case/'observation.json',observation)
        if gateway_config:stop_gateway()
        check(name+'-expected-exit',result['exitCode']==expected)
        if expected==2:check(name+'-no-vm-result',observation is None);return record,case
        check(name+'-stopped-and-drained',observation['started'] is True and observation['stopped'] is True
              and observation['jobTransportDrained'] is True and observation['gatewayRelayDrained'] is True)
        check(name+'-no-host-sharing',observation['networkDevices']==0 and observation['sharedDirectories']==0 and observation['writableHostDisks']==0)
        guest=observation['guestResult']
        if config['schema']=='testifysec.vm-config/v2':
            check(name+'-legacy-refuses-managed-job',guest['schema']=='testifysec.vm-result/v2' and guest['error']==reason and not guest['passed'])
            return record,case
        check(name+'-exact-binding',guest['schema']=='testifysec.vm-result/v3' and observation['schema']=='testifysec.vm-observation/v3'
              and guest['binding']==binding and guest['nonce']==observation['bootNonce'] and guest['jobSha256']==config['jobSha256'])
        raw=base64.b64decode(guest['outputBase64'],validate=True)
        check(name+'-output-byte-binding',sha(raw)==guest['outputSha256'])
        if reason:check(name+'-precise-refusal',guest['error']==reason and not guest['captureComplete'] and guest['files']==[] and guest['removed']==[])
        if expected==0:
            check(name+'-whole-worker-completion',observation['passed'] is True and guest['passed'] is True and guest['exitCode']==0
                  and all(guest[k] is True for k in ['jobValidated','workerStarted','exitObserved','reaped','outputDrained','outputComplete','captureComplete']))
            check(name+'-manifest-bindings',guest['initialManifestSha256']==manifest(initial) and guest['finalManifestSha256']==manifest(guest['files']))
            after={f['path'] for f in guest['files']}
            check(name+'-complete-removals',guest['removed']==[f['path'] for f in initial if f['path'] not in after])
            check(name+'-exact-file-bytes',all(len(base64.b64decode(f['contentBase64'],validate=True))==f['size'] and sha(base64.b64decode(f['contentBase64'],validate=True))==f['sha256'] for f in guest['files']))
        return record,case
    def start_gateway(config,socket):
        nonlocal gateway,gateway_log
        gateway_log=(config.parent/'gateway.log').open('wb')
        gateway=subprocess.Popen([str(out/'gateway'), '--config',str(config)],env={'PATH':'/usr/bin:/bin'},stdout=gateway_log,stderr=gateway_log)
        end=time.monotonic()+5
        while time.monotonic()<end and not socket.exists() and gateway.poll() is None:time.sleep(.02)
        check('gateway-ready',socket.exists() and gateway.poll() is None)
    def stop_gateway():
        nonlocal gateway,gateway_log
        if gateway:
            gateway.terminate()
            try:code=gateway.wait(timeout=40)
            except subprocess.TimeoutExpired:
                gateway.kill();gateway.wait(timeout=5);raise RuntimeError('gateway shutdown forced')
            gateway=None;check('gateway-clean-exit',code==0)
        if gateway_log:gateway_log.close();gateway_log=None
    try:
        root=out/'native-root';(root/'toolpack').mkdir(parents=True)
        fixture=root/'toolpack/opencode-worker'
        compiled=run(env+[args.go,'build','-trimpath','-buildvcs=false','-o',fixture,SOURCE/'fixtures/managed-worker.go'],'fixture-build')
        check('fixture-compiled',compiled['exitCode']==0);report['fixtureSha256']=digest(fixture)
        native=build('native-build',root)
        positive,case=execute('native-recursive-edit',native,'edit')
        guest=positive['observation']['guestResult'];files={f['path']:f for f in guest['files']}
        check('native-exact-binary-output',base64.b64decode(guest['outputBase64'])==b'\xff\x00\x80stderr-tail\n')
        check('native-recursive-edit-bytes',set(files)=={'keep.txt','nested/a&b/result.bin','nested/run.sh'} and files['nested/run.sh']['executable'] is True
              and base64.b64decode(files['nested/a&b/result.bin']['contentBase64'])==b'\x00\xff\x80\n' and guest['removed']==['delete.txt'])
        execute('ordinary-zero-exit-no-marker',native,'no-marker')
        for mode,reason in [('symlink','managed-artifact-type'),('hardlink','managed-artifact-type'),('special','managed-artifact-type'),
                            ('case-collision','managed-artifact-path'),('git','managed-artifact-path'),('overflow','managed-artifact-size'),
                            ('wide','managed-artifact-count'),('output-overflow','worker-output-limit'),('timeout','worker-deadline'),('nonzero-descendant','worker-failed')]:
            record,_=execute(mode,native,mode,3,reason)
            if mode=='nonzero-descendant':check('nonzero-descendant-exit-and-real-eof',record['observation']['guestResult']['exitCode']==7 and record['observation']['guestResult']['reaped'] is True and record['observation']['guestResult']['outputDrained'] is True)
        execute('large-material-frame',native,'no-marker',initial=[material('large.bin',b'x'*65536)])
        execute('tampered-job',native,'no-marker',2,mutate=lambda config,job,case:config.update(jobSha256='0'*64))
        execute('unapproved-path',native,'no-marker',2,initial=[material('.git/config',b'x')])
        execute('case-prefix-collision',native,'no-marker',2,initial=[material('A/file',b'x'),material('a/other',b'y')])
        execute('version-downgrade',native,'no-marker',3,'job-assignment-binding',mutate=lambda config,job,case:config.update(schema='testifysec.vm-config/v2'))

        # Compile and execute actual capture/parser Go tests inside a fresh Linux VM.
        tests_root=out/'tests-root';(tests_root/'toolpack').mkdir(parents=True)
        result=run(env+[args.go,'-C',SOURCE/'guest','test','-c','-mod=readonly','-o',tests_root/'toolpack/opencode-worker','.'],'guest-tests-build')
        check('guest-tests-compiled',result['exitCode']==0)
        tests=build('tests-build',tests_root,native);execute('actual-linux-guest-tests',tests,'ignored',initial=[])

        # Exercise exact Swift validation functions against captured real result bytes.
        prefix=(SOURCE/'host/main.swift').read_text().split('final class Runner:',1)[0]
        (out/'validation-types.swift').write_text(prefix)
        compiled=run(['/usr/bin/swiftc','-swift-version','5','-module-cache-path',out/'swift-validation-cache','-parse-as-library',
                      out/'validation-types.swift',SOURCE/'host/managed.swift',SOURCE/'fixtures/managed-validation.swift','-o',out/'validate'],'validation-build')
        check('validator-compiled',compiled['exitCode']==0)
        valid=json.loads(compact(guest));valid['nonce']='0123456789abcdef0123456789abcdef'
        for name,change in [('valid',None),('hash',lambda v:v['files'][0].update(sha256='0'*64)),('mode',lambda v:v['files'][0].update(executable=not v['files'][0]['executable'])),
                            ('missing-file',lambda v:v['files'].pop()),('removed',lambda v:v.update(removed=[])),('exit',lambda v:v.update(exitCode=7)),
                            ('reap',lambda v:v.update(reaped=False)),('drain',lambda v:v.update(outputDrained=False)),('nonce',lambda v:v.update(nonce='0'*32)),
                            ('base64',lambda v:v.update(outputBase64=v['outputBase64']+'=')),('unknown',lambda v:v.update(authority=True))]:
            value=json.loads(compact(valid))
            if change:change(value)
            mutation=out/('result-'+name+'.json');save(mutation,value)
            result=run([out/'validate',case/'config.json',case/'job.json',mutation],'validate-'+name,10)
            check('validate-'+name+'-decision',result['exitCode']==(0 if change is None else 2))
            report.setdefault('validationCases',[]).append({'name':name,'inputSha256':digest(mutation),'exitCode':result['exitCode'],
                                                           'stdoutSha256':sha(result['stdout']),'stderrSha256':sha(result['stderr'])})

        # Build the real retained gateway-mode OpenCode executable into the same
        # immutable image, with a test-only static utility reached through Bash.
        inputs=json.loads((args.worker_inputs/'manifest.json').read_bytes())
        actual_root=out/'actual-root';actual_root.mkdir(mode=0o700)
        for name,facts in inputs['files'].items():
            if name=='toolpack/opencode-worker':continue
            source=args.worker_inputs/'root'/name
            check('retained-input-'+name,digest(source)==facts['sha256'])
            target=actual_root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
            check('copied-retained-input-'+name,digest(target)==facts['sha256'] and digest(source)==facts['sha256'])
        wm=json.loads(Path(str(args.worker)+'.manifest.json').read_bytes())
        check('actual-worker-pinned',wm['fixtureModel'] is False and wm['binarySha256']==digest(args.worker))
        report['workerBuildManifest']=wm;report['retainedInputManifest']=inputs
        (actual_root/'toolpack').mkdir(exist_ok=True)
        shutil.copy2(args.worker,actual_root/'toolpack/opencode-worker');shutil.copy2(fixture,actual_root/'toolpack/managed-uat-helper')
        check('copied-worker-and-utility',digest(actual_root/'toolpack/opencode-worker')==wm['binarySha256']
              and digest(args.worker)==wm['binarySha256'] and digest(actual_root/'toolpack/managed-uat-helper')==report['fixtureSha256'])
        actual=build('actual-build',actual_root,native)
        gateway_sources=sources(SOURCE.parent/'gateway');platform_sources=sources(SOURCE.parent/'platform')
        report['gatewaySourceFiles']=gateway_sources;report['platformSourceFiles']=platform_sources
        result=run(['/usr/bin/env','GOWORK=off','GOTOOLCHAIN=local','GOPROXY=off','GOSUMDB=off','GOCACHE='+str(out/'go-cache'),
                    args.go,'-C',SOURCE.parent/'gateway','build','-mod=readonly','-trimpath','-buildvcs=false','-o',out/'gateway','.'],'gateway-build')
        check('gateway-compiled',result['exitCode']==0)
        calls=[]
        class Fixture(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                self.connection.settimeout(5)
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<1<<20:self.send_error(413);return
                body=json.loads(self.rfile.read(length))
                if self.path=='/v1/logs':self.send_response(503);self.end_headers();return
                if self.path!='/v1/chat/completions' or body.get('model')!='approved':self.send_error(400);return
                names=[t['function']['name'] for t in body.get('tools',[])]
                results=sum(m.get('role')=='tool' for m in body.get('messages',[]))
                operation='bash' if 'bash' in names else 'shell' if 'shell' in names else ''
                identifier='call-'+str(len(calls));args={'command':'/toolpack/managed-uat-helper edit','description':'Edit nested files and preserve executable bit','timeout':10000}
                use=bool(operation and results==0)
                calls.append({'tool':operation if use else None,'id':identifier,'arguments':args if use else None})
                delta={'role':'assistant','tool_calls':[{'index':0,'id':identifier,'type':'function','function':{'name':operation,'arguments':compact(args).decode()}}]} if use else {'role':'assistant','content':'Workspace changes completed.'}
                def chunk(delta,finish):return {'id':'fixture','object':'chat.completion.chunk','created':1,'model':'approved','choices':[{'index':0,'delta':delta,'finish_reason':finish}]}
                raw=b''.join(b'data: '+compact(v)+b'\n\n' for v in [chunk(delta,None),chunk({},'tool_calls' if use else 'stop')])+b'data: [DONE]\n\n'
                self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
                try:self.wfile.write(raw)
                except (BrokenPipeError,ConnectionResetError):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Fixture);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever);thread.start()
        spool=out/'spool';spool.mkdir(mode=0o700);token=out/'provider.token';token.write_text('synthetic-managed-uat');token.chmod(0o600)
        config={'schema':'testifysec.hardened-opencode.gateway/v1','protocol':'chat-completions','socket':str(out/'gateway.sock'),'spool':str(spool),
                'providerURL':f'http://127.0.0.1:{server.server_port}/v1/chat/completions','providerTokenFile':str(token),
                'collectorURL':f'http://127.0.0.1:{server.server_port}/v1/logs','collectorTokenFile':'','model':'approved','tenant':'fixture',
                'session':'assigned-per-case','agent':'spiffe://fixture.test/tenant/fixture/agent/fixture','profileDigest':'a'*64,
                'maxRecords':64,'maxOfflineSeconds':120,'timeoutSeconds':10,'developmentLoopback':True}
        record,_=execute('actual-opencode-edit',actual,'Perform the workspace edits and finish.',gateway_config=config)
        actual_guest=record['observation']['guestResult'];events=[json.loads(line) for line in base64.b64decode(actual_guest['outputBase64']).decode().splitlines() if line.startswith('{')]
        tools=[e['part'] for e in events if e.get('type')=='tool_use'];requested=[c for c in calls if c['tool']]
        check('actual-opencode-tool-completed',len(requested)==len(tools)==1 and tools[0].get('callID',tools[0].get('id'))==requested[0]['id'] and tools[0]['state']['status']=='completed'
              and tools[0]['state']['input']==requested[0]['arguments'] and tools[0]['state']['metadata'].get('exit',tools[0]['state']['metadata'].get('metadata',{}).get('exit'))==0)
        check('actual-opencode-no-fixture-marker',b'HARNESS_TEST_PASSED' not in base64.b64decode(actual_guest['outputBase64']))
        check('actual-opencode-exact-files',actual_guest['files']==guest['files'] and actual_guest['removed']==['delete.txt'])
        check('gateway-platform-sources-unchanged',sources(SOURCE.parent/'gateway')==gateway_sources and sources(SOURCE.parent/'platform')==platform_sources)
        check('sources-unchanged',sources(SOURCE)==before)
        report['executables']={str(p.relative_to(out)):digest(p) for p in [fixture,out/'validate',out/'gateway',tests_root/'toolpack/opencode-worker']}
        report['validatorTypesSha256']=digest(out/'validation-types.swift')
        report['passed']=True
    except BaseException as error:
        report['error']=type(error).__name__+': '+str(error)
    finally:
        try:stop_gateway()
        except Exception as error:report['cleanupError']=str(error);report['passed']=False
        if server:server.shutdown();server.server_close()
        if thread:thread.join(timeout=5)
        if thread and thread.is_alive():report['passed']=False;report['cleanupError']='provider thread did not drain'
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),'report':str(out/'report.json'),'sha256':digest(out/'report.json')}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
