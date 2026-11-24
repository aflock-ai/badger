#!/usr/bin/env python3
# jade:ring local
"""Real VZ UID65534 -> native relay -> compiled gateway; synthetic local HTTP only."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import threading
import time

SOURCE = Path(__file__).resolve().parent
GATEWAY = SOURCE.parent / 'gateway'

def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): result.update(chunk)
    return result.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--admission-bundle', type=Path)
    parser.add_argument('--valid-profile', type=Path)
    parser.add_argument('--expired-profile', type=Path)
    args = parser.parse_args()
    if any([args.admission_bundle,args.valid_profile,args.expired_profile]) and not all([args.admission_bundle,args.valid_profile,args.expired_profile]):
        parser.error('all three native profile fixture paths must be supplied together')
    out = args.output.absolute(); out.mkdir(mode=0o700)
    compact = lambda value: json.dumps(value,separators=(',',':')).encode()
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    sources = lambda root: {str(p.relative_to(root)):digest(p) for p in sorted(root.rglob('*')) if p.is_file() and p.suffix in ('.go','.mod','.sum','.swift','.py','.md','.plist')}
    report = {'schema':'testifysec.vm-relay-uat/v1','passed':False,'checks':[],'cases':[],
              'vmSourceFiles':sources(SOURCE),'gatewaySourceFiles':sources(GATEWAY),'platformSourceFiles':sources(GATEWAY.parent/'platform'),
              'revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=SOURCE,text=True).strip(),
              'worktreeDirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=SOURCE)),
              'qualification':'developer-only-unqualified','brokerAdmissionIntegrated':False,'liveProviderCalls':False,
              'scope':'actual VZ Linux UID65534, fixed VSOCK17002, native gateway, local synthetic provider/collector; no signed VM authorization or hardware measurement'}
    state={'mode':'valid','provider':[],'collector':[],'spool':None,'config':None,'collect':False}
    def check(name,condition):
        report['checks'].append({'name':name,'passed':bool(condition)})
        if not condition: raise AssertionError(name)
    def response(status='completed'):
        return {'id':'resp_fixture','object':'response','model':'approved','status':status,'output':[],
                'error':None,'incomplete_details':{'reason':'max_output_tokens'} if status=='incomplete' else None}
    def event(kind,sequence,value):
        return ('event: '+kind+'\ndata: '+json.dumps({'type':kind,'sequence_number':sequence,'response':value})+'\n\n').encode()
    class Fixture(BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def do_POST(self):
            raw=self.rfile.read(int(self.headers.get('Content-Length','0')))
            if self.path=='/v1/logs':
                state['collector'].append(json.loads(raw));self.send_response(200 if state['collect'] else 503);self.end_headers();self.wfile.write(b'{}');return
            starts=[json.loads(p.read_bytes()) for p in state['spool'].glob('*.json')]
            starts=[r for r in starts if r['outcome']=='started']
            state['provider'].append({'path':self.path,'body':json.loads(raw),'headers':dict(self.headers),'durableStarts':starts})
            mode=state['mode']
            if mode=='hold': time.sleep(8)
            self.send_response(200);self.send_header('Set-Cookie','must-not-reflect');self.end_headers()
            request=json.loads(raw)
            if self.path=='/v1/responses':
                content=json.dumps(response()).encode()
                if request.get('stream'):
                    content=event('response.created',0,response('in_progress'))
                    if mode!='truncated': content+=event('response.completed',1,response())
            else:
                content=b'{"choices":[{"message":{"content":"fixture reply"}}]}'
                if request.get('stream'): content=b'data: {"choices":[]}\n\n'+(b'' if mode=='truncated' else b'data: [DONE]\n\n')
            try: self.wfile.write(content)
            except (BrokenPipeError,ConnectionResetError): pass
    service=ThreadingHTTPServer(('127.0.0.1',0),Fixture)
    threading.Thread(target=service.serve_forever,daemon=True).start()
    current=None
    try:
        env=dict(os.environ,GOTOOLCHAIN='local',GOWORK='off',GOPROXY='off',GOSUMDB='off',GOMAXPROCS='2')
        gateway=out/'hardened-gateway'
        subprocess.run([str(args.go),'build','-trimpath','-buildvcs=false','-o',str(gateway),'.'],cwd=GATEWAY,env=env,check=True,capture_output=True,timeout=120)
        report['gatewayExecutableSha256']=digest(gateway)
        build=out/'build'
        subprocess.run(['python3','-B',str(SOURCE/'build.py'),'--go',str(args.go),'--output',str(build),'--mode','gateway'],cwd=SOURCE,env=env,check=True,capture_output=True,timeout=240)
        manifest=json.loads((build/'manifest.json').read_bytes());report['buildManifest']=manifest
        original=json.loads((build/'config.json').read_bytes())
        profile_digest='a'*64;tenant='fixture-tenant'
        if args.valid_profile:
            bundle=out/'admission';shutil.copytree(args.admission_bundle,bundle);bundle.chmod(0o700)
            admission=bundle/'hardened-admission'
            report['nativeAdmissionInputs']={str(p.relative_to(bundle)):digest(p) for p in sorted(bundle.rglob('*')) if p.is_file()}
            admitted=subprocess.run([str(admission)],input=args.valid_profile.read_bytes(),capture_output=True,env={'PATH':'/usr/bin:/bin'},timeout=10)
            check('real-native-profile-fixture',admitted.returncode==0)
            facts=json.loads(admitted.stdout);profile_digest=facts['payloadSha256'];tenant=facts['profile']['tenantId']
            report['nativeAdmissionSha256']=digest(admission);report['validProfileSha256']=digest(args.valid_profile)
        def execute(name,body=None,path='/v1/chat/completions',status=200,contains='fixture reply',attack='',protocol='chat-completions',mode='valid',expected=0,provider_count=1,config_mutation=None,audit_failure=False,profile='valid',terminate=False,export=False,padding_bytes=0,fixture_fault=None,test_host=False):
            nonlocal current
            index=len(report['cases']);case=out/('c'+str(index));case.mkdir(mode=0o700)
            spool=case/'spool';spool.mkdir(mode=0o700)
            token=case/'provider.token';token.write_text('synthetic-provider-credential');token.chmod(0o600)
            body=body if body is not None else {'model':'approved','messages':[{'role':'user','content':'fixture prompt'}]}
            binding=dict(original['binding'],profileSha256=profile_digest,sessionId='relay-case-'+str(index))
            spec={'path':path,'body':body,'status':status,'contains':contains,'attack':attack,'paddingBytes':padding_bytes}
            request={'mode':'gateway','prompt':compact(spec).decode()}
            binding['requestSha256']=sha(compact(request))
            job={'schema':'testifysec.vm-job/v2','binding':binding,'request':request,'materials':[]}
            job_path=case/'job.json';job_path.write_bytes(compact(job));job_path.chmod(0o600)
            config={'schema':'testifysec.hardened-opencode.gateway/v1','protocol':protocol,'socket':str(case/'gateway.sock'),
                    'spool':str(spool),'providerURL':f'http://127.0.0.1:{service.server_port}'+('/v1/responses' if protocol=='responses' else '/v1/chat/completions'),
                    'providerTokenFile':str(token),'collectorURL':f'http://127.0.0.1:{service.server_port}/v1/logs','collectorTokenFile':'',
                    'model':'approved','tenant':tenant,'session':binding['sessionId'],'agent':f'spiffe://fixture.test/tenant/{tenant}/agent/fixture-agent',
                    'profileDigest':profile_digest,'maxRecords':32,'maxOfflineSeconds':60,'timeoutSeconds':10,'developmentLoopback':True}
            if args.valid_profile:
                profile_path=case/'profile.json';profile_path.write_bytes((args.expired_profile if profile=='expired' else args.valid_profile).read_bytes());profile_path.chmod(0o600)
                config.update(signedProfileFile=str(profile_path),admissionExecutable=str(admission),admissionSha256=digest(admission))
            config_path=case/'gateway.json';config_path.write_bytes(compact(config));config_path.chmod(0o600)
            log=(case/'gateway.log').open('wb')
            current=subprocess.Popen([str(gateway),'--config',str(config_path)],stdout=log,stderr=log,env={'PATH':'/usr/bin:/bin'})
            deadline=time.monotonic()+5
            while not Path(config['socket']).exists() and current.poll() is None and time.monotonic()<deadline: time.sleep(.02)
            check(name+'-gateway-ready',current.poll() is None and Path(config['socket']).exists())
            state.update(mode=mode,provider=[],collector=[],spool=spool,config=config,collect=False)
            vm=dict(original,binding=binding,jobFile=str(job_path),jobSha256=digest(job_path),gatewayConfigFile=str(config_path),gatewayConfigSha256=digest(config_path),timeoutSeconds=40)
            if fixture_fault: vm['fixtureFault']=fixture_fault
            if config_mutation: config_mutation(vm,config_path)
            vm_path=case/'vm.json';vm_path.write_bytes(compact(vm));vm_path.chmod(0o600)
            if audit_failure: spool.chmod(0o500)
            start=time.monotonic()
            process=subprocess.Popen([str(build/('hc-vm-uat' if fixture_fault or test_host else 'hc-vm')),str(vm_path)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/nonexistent'})
            try:
                if terminate:
                    deadline=time.monotonic()+8
                    while not state['provider'] and process.poll() is None and time.monotonic()<deadline:time.sleep(.02)
                    check(name+'-provider-in-flight',bool(state['provider']))
                    process.send_signal(signal.SIGTERM)
                stdout,stderr=process.communicate(timeout=45)
            except BaseException:
                process.kill();process.communicate(timeout=10);raise
            finally:
                if audit_failure:spool.chmod(0o700)
            observation=json.loads(stdout) if stdout else None
            records=[json.loads(p.read_bytes()) for p in spool.glob('*.json')]
            report['cases'].append({'name':name,'exitCode':process.returncode,'elapsedSeconds':time.monotonic()-start,'observation':observation,
                                   'configSha256':digest(vm_path),'jobSha256':digest(job_path),'gatewayConfigSha256':digest(config_path),
                                   'stdoutSha256':sha(stdout),'stderrSha256':sha(stderr),'provider':list(state['provider']),'auditRecords':records})
            check(name+'-exit',process.returncode==expected)
            check(name+'-exact-provider-effects',len(state['provider'])==provider_count)
            if expected!=2:
                check(name+'-actual-isolated-vm-stopped',observation['started'] is True and observation['stopped'] is True and observation['networkDevices']==0 and observation['sharedDirectories']==0 and observation['writableHostDisks']==0)
                relay=observation['gatewayRelay']
                check(name+'-duplex-counter-types',all(type(relay.get(key)) is int and relay[key]>=0
                      for key in ('earlyGatewayRefusals','responseCancellations')))
                check(name+'-transport-drained',observation['gatewayRelayDrained'] is True and observation['jobTransportDrained'] is True and relay['admissionClosed'] is True and relay['active']==0)
            else: check(name+'-before-vm',not stdout)
            if expected==0:
                guest=observation['guestResult']
                check(name+'-bound-uid-artifact',guest['jobValidated'] is True and guest['binding']==binding and guest['jobSha256']==digest(job_path) and guest['nonce']==observation['bootNonce'] and guest['workerUid']==65534 and guest['rootReadonly'] is True and guest['files']=={'result.txt':base64.b64encode(b'vm-fixture-verified\n').decode()})
            for item in state['provider']:
                if padding_bytes:
                    check(name+'-provider-observed-exact-20k-body',item['body'].get('messages')==[{'role':'user','content':'x'*20480}]
                          and item['body'].get('stream',False)==body.get('stream',False) and item['body'].get('model')=='approved')
                headers={k.lower():v for k,v in item['headers'].items()}
                check(name+'-protected-credential-and-header-filter',headers.get('authorization')=='Bearer synthetic-provider-credential' and 'x-agent-id' not in headers and 'x-provider-url' not in headers)
                starts=item['durableStarts']
                check(name+'-exact-durable-assignment-before-provider',len(starts)==1 and starts[0]['session']==binding['sessionId'] and starts[0]['profileDigest']==profile_digest and starts[0]['agent']==config['agent'])
                terminals=[r for r in records if r['id']==starts[0]['id'] and r['outcome']!='started']
                check(name+'-exact-terminal-audit',len(terminals)==1)
                if mode=='truncated':
                    check(name+'-interrupted-terminal-audit',terminals[0]['outcome']=='response-interrupted'
                          and terminals[0]['status']==200 and terminals[0]['session']==binding['sessionId']
                          and terminals[0]['profileDigest']==profile_digest and terminals[0]['agent']==config['agent'])
            check(name+'-no-credential-output',b'synthetic-provider-credential' not in stdout+stderr and b'synthetic-provider-credential' not in (case/'gateway.log').read_bytes())
            if export:
                state['collect']=True
                deadline=time.monotonic()+5
                while list(spool.glob('*.json')) and time.monotonic()<deadline:time.sleep(.05)
                check(name+'-collector-acknowledged-durable-record',bool(state['collector']) and not list(spool.glob('*.json'))
                      and all(r['id'] in json.dumps(state['collector']) for r in records))
            current.terminate();current.wait(timeout=12);log.close()
            check(name+'-gateway-stopped',current.returncode==0);current=None
            return observation
        execute('chat-completion',export=True)
        execute('chat-20k-completion',padding_bytes=20480)
        execute('chat-20k-stream',padding_bytes=20480,body={'model':'approved','messages':[{'role':'user','content':'fixture'}],'stream':True},contains='[DONE]')
        execute('test-host-valid-receipt',test_host=True)
        for fault in ('receipt-wrong-magic','receipt-wrong-digest','receipt-short','receipt-missing'):
            observed=execute(fault,fixture_fault=fault,padding_bytes=20480,expected=3,provider_count=0)
            check(fault+'-ordinary-confirmation-read-refuses',observed['gatewayRelay']['lastError']=='relay-frame-truncated' and observed['gatewayRelay']['forwarded']==0)
            execute(fault+'-production-config-refused',expected=2,provider_count=0,config_mutation=lambda vm,_,value=fault:vm.update(fixtureFault=value))

        execute('chat-stream',body={'model':'approved','messages':[{'role':'user','content':'fixture'}],'stream':True},contains='[DONE]')
        response_body={'model':'approved','store':False,'input':[{'role':'user','content':[{'type':'input_text','text':'fixture'}]}]}
        execute('responses-completion',body=response_body,path='/v1/responses',protocol='responses',contains='completed')
        execute('responses-stream',body=dict(response_body,stream=True),path='/v1/responses',protocol='responses',contains='response.completed')
        execute('wrong-model',body={'model':'other','messages':[{}]},status=403,contains='model not approved',provider_count=0)
        execute('wrong-protocol',body=response_body,path='/v1/responses',status=400,contains='unsupported request',provider_count=0)
        execute('wrong-http-path',path='/v1/files',status=400,contains='unapproved model route',provider_count=0)
        execute('required-audit-unavailable',status=503,contains='required audit unavailable',provider_count=0,audit_failure=True)
        slow=execute('guest-slow-body-concurrency',attack='slow-body',provider_count=0)
        check('two-body-reservations-refuse-third-and-drain',slow['gatewayRelay']['connections']==0 and 'THIRD_SLOW_BODY_REFUSED CONNECT_CANCELLED' in slow['guestResult']['output'])
        if args.valid_profile: execute('expired-profile',status=403,contains='signed profile',provider_count=0,profile='expired')
        assignment_attacks=('nonce','job','request','profile','session','materials','backend','path','sequence','body-limit','body-encoding','unknown')
        wire_errors={attack:'relay-assignment-or-request' for attack in assignment_attacks}
        wire_errors.update({'duplicate':'relay-json-duplicate','null-sequence':'relay-json-number','oversize':'relay-frame-limit',
                            'extra':'relay-frame-extra-or-no-eof','truncated':'relay-frame-truncated','no-eof':'relay-frame-extra-or-no-eof',
                            'old-magic':'relay-magic','replay':'relay-replayed-or-closed',
                            'acceptance-missing':'relay-frame-truncated','acceptance-short':'relay-frame-truncated',
                            'acceptance-magic':'relay-receipt-confirmation','acceptance-digest':'relay-receipt-confirmation'})
        for attack,last_error in wire_errors.items():
            observation=execute('wire-'+attack,attack=attack,expected=3,provider_count=1 if attack=='replay' else 0)
            check(attack+'-exact-host-refusal-stage',observation['error']=='gateway-relay-refused' and not observation['passed']
                  and observation['gatewayRelay']['lastError']==last_error)
        observation=execute('wire-busy',attack='busy',expected=3,provider_count=0)
        check('busy-host-refusal',observation['error']=='gateway-connection-refused' and not observation['passed'])
        for protocol,path,body in [('chat-completions','/v1/chat/completions',{'model':'approved','messages':[{}],'stream':True}),('responses','/v1/responses',dict(response_body,stream=True))]:
            observation=execute(protocol+'-truncated',body=body,path=path,protocol=protocol,mode='truncated',expected=3)
            check(protocol+'-exact-host-truncation-refusal',not observation['passed']
                  and observation['error']=='gateway-relay-refused'
                  and observation['gatewayRelay']['lastError']=='gateway-response-truncated')
        execute('SIGTERM-active-relay',mode='hold',expected=3,terminate=True)
        execute('gateway-config-digest',expected=2,provider_count=0,config_mutation=lambda vm,_:vm.update(gatewayConfigSha256='0'*64))
        def wrong_assignment(vm,path):
            config=json.loads(path.read_bytes());config['session']='wrong-session';path.write_bytes(compact(config));vm['gatewayConfigSha256']=digest(path)
        execute('gateway-config-assignment',expected=2,provider_count=0,config_mutation=wrong_assignment)
        def socket_alias(vm,path):
            config=json.loads(path.read_bytes());alias=path.parent/'alias.sock';alias.symlink_to(config['socket'])
            config['socket']=str(alias);path.write_bytes(compact(config));vm['gatewayConfigSha256']=digest(path)
        for name,mutation in [('socket-alias',socket_alias),('socket-parent-custody',lambda _,path:path.parent.chmod(0o755)),('socket-absent',lambda _,path:(path.parent/'gateway.sock').unlink())]:
            refused=execute(name,expected=3,provider_count=0,config_mutation=mutation)
            check(name+'-no-host-execution-fallback',refused['gatewayRelay']['forwarded']==0 and not refused['passed'])
        check('vm-source-unchanged',sources(SOURCE)==report['vmSourceFiles'])
        check('gateway-source-unchanged',sources(GATEWAY)==report['gatewaySourceFiles'])
        check('platform-source-unchanged',sources(GATEWAY.parent/'platform')==report['platformSourceFiles'])
        check('reused-root-unchanged',digest(manifest['rootDisk'])==manifest['rootDiskSha256'])
        check('gateway-binary-unchanged',digest(gateway)==report['gatewayExecutableSha256'])
        if args.valid_profile:check('native-admission-bundle-unchanged',all(digest(bundle/name)==sha for name,sha in report['nativeAdmissionInputs'].items()))
        report['passed']=True
    finally:
        if current is not None and current.poll() is None: current.terminate();current.wait(timeout=12)
        service.shutdown();service.server_close()
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),'report':str(out/'report.json'),'sha256':digest(out/'report.json')}))

if __name__=='__main__':main()
