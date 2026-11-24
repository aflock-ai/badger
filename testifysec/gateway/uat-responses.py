# jade:ring local
"""Native Responses gateway over UDS plus compiled installed SDK; local synthetic HTTP only."""
import argparse
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from uat import UnixHTTP


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--bun', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--model', choices=['gpt-5.4', 'gpt-6-astra'], default='gpt-5.4')
    parser.add_argument('--binary-output', type=Path, help='Optional new path retaining the exact native executable tested.')
    args = parser.parse_args()
    model_id = args.model
    effort = 'max' if model_id == 'gpt-6-astra' else 'low'
    root = Path(__file__).resolve().parent
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    sources = lambda: {p.name: sha(p) for p in sorted(root.iterdir()) if p.is_file()}
    report = {'schema': 'testifysec.hardened-opencode.gateway-responses-uat/v1', 'passed': False,
              'sourceFiles': sources(), 'bunExecutableSha256': sha(args.bun), 'model': model_id, 'effort': effort,
              'checks': [], 'releaseQualified': False, 'productionEnabled': False,
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
              'worktreeDirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)),
              'limitations': ['Synthetic provider and collector; no model credentials, OAuth flow, or protected worker enablement.',
                              'Signed profile and live platform identity checks have separate harnesses.',
                              'Responses text/function subset only; hosted tools, remote inputs, stored references and background jobs refused.']}
    state = {'provider': [], 'collector': [], 'mode': 'valid', 'collect': False}
    process = None

    def check(name, condition):
        report['checks'].append({'id': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    def result(status='completed', refusal=False):
        return {'id': 'resp_fixture', 'object': 'response', 'created_at': 1, 'model': model_id, 'status': status,
                'output': [{'type': 'message', 'id': 'msg_fixture', 'role': 'assistant', 'status': 'completed',
                            'content': [{'type': 'refusal', 'refusal': 'fixture refusal'}] if refusal else
                                       [{'type': 'output_text', 'text': 'fixture response', 'annotations': []}]}],
                'usage': {'input_tokens': 2, 'output_tokens': 2, 'input_tokens_details': {'cached_tokens': 0}, 'output_tokens_details': {'reasoning_tokens': 0}},
                'error': {'code': 'server_error', 'message': 'synthetic failure'} if status == 'failed' else None,
                'incomplete_details': {'reason': 'max_output_tokens'} if status == 'incomplete' else None}

    def event(kind, seq, **values):
        return ('event: ' + kind + '\ndata: ' + json.dumps(dict(type=kind, sequence_number=seq, **values)) + '\n\n').encode()

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            if self.path == '/v1/logs':
                state['collector'].append(json.loads(body))
                self.send_response(200 if state['collect'] else 503)
                self.end_headers()
                self.wfile.write(b'{}')
                return
            records = [json.loads(p.read_text()) for p in spool.glob('*.json')]
            starts = [r for r in records if r['outcome'] == 'started']
            state['provider'].append({'path': self.path, 'body': json.loads(body), 'headers': dict(self.headers),
                                      'durableStarts': len(starts), 'requestID': starts[0]['id'] if len(starts) == 1 else None})
            mode = state['mode']
            if mode == 'redirect':
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{self.server.server_port}/trap')
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Set-Cookie', 'must-not-reflect')
            self.end_headers()
            request = json.loads(body)
            if not request.get('stream'):
                content = json.dumps(result()).encode()
                if mode == 'wrong-model':
                    content = content.replace(model_id.encode(), b'other')
                if mode == 'oversize':
                    content = b' ' * ((16 << 20) + 1)
            else:
                created = event('response.created', 0, response=result('in_progress'))
                status = mode if mode in ('failed', 'incomplete') else 'completed'
                content = created + event('response.output_item.added', 1, output_index=0,
                                          item={'type': 'message', 'id': 'msg_fixture', 'role': 'assistant', 'status': 'in_progress', 'content': []})
                content += event('response.output_text.delta', 2, output_index=0, content_index=0, item_id='msg_fixture', delta='fixture response')
                content += event('response.output_item.done', 3, output_index=0, item=result()['output'][0])
                terminal = event('response.' + status, 4, response=result(status, mode == 'refusal'))
                content += terminal
                if mode == 'truncated': content = created
                if mode == 'done-only': content = created + b'data: [DONE]\n\n'
                if mode == 'duplicate': content += terminal
                if mode == 'partial': content = content[:-1]
                if mode == 'wrong-model': content = content.replace(model_id.encode(), b'other')
                if mode == 'null-sequence': content = content.replace(b'"sequence_number": 0', b'"sequence_number": null')
                if mode == 'bad-sequence': content = content.replace(b'"sequence_number": 4', b'"sequence_number": 1')
                if mode == 'oversize': content = created + b'data: ' + b'x' * 65537
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass

    service = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    threading.Thread(target=service.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='hc-gateway-responses-', dir='/private/tmp' if Path('/private/tmp').exists() else None) as temp:
            work = Path(temp).resolve()
            binary = args.binary_output.absolute() if args.binary_output else work / 'hardened-gateway'
            if binary.exists(): raise AssertionError('choose a new native binary output path')
            env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off')
            subprocess.run([args.go, 'build', '-trimpath', '-o', str(binary), '.'], cwd=root, env=env, check=True)
            report['gatewaySha256'] = sha(binary)
            if args.binary_output: report['gatewayExecutable'] = str(binary)
            sdk = work / 'sdk-responses'
            build = subprocess.run([str(args.bun), str(root / 'build-sdk.ts'), str(sdk)], cwd=root, capture_output=True, timeout=300)
            if build.returncode:
                raise AssertionError('SDK fixture build: ' + build.stderr.decode()[-4000:])
            report['sdkBinarySha256'] = sha(sdk)
            # The 2.0 client: @opencode/ai's OpenAI Responses route and the managed build's gateway transport.
            repo = root.parent.parent
            sdk_inputs = [*sorted((repo / 'packages/ai/src/protocols').glob('open*-responses*.ts')),
                          *sorted((repo / 'packages/ai/src/providers').glob('openai*.ts')), repo / 'packages/server/src/managed.ts']
            report['sdkInputs'] = {str(p.relative_to(repo)): sha(p) for p in sdk_inputs}
            spool = work / 'spool'
            spool.mkdir(mode=0o700)
            token = work / 'provider.token'
            token.write_text('synthetic-protected-provider-token')
            token.chmod(0o600)
            config = {'schema': 'testifysec.hardened-opencode.gateway/v1', 'protocol': 'responses', 'socket': str(work / 'gateway.sock'),
                      'spool': str(spool), 'providerURL': f'http://127.0.0.1:{service.server_port}/v1/responses',
                      'providerTokenFile': str(token), 'collectorURL': f'http://127.0.0.1:{service.server_port}/v1/logs', 'collectorTokenFile': '',
                      'model': model_id, 'tenant': 'fixture-tenant', 'session': 'fixture-session',
                      'agent': 'spiffe://fixture.test/tenant/fixture-tenant/agent/fixture-agent', 'profileDigest': 'a'*64,
                      'maxRecords': 64, 'maxOfflineSeconds': 60, 'timeoutSeconds': 5, 'developmentLoopback': True}
            config_path = work / 'config.json'
            def start(c):
                config_path.write_text(json.dumps(c)); config_path.chmod(0o600)
                return subprocess.Popen([str(binary), '--config', str(config_path)], stdout=log, stderr=log, env={'PATH':'/nonexistent'})
            with (work / 'gateway.log').open('wb') as log:
                for name, change in [('unknown-protocol', {'protocol':'unsupported'}), ('endpoint-protocol-mismatch', {'providerURL': f'http://127.0.0.1:{service.server_port}/v1/chat/completions'})]:
                    process = start(dict(config, **change))
                    check(name, process.wait(timeout=5) != 0)
                process = start(config)
                deadline = time.monotonic() + 8
                while not Path(config['socket']).exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.025)
                check('native-responses-startup', process.poll() is None and Path(config['socket']).exists())
                sdk_env = {'PATH':'/nonexistent','HOME':str(work),'TMPDIR':str(work)}
                execution = subprocess.run([str(sdk), config['socket'], model_id], cwd=work, env=sdk_env, capture_output=True, timeout=30)
                check('actual-compiled-sdk-serialization-parser', execution.returncode == 0 or print(execution.stderr.decode()[-4000:]))
                report['sdk'] = json.loads(execution.stdout)
                check('sdk-generate-stream-function-and-encrypted-history', len(state['provider']) == 3 and report['sdk']['passed'])
                check('actual-sdk-effort-preserved-to-provider', report['sdk']['effort'] == effort
                      and all(r['body'].get('reasoning', {}).get('effort') == effort and r['body']['model'] == model_id for r in state['provider']))
                def call(payload=None, path='/v1/responses'):
                    payload = payload if payload is not None else {'model':model_id,'store':False,'input':'synthetic-private-prompt','stream':True,'reasoning':{'effort':effort}}
                    connection = UnixHTTP(config['socket'])
                    connection.request('POST', path, json.dumps(payload) if isinstance(payload,dict) else payload, {'Content-Type':'application/json'})
                    try:
                        response=connection.getresponse()
                        try: body=response.read(); interrupted=False
                        except http.client.IncompleteRead as e: body=e.partial; interrupted=True
                        return response.status,body,interrupted
                    except (http.client.RemoteDisconnected, ConnectionResetError):
                        return 0,b'',True
                    finally: connection.close()
                for name, payload, path in [
                    ('model-refused',{'model':'other','store':False,'input':'x'},'/v1/responses'),
                    ('chat-path-refused',None,'/v1/chat/completions'),
                    ('query-refused',None,'/v1/responses?destination=other'),
                    ('store-required',{'model':model_id,'input':'x'},'/v1/responses'),
                    ('hosted-tools-refused',{'model':model_id,'store':False,'input':'x','tools':[{'type':'web_search'}]},'/v1/responses'),
                    ('duplicate-nested-key-refused',b'{"model":"'+model_id.encode()+b'","store":false,"input":[{"role":"user","content":[{"type":"input_text","text":"one","text":"two"}]}]}','/v1/responses'),
                ]:
                    before=len(state['provider']);status,_,_=call(payload,path);check(name,status>=400 and len(state['provider'])==before)
                invalid_efforts = ['ultra', 'MAX', None, {'level':'max'}, 'none', 'minimal'] if model_id == 'gpt-6-astra' else ['ultra', 'MAX', None, {'level':'max'}, 'max']
                for invalid in invalid_efforts:
                    before=len(state['provider'])
                    status,_,_=call({'model':model_id,'store':False,'input':'x','reasoning':{'effort':invalid}})
                    check('reasoning-effort-refused-'+json.dumps(invalid,sort_keys=True), status==400 and len(state['provider'])==before)
                if model_id == 'gpt-6-astra':
                    for key in ['temperature','top_p']:
                        before=len(state['provider'])
                        status,_,_=call({'model':model_id,'store':False,'input':'x','reasoning':{'effort':'max'},key:1})
                        check('astra-'+key+'-refused', status==400 and len(state['provider'])==before)
                before=len(state['provider'])
                duplicate = b'{"model":"'+model_id.encode()+b'","store":false,"input":"x","reasoning":{"effort":"max","effort":"low"}}'
                status,_,_=call(duplicate)
                check('duplicate-effort-refused', status==400 and len(state['provider'])==before)
                for mode in ['completed','failed','incomplete','refusal']:
                    state['mode']=mode;status,body,interrupted=call()
                    check('stream-'+mode,status==200 and not interrupted and b'response.'+(mode if mode in ('failed','incomplete') else 'completed').encode() in body)
                for mode in ['truncated','done-only','duplicate','partial','wrong-model','bad-sequence','null-sequence','oversize']:
                    state['mode']=mode;_,body,interrupted=call()
                    check('refuse-stream-'+mode,interrupted and b'"type": "response.completed"' not in body)
                for mode in ['wrong-model','oversize']:
                    state['mode']=mode;status,_,_=call({'model':model_id,'store':False,'input':'x','reasoning':{'effort':effort}})
                    check('refuse-json-'+mode,status==502)
                state['mode']='redirect';before=len(state['provider']);status,_,_=call()
                check('provider-redirect-refused',status==502 and len(state['provider'])==before+1 and state['provider'][-1]['path']=='/v1/responses')
                state['mode']='valid'
                records = [json.loads(p.read_text()) for p in spool.glob('*.json')]
                check('durable-start-before-every-provider-effect',all(r['durableStarts']==1 for r in state['provider']))
                outcomes={r['outcome'] for r in records}
                check('durable-distinct-model-and-transport-outcomes',{'provider-response-completed','provider-response-refused','provider-response-failed','provider-response-incomplete','response-interrupted','request-denied'}<=outcomes)
                check('provider-credential-confined',all(r['headers'].get('Authorization')=='Bearer synthetic-protected-provider-token' for r in state['provider']))
                check('no-prompt-or-credential-in-spool',all('synthetic-private-prompt' not in p.read_text() and 'synthetic-protected-provider-token' not in p.read_text() for p in spool.glob('*.json')))
                while len(list(spool.glob('*.json'))) < config['maxRecords']:
                    status,_,_=call({'model':model_id,'store':False,'input':'fixture audit capacity','reasoning':{'effort':effort}})
                    if status != 200: raise AssertionError('unexpected audit-capacity fixture refusal')
                before=len(state['provider']);status,_,_=call()
                check('bounded-audit-outage-refuses-new-effect',status==503 and len(state['provider'])==before)
                state['collect']=True
                deadline=time.monotonic()+8
                while list(spool.glob('*.json')) and time.monotonic()<deadline:time.sleep(.05)
                check('otlp-recovers-after-collector-outage',not list(spool.glob('*.json')) and bool(state['collector']))
                state['collect']=False
                (spool/'unexpected').write_text('force durable audit refusal')
                # Runtime spool insertion does not detect arbitrary names until restart.
                process.terminate();process.wait(timeout=8)
                process=start(config)
                check('audit-corruption-refuses-startup',process.wait(timeout=5)!=0)
            report['providerRequests']=len(state['provider'])
            report['outcomes']=sorted(outcomes)
            check('native-and-sdk-executable-paths-unchanged', sha(binary)==report['gatewaySha256'] and sha(sdk)==report['sdkBinarySha256'])
            if sources()!=report['sourceFiles']:raise AssertionError('gateway source changed during UAT')
            report['passed']=True
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        report['failure']=str(error)
    finally:
        if process and process.poll() is None:process.terminate();process.wait(timeout=8)
        service.shutdown();service.server_close()
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),'report':str(args.report),'failure':report.get('failure')}))
    return 0 if report['passed'] else 1

if __name__=='__main__':
    raise SystemExit(main())
