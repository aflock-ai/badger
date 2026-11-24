#!/usr/bin/env python3
# jade:ring local
"""Actual compiled OpenCode in VZ, fixed relay, native gateway, synthetic provider."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import threading
import time
import uuid

SOURCE = Path(__file__).resolve().parent
OPENCODE = SOURCE.parent.parent
GATEWAY = SOURCE.parent / 'gateway'


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sources(root):
    return {str(path.relative_to(root)): digest(path) for path in sorted(root.rglob('*'))
            if path.is_file() and path.suffix in ('.go', '.mod', '.sum', '.swift', '.py', '.md', '.plist')}


def private_json(path, value):
    path.write_bytes(compact(value))
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--worker', required=True, type=Path)
    parser.add_argument('--worker-inputs', required=True, type=Path,
                        help='Retained extract-worker.py directory; all regular input bytes are rechecked')
    parser.add_argument('--admission-bundle', required=True, type=Path)
    parser.add_argument('--valid-profile', required=True, type=Path)
    parser.add_argument('--expired-profile', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.absolute()
    out.mkdir(mode=0o700)
    report = {'schema': 'testifysec.vm-worker-relay-uat/v1', 'passed': False, 'checks': [], 'cases': [],
              'host': {'os': os.uname().sysname, 'release': os.uname().release, 'architecture': os.uname().machine},
              'vmSourceFiles': sources(SOURCE), 'gatewaySourceFiles': sources(GATEWAY),
              'platformSourceFiles': sources(GATEWAY.parent / 'platform'),
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip(),
              'worktreeDirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=SOURCE)),
              'qualification': 'developer-only-unqualified', 'brokerAdmissionIntegrated': False,
              'vmAuthorizationSigned': False, 'platformOnlineChecks': False,
              'liveProviderCalls': False, 'dockerInvocations': 0,
              'scope': 'actual VZ Linux compiled OpenCode, native gateway profile admission, local synthetic provider; no platform identity or hardware measurement'}
    state = {'calls': [], 'spool': None, 'mode': 'valid', 'collector': [], 'collect': False}
    fixture_lock = threading.Lock()
    service = None
    gateway_process = None
    vm_process = None
    log = None

    def check(name, condition):
        report['checks'].append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 2 * 1024 * 1024:
                self.send_error(413)
                return
            raw = self.rfile.read(length)
            body = json.loads(raw)
            if self.path == '/v1/logs':
                state['collector'].append(body)
                self.send_response(200 if state['collect'] else 503)
                self.end_headers()
                self.wfile.write(b'{}')
                return
            if self.path != '/v1/chat/completions' or body.get('model') != 'approved':
                self.send_error(400)
                return
            names = [tool['function']['name'] for tool in body.get('tools', [])]
            starts = [json.loads(p.read_bytes()) for p in state['spool'].glob('*.json')]
            starts = [record for record in starts if record['outcome'] == 'started']
            call = {'path': self.path, 'bodySha256': sha(raw), 'bodyBytes': len(raw),
                    'tools': names, 'model': body['model'], 'stream': body.get('stream'),
                    'credentialMatched': self.headers.get('Authorization') == 'Bearer synthetic-vm-provider-credential',
                    'guestAuthorityAbsent': self.headers.get('X-Agent-ID') is None, 'durableStarts': starts}
            with fixture_lock:
                state['calls'].append(call)
                fixture_id = str(len(state['calls']))
            if set(names) & {'task', 'webfetch', 'websearch', 'lsp', 'skill', 'question'}:
                self.send_error(400)
                return
            results = sum(message.get('role') == 'tool' for message in body.get('messages', []))
            operation = ''
            arguments = None
            if 'write' in names and results == 0:
                operation = 'write'
                # OpenCode 2.0's write tool names its target `path`, 1.x's `filePath`: follow the advertised one.
                target = 'path' if any(tool['function']['name'] == 'write' and 'path' in tool['function'].get('parameters', {}).get('properties', {})
                                       for tool in body.get('tools', [])) else 'filePath'
                arguments = {target: '/workspace/result.txt', 'content': 'hardened-worker-verified\n'}
            if ('bash' in names or 'shell' in names) and results == 1:
                operation = 'bash' if 'bash' in names else 'shell'
                command = 'test "$(cat result.txt)" = hardened-worker-verified && printf \'HARNESS_TEST_PASSED\\n\''
                if state['mode'] == 'failed-test':
                    command = 'printf \'EXPECTED_TEST_FAILURE\\n\'; exit 7'
                arguments = {'command': command, 'description': 'Check generated file', 'timeout': 10000}
            call['requestedTool'] = operation
            call['callId'] = 'call-' + fixture_id if operation else None
            call['arguments'] = arguments
            def chunk(delta, finish):
                return {'id': 'fixture-' + fixture_id, 'object': 'chat.completion.chunk',
                        'created': 1, 'model': 'approved',
                        'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish}]}
            if operation:
                delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': 'call-' + fixture_id,
                         'type': 'function', 'function': {'name': operation, 'arguments': compact(arguments).decode()}}]}
                finish = 'tool_calls'
            else:
                delta = {'role': 'assistant', 'content': 'Managed file and test journey completed.'}
                finish = 'stop'
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            content = b''.join(b'data: ' + compact(item) + b'\n\n' for item in (chunk(delta, None), chunk({}, finish)))
            if state['mode'] != 'truncated':
                content += b'data: [DONE]\n\n'
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass

    try:
        inputs_manifest_path = args.worker_inputs / 'manifest.json'
        inputs = json.loads(inputs_manifest_path.read_bytes())
        check('reviewed-extraction-manifest', inputs['schema'] == 'testifysec.vm-worker-inputs/v1'
              and inputs['containerStarted'] is False and inputs['ownedContainerRemoved'] is True)
        report['retainedRootInputManifest'] = inputs
        report['retainedRootInputManifestSha256'] = digest(inputs_manifest_path)
        shutil.copyfile(inputs_manifest_path, out / 'original-root-input-manifest.json')
        check('copied-original-root-manifest', digest(out / 'original-root-input-manifest.json')
              == report['retainedRootInputManifestSha256'])
        root = out / 'worker-root'
        root.mkdir(mode=0o700)
        actual = {}
        for path in sorted((args.worker_inputs / 'root').rglob('*')):
            info = path.lstat()
            check('regular-root-input-' + str(path.relative_to(args.worker_inputs / 'root')),
                  stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
            if stat.S_ISREG(info.st_mode):
                name = str(path.relative_to(args.worker_inputs / 'root'))
                actual[name] = digest(path)
                check('pinned-root-input-' + name, name in inputs['files'] and actual[name] == inputs['files'][name]['sha256'])
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                target.chmod(0o755)
                check('copied-root-input-' + name, digest(target) == actual[name])
        check('exact-root-input-closure', set(actual) == set(inputs['files']))
        worker_manifest = json.loads(Path(str(args.worker) + '.manifest.json').read_bytes())
        check('actual-gateway-worker', worker_manifest['component'] == 'hardened-opencode-worker'
              and worker_manifest['target'] == 'bun-linux-arm64' and worker_manifest['fixtureModel'] is False
              and digest(args.worker) == worker_manifest['binarySha256'])
        check('current-worker-selected-sources', all(digest(OPENCODE / name) == value for name, value in worker_manifest['sourceFiles'].items()))
        report['workerBuildManifest'] = worker_manifest
        report['workerManifestSha256'] = digest(Path(str(args.worker) + '.manifest.json'))
        shutil.copyfile(Path(str(args.worker) + '.manifest.json'), out / 'original-worker-manifest.json')
        check('copied-original-worker-manifest', digest(out / 'original-worker-manifest.json') == report['workerManifestSha256'])
        shutil.copyfile(args.worker, root / 'toolpack/opencode-worker')
        (root / 'toolpack/opencode-worker').chmod(0o755)
        check('copied-gateway-worker', digest(root / 'toolpack/opencode-worker') == worker_manifest['binarySha256'])
        env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off', GOMAXPROCS='2')
        gateway_stage = out / 'gateway-source'
        for module, selected in ((GATEWAY, report['gatewaySourceFiles']), (GATEWAY.parent / 'platform', report['platformSourceFiles'])):
            for name, expected in selected.items():
                target = gateway_stage / module.name / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(module / name, target)
                check('staged-' + module.name + '-' + name, digest(target) == expected)
        gateway = out / 'hardened-gateway'
        compiled = subprocess.run([str(args.go), 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-o', str(gateway), '.'],
                                  cwd=gateway_stage / 'gateway', env=env, capture_output=True, timeout=180)
        (out / 'gateway-build.log').write_bytes(compiled.stdout + compiled.stderr)
        check('native-gateway-build', compiled.returncode == 0)
        report['gatewayExecutableSha256'] = digest(gateway)
        build = out / 'build'
        compiled = subprocess.run(['python3', '-B', str(SOURCE / 'build.py'), '--go', str(args.go), '--output', str(build),
                                   '--mode', 'worker', '--worker-root', str(root)], env=env, capture_output=True, timeout=300)
        (out / 'vm-build.log').write_bytes(compiled.stdout + compiled.stderr)
        check('native-vm-worker-build', compiled.returncode == 0)
        manifest = json.loads((build / 'manifest.json').read_bytes())
        report['buildManifest'] = manifest
        original = json.loads((build / 'config.json').read_bytes())
        admission_dir = out / 'admission'
        shutil.copytree(args.admission_bundle, admission_dir)
        admission_dir.chmod(0o700)
        admission = admission_dir / 'hardened-admission'
        report['nativeAdmissionFiles'] = {str(p.relative_to(admission_dir)): digest(p) for p in admission_dir.rglob('*') if p.is_file()}
        valid_raw = args.valid_profile.read_bytes()
        expired_raw = args.expired_profile.read_bytes()
        accepted = subprocess.run([str(admission)], input=valid_raw, capture_output=True, env={'PATH': '/usr/bin:/bin'}, timeout=10)
        rejected = subprocess.run([str(admission)], input=expired_raw, capture_output=True, env={'PATH': '/usr/bin:/bin'}, timeout=10)
        check('real-native-valid-and-expired-profile', accepted.returncode == 0 and rejected.returncode != 0
              and json.loads(rejected.stdout).get('reason') == 'profile-time-invalid')
        facts = json.loads(accepted.stdout)
        profile_digest = facts['payloadSha256']
        report['validProfileSha256'] = sha(valid_raw)
        report['expiredProfileSha256'] = sha(expired_raw)
        service = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        service.daemon_threads = True
        threading.Thread(target=service.serve_forever, daemon=True).start()

        def execute(name, mode='valid', refusal=None, material=b'initial fixture\n'):
            nonlocal gateway_process, vm_process, log
            case = out / ('c' + str(len(report['cases'])))
            case.mkdir(mode=0o700)
            spool = case / 'spool'
            spool.mkdir(mode=0o700)
            token = case / 'provider.token'
            token.write_text('synthetic-vm-provider-credential')
            token.chmod(0o600)
            materials = [{'path': 'seed.txt', 'sha256': sha(material), 'contentBase64': base64.b64encode(material).decode()}]
            request = {'mode': 'worker', 'prompt': 'Write result.txt containing hardened-worker-verified then run the shell test. Preserve seed.txt.'}
            binding = dict(original['binding'], sessionId=uuid.uuid4().hex, profileSha256=profile_digest,
                           requestSha256=sha(compact(request)), materialsSha256=sha(compact(materials)))
            job = {'schema': 'testifysec.vm-job/v2', 'binding': binding, 'request': request, 'materials': materials}
            job_path = case / 'job.json'
            private_json(job_path, job)
            profile_path = case / 'profile.json'
            profile_path.write_bytes(expired_raw if refusal == 'expired' else valid_raw)
            profile_path.chmod(0o600)
            config = {'schema': 'testifysec.hardened-opencode.gateway/v1', 'protocol': 'chat-completions',
                      'socket': str(case / 'gateway.sock'), 'spool': str(spool),
                      'providerURL': f'http://127.0.0.1:{service.server_port}/v1/chat/completions',
                      'providerTokenFile': str(token), 'collectorURL': f'http://127.0.0.1:{service.server_port}/v1/logs',
                      'collectorTokenFile': '', 'model': 'other' if refusal == 'model' else 'approved',
                      'tenant': facts['profile']['tenantId'], 'session': binding['sessionId'],
                      'agent': 'spiffe://fixture.test/tenant/fixture/agent/fixture-agent', 'profileDigest': profile_digest,
                      'maxRecords': 64, 'maxOfflineSeconds': 120, 'timeoutSeconds': 10, 'developmentLoopback': True,
                      'signedProfileFile': str(profile_path), 'admissionExecutable': str(admission), 'admissionSha256': digest(admission)}
            if refusal == 'protocol':
                config['protocol'] = 'responses'
                config['providerURL'] = f'http://127.0.0.1:{service.server_port}/v1/responses'
            config_path = case / 'gateway.json'
            private_json(config_path, config)
            log = (case / 'gateway.log').open('wb')
            gateway_process = subprocess.Popen([str(gateway), '--config', str(config_path)], stdout=log, stderr=log, env={'PATH': '/usr/bin:/bin'})
            deadline = time.monotonic() + 5
            while not Path(config['socket']).exists() and gateway_process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            check(name + '-gateway-ready', gateway_process.poll() is None and Path(config['socket']).exists())
            state.update(calls=[], spool=spool, mode=mode, collector=[], collect=False)
            vm = dict(original, binding=binding, jobFile=str(job_path), jobSha256=digest(job_path),
                      gatewayConfigFile=str(config_path), gatewayConfigSha256=digest(config_path))
            vm_path = case / 'vm.json'
            private_json(vm_path, vm)
            if refusal == 'audit':
                spool.chmod(0o500)
            start = time.monotonic()
            vm_process = subprocess.Popen([str(build / 'hc-vm'), str(vm_path)], stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/nonexistent'})
            try:
                stdout, stderr = vm_process.communicate(timeout=70)
            finally:
                if refusal == 'audit':
                    spool.chmod(0o700)
            observation = json.loads(stdout) if stdout else None
            records = [json.loads(path.read_bytes()) for path in spool.glob('*.json')]
            report['cases'].append({'name': name, 'exitCode': vm_process.returncode, 'elapsedSeconds': time.monotonic() - start,
                                   'observation': observation, 'provider': list(state['calls']), 'auditRecords': records,
                                   'configSha256': digest(vm_path), 'jobSha256': digest(job_path), 'gatewayConfigSha256': digest(config_path),
                                   'stdoutSha256': sha(stdout), 'stderrSha256': sha(stderr)})
            (case / 'observation.json').write_bytes(stdout)
            check(name + '-expected-outcome', vm_process.returncode == (0 if mode == 'valid' and not refusal else 3))
            check(name + '-actual-isolated-vm-stopped', observation['schema'] == 'testifysec.vm-observation/v2'
                  and observation['started'] is True and observation['stopped'] is True and observation['networkDevices'] == 0
                  and observation['sharedDirectories'] == 0 and observation['writableHostDisks'] == 0
                  and observation['admissionIntegrated'] is False and observation['gatewayIntegrated'] is True)
            check(name + '-relay-and-job-drained', observation['gatewayRelayDrained'] is True and observation['jobTransportDrained'] is True
                  and observation['gatewayRelay']['active'] == 0 and observation['gatewayRelay']['admissionClosed'] is True)
            check(name + '-explicit-relay-outcomes', all(type(observation['gatewayRelay'].get(key)) is int
                  and observation['gatewayRelay'][key] >= 0 for key in ('earlyGatewayRefusals', 'responseCancellations')))
            guest = observation['guestResult']
            events = []
            if mode == 'truncated':
                check(name + '-exact-host-truncation-refusal', observation['error'] == 'gateway-relay-refused'
                      and observation['gatewayRelay']['lastError'] == 'gateway-response-truncated' and not observation['passed'])
            else:
                check(name + '-exact-worker-binding', guest['schema'] == 'testifysec.vm-result/v2' and guest['jobValidated'] is True
                      and guest['binding'] == binding and guest['jobSha256'] == digest(job_path) and guest['nonce'] == observation['bootNonce']
                      and guest['workerUid'] == 65534 and guest['rootReadonly'] is True)
                for line in guest['output'].splitlines():
                    if line.startswith('{'):
                        events.append(json.loads(line))
                check(name + '-actual-gateway-worker-start', any(event.get('type') == 'managed_worker_start'
                      and event.get('fixtureModel') is False and event.get('profileDigest') == profile_digest for event in events))
            if not refusal and mode != 'truncated':
                requested = [call for call in state['calls'] if call['requestedTool']]
                tools = [event['part'] for event in events if event.get('type') == 'tool_use']
                check(name + '-actual-upstream-tools', len(tools) == len(requested) == 2
                      and all(sum(part.get('callID', part.get('id')) == call['callId'] and part.get('tool') == call['requestedTool']
                          and part['state']['status'] == 'completed' and part['state']['input'] == call['arguments']
                          for part in tools) == 1 for call in requested))
                check(name + '-exact-captured-regular-files', guest['files'] == {'seed.txt': base64.b64encode(material).decode(),
                      'result.txt': base64.b64encode(b'hardened-worker-verified\n').decode()})
                shell = next(part['state'] for part in tools if part['tool'] in ('bash', 'shell'))
                check(name + '-completed-shell-result', shell['metadata'].get('exit', shell['metadata'].get('metadata', {}).get('exit')) == (0 if mode == 'valid' else 7)
                      and ('HARNESS_TEST_PASSED' if mode == 'valid' else 'EXPECTED_TEST_FAILURE') in shell['output'].splitlines()
                      and (mode == 'valid' or guest['error'] == 'artifact-or-test-mismatch'))
                check(name + '-model-write-test-sequence', [call['requestedTool'] for call in state['calls'] if call['requestedTool']]
                      == ['write', 'bash' if any('bash' in call['tools'] for call in state['calls']) else 'shell'])
            if refusal:
                check(name + '-no-provider-effects', not state['calls'] and not guest['passed'])
            else:
                check(name + '-provider-effects-observed', bool(state['calls']))
            ids = []
            for index, call in enumerate(state['calls']):
                check(name + '-provider-custody-' + str(index), call['credentialMatched'] and call['guestAuthorityAbsent']
                      and call['model'] == 'approved' and call['stream'] is True)
                starts = call['durableStarts']
                pairs = [(start_record, terminal) for start_record in starts for terminal in records
                         if start_record['id'] == terminal['id'] and terminal['requestBytes'] == call['bodyBytes']
                         and terminal['status'] == 200 and terminal['outcome']
                         == ('response-interrupted' if mode == 'truncated' else 'provider-stream-ended')]
                check(name + '-unique-audit-pair-' + str(index), len(pairs) == 1)
                start_record, terminal = pairs[0]
                check(name + '-audit-before-effect-' + str(index), start_record['session'] == binding['sessionId']
                      and start_record['profileDigest'] == profile_digest and start_record['agent'] == config['agent']
                      and start_record['identitySource'] == 'administrator-provisioned')
                identifier = start_record['id']
                ids.append(identifier)
                check(name + '-paired-terminal-assignment-' + str(index), terminal['session'] == binding['sessionId']
                      and terminal['profileDigest'] == profile_digest and terminal['agent'] == config['agent']
                      and terminal['identitySource'] == 'administrator-provisioned')
            other_records = [record for record in records if record['id'] not in ids]
            allowed_denials = {('request-denied', 429)}
            if refusal == 'expired':
                allowed_denials.add(('profile-refused', 403))
            if refusal == 'model':
                allowed_denials.add(('request-denied', 403))
            if refusal == 'protocol':
                allowed_denials.add(('request-denied', 400))
            check(name + '-all-remaining-audits-are-explicit-denials', all(
                (record['outcome'], record['status']) in allowed_denials and record['session'] == binding['sessionId']
                and record['profileDigest'] == profile_digest and record['agent'] == config['agent'] for record in other_records))
            check(name + '-unique-request-audit-pairs', len(ids) == len(set(ids))
                  and len(records) == len(set(record['id'] for record in records)))
            if refusal in ('expired', 'model', 'protocol'):
                expected_denial = {'expired': ('profile-refused', 403), 'model': ('request-denied', 403),
                                   'protocol': ('request-denied', 400)}[refusal]
                check(name + '-intended-native-denial-observed', any((record['outcome'], record['status']) == expected_denial
                      for record in other_records))
            check(name + '-credential-absent-from-result-and-log', b'synthetic-vm-provider-credential' not in stdout + stderr
                  + (case / 'gateway.log').read_bytes() + compact(records))
            if mode == 'valid' and not refusal:
                state['collect'] = True
                deadline = time.monotonic() + 5
                while list(spool.glob('*.json')) and time.monotonic() < deadline:
                    time.sleep(.05)
                check(name + '-collector-acknowledged', bool(state['collector']) and not list(spool.glob('*.json'))
                      and all(identifier in json.dumps(state['collector']) for identifier in ids))
            gateway_process.terminate()
            gateway_process.wait(timeout=40)
            check(name + '-gateway-clean-shutdown', gateway_process.returncode == 0)
            gateway_process = None
            vm_process = None
            log.close()
            log = None
            check(name + '-immutable-kernel-and-root', digest(Path(manifest['kernel'])) == manifest['kernelSha256']
                  and digest(Path(manifest['rootDisk'])) == manifest['rootDiskSha256'])
            return observation

        first = execute('edit-test')
        second = execute('fresh-session-reused-image', material=b'second independent session\n')
        check('same-backend-new-session-and-boot', first['guestResult']['binding']['backendSha256'] == second['guestResult']['binding']['backendSha256']
              and first['bootNonce'] != second['bootNonce'] and first['guestResult']['binding']['sessionId'] != second['guestResult']['binding']['sessionId'])
        execute('expired-profile', refusal='expired')
        execute('wrong-model', refusal='model')
        execute('wrong-protocol', refusal='protocol')
        execute('required-audit-unavailable', refusal='audit')
        execute('failed-shell-test', mode='failed-test')
        execute('truncated-provider-stream', mode='truncated')
        check('current-selected-sources-unchanged', sources(SOURCE) == report['vmSourceFiles']
              and sources(GATEWAY) == report['gatewaySourceFiles'] and sources(GATEWAY.parent / 'platform') == report['platformSourceFiles']
              and all(digest(OPENCODE / name) == value for name, value in worker_manifest['sourceFiles'].items()))
        check('selected-binaries-and-inputs-unchanged', digest(gateway) == report['gatewayExecutableSha256']
              and digest(args.worker) == worker_manifest['binarySha256'] and digest(inputs_manifest_path) == report['retainedRootInputManifestSha256']
              and all(digest(args.worker_inputs / 'root' / name) == value for name, value in actual.items())
              and all(digest(build / name) == value for name, value in manifest['binaries'].items())
              and all(digest(admission_dir / name) == value for name, value in report['nativeAdmissionFiles'].items()))
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        cleanup = True
        cleanup_errors = []
        for process in (vm_process, gateway_process):
            if process is None:
                continue
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=40)
                    except subprocess.TimeoutExpired:
                        cleanup = False
                        process.kill()
                        process.wait(timeout=5)
                if process is gateway_process and process.returncode != 0:
                    cleanup = False
            except BaseException as error:
                cleanup = False
                cleanup_errors.append(type(error).__name__)
        try:
            if log:
                log.close()
            if service:
                service.shutdown()
                service.server_close()
        except BaseException as error:
            cleanup = False
            cleanup_errors.append(type(error).__name__)
        report['ownedProcessCleanup'] = cleanup
        report['cleanupErrors'] = cleanup_errors
        report['passed'] = report['passed'] and cleanup
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(out / 'report.json'), 'sha256': digest(out / 'report.json'),
                      'passed': report['passed'], 'checks': len(report['checks'])}))
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
