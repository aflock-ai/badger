#!/usr/bin/env python3
# jade:ring local
"""Actual native VZ session, signed backend admission and synthetic TLS platform UAT."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import ssl
import signal
import socketserver
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.parse

SOURCE = Path(__file__).resolve().parent
OPENCODE = SOURCE.parent.parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            value.update(chunk)
    return value.hexdigest()


def compact(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()


def private(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def save(path, value):
    private(path, compact(value))


def sources(directory):
    return {str(p.relative_to(directory)): digest(p) for p in sorted(directory.rglob('*'))
            if p.is_file() and p.suffix in ('.go', '.mod', '.sum', '.swift', '.py', '.md', '.plist')}


def group_gone(pid, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        time.sleep(.02)
    return False


def go_inventory(raw):
    """Selected actual Go, cgo, assembly, test and embedded dependency inputs."""
    decoder = json.JSONDecoder()
    remaining = raw.decode()
    files = set()
    while remaining.strip():
        package, end = decoder.raw_decode(remaining.lstrip())
        remaining = remaining.lstrip()[end:]
        if package.get('Standard') or package.get('ImportPath', '').endswith('.test'):
            continue
        directory = Path(package['Dir'])
        for key in ('GoFiles', 'CgoFiles', 'CFiles', 'CXXFiles', 'MFiles', 'HFiles', 'FFiles', 'SFiles', 'SysoFiles',
                    'EmbedFiles', 'TestGoFiles', 'XTestGoFiles', 'TestEmbedFiles', 'XTestEmbedFiles'):
            files.update(directory / name for name in package.get(key, []))
        module = package.get('Module', {})
        module = module.get('Replace', module)
        if module.get('GoMod'):
            mod = Path(module['GoMod'])
            files.add(mod)
            if mod.with_suffix('.sum').exists():
                files.add(mod.with_suffix('.sum'))
    return {str(path): digest(path) for path in sorted(files)}


class UnixHTTP(HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=5)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def run_session_cases(out, assignment, report, check, command, control, state, lock, all_records, ready):
    workspace = out / 'workspace'
    (workspace / 'nested').mkdir(mode=0o700)
    initial = {'delete.txt': b'remove\n', 'keep.txt': b'original\n', 'nested/run.sh': b'old\n'}
    for name, raw in initial.items():
        private(workspace / name, raw)
    (workspace / '.git/hooks').mkdir(mode=0o700, parents=True)
    private(workspace / '.git/hooks/pre-commit', b'never executed or exported\n')
    host_snapshot = {str(path.relative_to(workspace)): digest(path) for path in workspace.rglob('*') if path.is_file()}
    profile_pin = report['profileSha256']
    manifest_pin = report['backendManifestSha256']
    pair_pin = sha((report['backendManifest']['files']['kernel']['sha256'] + '\n'
                    + report['backendManifest']['files']['rootDisk']['sha256'] + '\n').encode())
    request = {'schema': 'testifysec.aflock.vz-session-request/v1', 'workspaceId': assignment['workspaceId'],
               'prompt': 'Perform the synthetic workspace edits, run the bounded test, and finish.', 'timeoutSeconds': 45}
    sessions = []

    def descriptors(files):
        return [{key: value[key] for key in ('path', 'sha256', 'size', 'executable')} for value in files]

    def verify_capture(name, guest, original):
        raw = base64.b64decode(guest['outputBase64'], validate=True)
        check(name + '-output-exact-bytes', len(raw) <= 65536 and sha(raw) == guest['outputSha256'])
        files = guest['files']
        check(name + '-capture-ordered', isinstance(files, list) and [entry['path'] for entry in files] == sorted(entry['path'] for entry in files))
        for entry in files:
            content = base64.b64decode(entry['contentBase64'], validate=True)
            check(name + '-exact-file-' + entry['path'], len(content) == entry['size'] <= 65536 and sha(content) == entry['sha256'])
        check(name + '-initial-manifest-bound', guest['initialManifestSha256'] == sha(compact(descriptors(original)).replace(b'&', b'\\u0026')))
        if guest['captureComplete']:
            check(name + '-final-manifest-bound', guest['finalManifestSha256'] == sha(compact(descriptors(files)).replace(b'&', b'\\u0026')))
            check(name + '-removed-exact', guest['removed'] == sorted(set(entry['path'] for entry in original) - set(entry['path'] for entry in files)))
        else:
            check(name + '-incomplete-is-not-deletion', files == [] and guest['removed'] == [] and not guest['finalManifestSha256'])
        return raw

    def invoke(name, *, mode='valid', modified_assignment=None, raw_request=None, preboot=False, code=None,
               complete=None, prepare=None, restore=None, reset=True):
        control('reset' if reset else 'clear-observations')
        with lock:
            state.update(calls=[], collector=[], mode=mode, errors=[], mutated=False, quotaProbe=None)
        if prepare:
            prepare()
        selected = modified_assignment or assignment
        assignment_path = out / (name + '-assignment.json')
        request_path = out / (name + '-request.json')
        save(assignment_path, selected)
        encoded_request = compact(request) if raw_request is None else raw_request
        private(request_path, encoded_request)
        try:
            process = command(name, [out / 'session', '--assignment', assignment_path, '--request', request_path], timeout=120, expected=None,
                              extra_env={'PATH': '/nonexistent', 'HTTP_PROXY': 'http://127.0.0.1:1',
                                         'HTTPS_PROXY': 'http://127.0.0.1:1', 'ALL_PROXY': 'http://127.0.0.1:1', 'NO_PROXY': ''})
        finally:
            if restore:
                restore()
        value = json.loads(process['stdout'])
        calls = list(state['calls'])
        identity_calls = control('observations')['calls'] or []
        records = [record for record in all_records() if record['session'] == value['sessionId']]
        record = {'name': name, 'result': value, 'providerCalls': calls, 'platformCalls': identity_calls,
                  'audits': records, 'exitCode': process['exitCode'], 'quotaProbe': state.get('quotaProbe')}
        report['cases'].append(record)
        check(name + '-typed-result', value['schema'] == 'testifysec.aflock.vz-session-result/v1'
              and value['qualification'] == 'developer-only-unqualified' and value['finalizedSigningEvidence'] is False
              and value['completionSemantics'] == 'worker-exit-and-complete-capture')
        check(name + '-native-exit-matches-completion', process['exitCode'] == (0 if value['completed'] else 1))
        check(name + '-all-runtime-state-cleaned', not list((out / 'state').iterdir()) and not list((out / 'stage').iterdir()))
        check(name + '-fixture-errors-absent', not state['errors'])
        secret = (out / 'platform-state/refresh').read_bytes()
        check(name + '-no-secrets-in-output-audit', secret not in process['stdout'] + process['stderr'] + compact(records)
              and b'synthetic-aflock-vm-provider' not in process['stdout'] + process['stderr'] + compact(records))
        if code is not None:
            check(name + '-exact-refusal', value['code'] == code and value['completed'] is False)
        if complete is not None:
            check(name + '-completion', value['completed'] is complete)
        execution = value['execution']
        if preboot:
            check(name + '-zero-host-or-provider-effects', execution['hostInvoked'] is False and not calls and not execution.get('observationBase64'))
            return value
        check(name + '-host-process-observed', execution['hostInvoked'] is True and execution['hostExitObserved'] is True
              and execution['hostStdoutEOF'] is True and execution['hostStderrEOF'] is True and execution['hostGroupAbsent'] is True)
        check(name + '-native-cleanup-observed', execution['cleanupSafe'] is True and value['gatewayStopped'] is True
              and value['stateCleaned'] is True and value['backendCleaned'] is True and value['auditRetained'] is True)
        raw = base64.b64decode(execution['observationBase64'], validate=True)
        check(name + '-exact-host-observation', sha(raw) == execution['observationSha256'])
        observation = json.loads(raw)
        check(name + '-v4-lifecycle-and-scope', observation['schema'] == 'testifysec.vm-observation/v4'
              and observation['started'] is True and observation['stopped'] is True and observation['serialReaderDrained'] is True
              and observation['serialEOFObserved'] is True and observation['jobTransportDrained'] is True and observation['gatewayRelayDrained'] is True
              and observation['admissionIntegrated'] is False and observation['networkDevices'] == observation['sharedDirectories'] == observation['writableHostDisks'] == 0)
        job_raw = base64.b64decode(execution['jobBase64'], validate=True)
        job = json.loads(job_raw)
        binding = execution['binding']
        check(name + '-native-job-profile-backend-bindings', sha(job_raw) == execution['jobSha256'] == observation['jobSha256']
              and execution['profileSha256'] == profile_pin and execution['backendManifestSha256'] == manifest_pin
              and binding == job['binding'] and binding['sessionId'] == value['sessionId']
              and binding['profileSha256'] == profile_pin and binding['backendSha256'] == pair_pin
              and binding['requestSha256'] == sha(compact(job['request']).replace(b'&', b'\\u0026'))
              and binding['materialsSha256'] == sha(compact(job['materials']).replace(b'&', b'\\u0026')))
        check(name + '-caller-request-and-assignment-pinned', value['callerRequestSha256'] == sha(encoded_request)
              and value['assignmentSha256'] == digest(assignment_path) and value['platformConfigSha256'] == assignment['platformConfigSha256'])
        check(name + '-snapshot-exact-and-git-excluded', {entry['path']: base64.b64decode(entry['contentBase64'], validate=True) for entry in job['materials']} == initial)
        identity = value['platformIdentity']
        check(name + '-platform-identity-without-authority', identity['authenticated'] is True and identity['authorization'] == 'none'
              and identity['tenant_id'] == ready['tenantId'] and identity['agent_id'] == ready['agentId']
              and identity['repository_id'] == ready['repositoryId'] and identity['spiffe_id'] == ready['spiffeId']
              and identity['delegation']['human_presence'] == 'not-asserted' and identity['delegation']['user_id'] == ready['delegatingUserId']
              and identity['delegation']['enrollment_aal'] == 'aal2')
        successful_checks = [call for call in identity_calls if call.get('status') == 200]
        check(name + '-fresh-native-and-per-request-platform-checks', len(successful_checks) >= 2 + len(calls)
              and len({call['nonce'] for call in identity_calls}) == len(identity_calls)
              and all(call['credentialMatched'] and call['tls'] for call in identity_calls)
              and any(call.get('response') == identity for call in successful_checks))
        guest = observation['guestResult']
        output = b''
        if guest:
            check(name + '-guest-actual-worker-isolation', guest['workerStarted'] is True and guest['workerUid'] == 65534
                  and guest['rootReadonly'] is True and guest['binding'] == binding and guest['nonce'] == observation['bootNonce'])
            output = verify_capture(name, guest, job['materials'])
        else:
            check(name + '-truncated-host-stop-without-invented-guest-result', mode == 'truncated' and not value['completed']
                  and not observation['passed'] and observation['gatewayRelay']['lastError'] == 'gateway-response-truncated')
        ids = []
        for index, call in enumerate(calls):
            terminal = [item for item in records if item['id'] == call['auditId']]
            check(name + '-unique-terminal-' + str(index), len(terminal) == 1)
            terminal = terminal[0]
            start = call['durableStart']
            check(name + '-audit-before-effect-' + str(index), start['outcome'] == 'started' and start['id'] == terminal['id']
                  and terminal['requestBytes'] == call['bodyBytes'] and terminal['status'] == 200
                  and terminal['outcome'] == ('response-interrupted' if mode == 'truncated' else 'provider-stream-ended')
                  and start['started'] == terminal['started']
                  and datetime.fromisoformat(terminal['finished']) >= datetime.fromisoformat(terminal['started']))
            for label, item in [('start', start), ('terminal', terminal)]:
                check(name + '-authenticated-' + label + '-' + str(index), item['identitySource'] == 'platform-online-check'
                      and item['agent'] == ready['spiffeId'] and item['tenant'] == ready['tenantId'] and item['repositoryId'] == ready['repositoryId']
                      and item['delegatingUserId'] == ready['delegatingUserId'] and item['enrollmentAal'] == 'aal2'
                      and item['profileDigest'] == profile_pin and item['session'] == value['sessionId'])
            observed_identity = [entry['response'] for entry in successful_checks
                                 if entry.get('response', {}).get('checked_at') == start['identityCheckedAt']]
            check(name + '-audit-joins-platform-check-' + str(index), len(observed_identity) == 1
                  and observed_identity[0]['spiffe_id'] == start['agent']
                  and observed_identity[0]['repository_id'] == start['repositoryId']
                  and observed_identity[0]['authorization'] == 'none')
            check(name + '-provider-secret-boundary-' + str(index), call['credentialMatched'] and call['authorityAbsent'])
            config = call['runtimeConfig']
            check(name + '-observed-generated-config-before-provider-' + str(index), call['runtimeConfigSha256'] == execution['configSha256']
                  and config['schema'] == 'testifysec.vm-config/v4' and config['binding'] == binding
                  and config['backendManifestSha256'] == manifest_pin and config['jobSha256'] == execution['jobSha256']
                  and config['gatewayConfigSha256'] == execution['gatewayConfigSha256'])
            ids.append(call['auditId'])
        check(name + '-audit-id-uniqueness', len(ids) == len(set(ids)) and len(records) == len({item['id'] for item in records}))
        remaining = [item for item in records if item['id'] not in ids]
        allowed = {('request-denied', 429)}
        if mode == 'revoke-during':
            allowed.add(('identity-refused', 403))
        if mode == 'wrong-model':
            allowed.add(('request-denied', 403))
        check(name + '-all-unpaired-records-explicit-denials', all((item['outcome'], item['status']) in allowed for item in remaining))
        check(name + '-host-workspace-unchanged', host_snapshot == {str(path.relative_to(workspace)): digest(path) for path in workspace.rglob('*') if path.is_file()})
        sessions.append((value['sessionId'], observation['bootNonce']))
        if mode == 'valid':
            check(name + '-worker-complete', guest['passed'] and guest['exitObserved'] and guest['exitCode'] == 0 and guest['reaped']
                  and guest['outputDrained'] and guest['outputComplete'] and guest['captureComplete'])
            expected = {'keep.txt': (b'changed\n', False), 'nested/a&b/result.bin': (bytes([0, 255, 128, 10]), False),
                        'nested/run.sh': (b'#!/bin/sh\nexit 0\n', True)}
            actual = {entry['path']: (base64.b64decode(entry['contentBase64'], validate=True), entry['executable']) for entry in guest['files']}
            check(name + '-exact-nested-binary-executable-edits', actual == expected and guest['removed'] == ['delete.txt'])
            events = [json.loads(line) for line in output.splitlines() if line.startswith(b'{')]
            tools = [event['part'] for event in events if event.get('type') == 'tool_use']
            requested = [call for call in calls if call['operation']]
            check(name + '-actual-upstream-tool-completed', len(tools) == len(requested) == 1
                  and tools[0].get('callID', tools[0].get('id')) == requested[0]['callId'] and tools[0]['state']['status'] == 'completed'
                  and tools[0]['state']['input'] == requested[0]['arguments'] and tools[0]['state']['metadata'].get('exit', tools[0]['state']['metadata'].get('metadata', {}).get('exit')) == 0)
            check(name + '-no-fixture-success-marker', b'HARNESS_TEST_PASSED' not in output)
        elif mode == 'revoke-during':
            check(name + '-revoked-next-request-refused', state['mutated'] and any(call.get('status') == 401 for call in identity_calls)
                  and any(item['outcome'] == 'identity-refused' and item['status'] == 403 for item in remaining))
            check(name + '-no-provider-call-after-revoking-tool-response', [call for call in calls if call['operation']][-1] == calls[-1])
        elif mode == 'truncated':
            check(name + '-transport-interruption-observed', calls and any(item['outcome'] == 'response-interrupted' for item in records))
        elif mode == 'audit-quota':
            probe = state.get('quotaProbe') or {}
            check(name + '-audit-bound-blocks-next-model-call', len(records) == 2 and len(calls) <= 2
                  and probe.get('status') == 503 and probe['exactAuditRefusal']
                  and probe['recordsBefore'] == probe['recordsAfter'] == 2
                  and probe['providerCallsBefore'] == probe['providerCallsAfter'])
        elif mode in ('symlink', 'overflow'):
            check(name + '-unsafe-capture-refused', guest['captureComplete'] is False and guest['passed'] is False)
        elif mode == 'timeout':
            check(name + '-worker-deadline-observed', guest['passed'] is False and guest['error'] == 'worker-deadline'
                  and guest['exitObserved'] and guest['reaped'] and guest['outputDrained'])
        return value

    invoke('actual-native-session', complete=True)
    for name, modified in [('request-workspace', {**request, 'workspaceId': 'foreign'}),
                           ('request-authority', {**request, 'agent': ready['spiffeId']}),
                           ('request-path', {**request, 'workspaceDirectory': str(workspace)}),
                           ('request-timeout', {**request, 'timeoutSeconds': 46})]:
        invoke(name, raw_request=compact(modified), preboot=True, code='request_invalid')
    invoke('request-duplicate', raw_request=b'{"schema":"ignored",' + compact(request)[1:], preboot=True, code='request_invalid')
    invoke('profile-expired', modified_assignment={**assignment, 'signedProfileFile': str(out / 'profiles/expired.json')},
           preboot=True, code='backend_profile_denied')
    invoke('profile-cross-version', modified_assignment={**assignment, 'signedProfileFile': str(out / 'profiles/valid-v1.json')},
           preboot=True, code='backend_profile_denied')
    kernel = out / 'installation/kernel'
    with kernel.open('rb') as stream:
        original_byte = stream.read(1)
    def replace_kernel(raw):
        kernel.chmod(0o600)
        with kernel.open('r+b') as stream:
            stream.write(raw)
        kernel.chmod(0o400)
    invoke('backend-kernel-tamper', prepare=lambda: replace_kernel(bytes([original_byte[0] ^ 1])),
           restore=lambda: replace_kernel(original_byte), preboot=True, code='backend_file_digest')
    for name, operation in [('scope-before-boot', 'remove-scope'), ('platform-outage', 'outage')]:
        invoke(name, prepare=lambda operation=operation: control(operation), preboot=True, code='platform_identity')
    invoke('workspace-symlink', prepare=lambda: (workspace / 'link').symlink_to('/etc/passwd'), restore=lambda: (workspace / 'link').unlink(),
           preboot=True, complete=False)
    invoke('actual-second-session', complete=True)
    template = json.loads((out / 'gateway-template.json').read_bytes())
    for name, change in [('unsupported-worker-model', {'model': 'denied'}),
                         ('unsupported-worker-responses', {'protocol': 'responses'})]:
        path = out / (name + '-template.json')
        save(path, {**template, **change})
        invoke(name, modified_assignment={**assignment, 'gatewayTemplateFile': str(path), 'gatewayTemplateSha256': digest(path)},
               preboot=True, code='worker_route_unsupported')
        check(name + '-no-platform-check-before-route-refusal', not report['cases'][-1]['platformCalls'])
    quota = out / 'quota-template.json'
    save(quota, {**template, 'maxRecords': 2})
    invoke('bounded-audit-spool', mode='audit-quota', modified_assignment={**assignment, 'gatewayTemplateFile': str(quota), 'gatewayTemplateSha256': digest(quota)},
           raw_request=compact({**request, 'timeoutSeconds': 8}), complete=False)
    invoke('truncated-model-stream', mode='truncated')
    invoke('capture-symlink', mode='symlink', complete=False)
    invoke('capture-overflow', mode='overflow', complete=False)
    invoke('worker-timeout', mode='timeout', raw_request=compact({**request, 'timeoutSeconds': 2}), complete=False)
    invoke('revoke-during-session', mode='revoke-during')
    invoke('revoked-before-boot', reset=False, preboot=True, code='platform_identity')
    check('sessions-and-nonces-are-fresh', len({value[0] for value in sessions}) == len(sessions)
          and len({value[1] for value in sessions}) == len(sessions))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--bun', required=True, type=Path)
    parser.add_argument('--worker', required=True, type=Path)
    parser.add_argument('--worker-inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.absolute()
    out.mkdir(mode=0o700)
    for name in ('home', 'tmp', 'platform-state', 'state', 'audit', 'stage', 'workspace'):
        (out / name).mkdir(mode=0o700)
    env = {'PATH': ':'.join([str(args.go.parent), str(args.bun.parent), str(Path(sys.executable).parent), '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
           'HOME': str(out / 'home'), 'TMPDIR': str(out / 'tmp'), 'LANG': 'C', 'GOWORK': 'off',
           'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOMAXPROCS': '2',
           'GOMODCACHE': os.environ.get('GOMODCACHE', str(Path.home() / 'go/pkg/mod')),
           'GOCACHE': os.environ.get('GOCACHE', str(Path.home() / 'Library/Caches/go-build')),
           'GOFLAGS': '-mod=readonly -p=2', 'CGO_ENABLED': '1'}
    roots = {'vm': SOURCE, 'broker': SOURCE.parent / 'broker', 'gateway': SOURCE.parent / 'gateway',
             'platform': SOURCE.parent / 'platform', 'managed': SOURCE.parent / 'managed', 'native': SOURCE.parent / 'native'}
    report = {'schema': 'testifysec.aflock.vz-session-uat/v1', 'passed': False, 'checks': [], 'cases': [], 'commands': {},
              'startedAt': datetime.now(timezone.utc).isoformat(), 'sourceFiles': {name: sources(root) for name, root in roots.items()},
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=OPENCODE, text=True).strip(),
              'worktreeDirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=OPENCODE)),
              'tools': {name: {'path': str(path.resolve()), 'sha256': digest(path)} for name, path in [('go', args.go), ('bun', args.bun), ('python', Path(sys.executable))]},
              'scope': 'actual compiled OpenCode VM plus native signed-profile/backend admission and a synthetic local TLS platform',
              'qualification': 'developer-only-unqualified', 'liveProviderCalls': False, 'dockerInvocations': 0,
              'limitations': ['Platform identity comes from the synthetic session-check fixture (platform/cmd/session-platform-fixture): '
                              'no production platform handler, enrollment store, tenant filter or revocation store is exercised.',
                              'Synthetic provider, with native verification of every platform and provider response.',
                              'Same-UID developer custody; no installed privilege boundary, hardware attestation, FIPS/IL6 qualification or current human ceremony.',
                              'Host observations retain admissionIntegrated:false; native admission and live identity are separate facts.',
                              'No finalized signing record, host workspace apply, Git push, upload or platform policy activation.']}
    fixture = None
    fixture_log = None
    service = None
    service_thread = None
    edge = None
    edge_thread = None
    ready = None
    lock = threading.Lock()
    handler_threads = []
    state = {'calls': [], 'collector': [], 'mode': 'valid', 'errors': [], 'audit': out / 'audit', 'mutated': False,
             'deviceCodes': {}, 'deviceTokens': [], 'signIns': 0, 'signOuts': []}

    def check(name, ok):
        report['checks'].append({'name': name, 'passed': bool(ok)})
        if not ok:
            raise RuntimeError(name)

    def command(name, argv, cwd=OPENCODE, timeout=300, expected=0, extra_env=None, limit=4 << 20):
        # File-backed bounded output avoids any inherited-stdin/pipe EOF trap.
        # Group absence still must be observed, even after the leader exited.
        stdout_path, stderr_path = out / (name + '.stdout'), out / (name + '.stderr')
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            stdout_path.chmod(0o600)
            stderr_path.chmod(0o600)
            process = subprocess.Popen([str(x) for x in argv], cwd=cwd, env={**env, **(extra_env or {})},
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            end = time.monotonic() + timeout
            complete = False
            try:
                while process.poll() is None:
                    if time.monotonic() >= end or max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > limit:
                        raise RuntimeError(name + '-deadline-or-output-bound')
                    if name == 'bounded-audit-spool' and state.get('quotaProbe') is None:
                        sockets = list((out / 'state').glob('*/gateway.sock'))
                        if len(sockets) == 1:
                            current = [record for record in all_records() if record['session'] == sockets[0].parent.name]
                            if len(current) == 2 and all(record['outcome'] != 'started' for record in current):
                                probe_quota(sockets[0])
                    time.sleep(.03)
                check(name + '-owned-group-absent', group_gone(process.pid))
                check(name + '-output-bounded', max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) <= limit)
                complete = True
            finally:
                if not complete:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
                    check(name + '-failure-group-cleaned', group_gone(process.pid))
        stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
        report['commands'][name] = {'exitCode': process.returncode, 'stdoutSha256': sha(stdout), 'stderrSha256': sha(stderr)}
        if expected is not None:
            check(name + '-exit', process.returncode == expected)
        return {'exitCode': process.returncode, 'stdout': stdout, 'stderr': stderr}

    def control(operation):
        connection = UnixHTTP(ready['controlSocket'])
        try:
            connection.request('POST', '/' + operation, body=b'{}', headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(1 << 20)
            if response.status != 200 or len(raw) >= 1 << 20:
                raise RuntimeError('platform fixture control refused')
            return json.loads(raw)
        finally:
            connection.close()

    def all_records():
        records = []
        for path in sorted(state['audit'].rglob('*.json')):
            if path.stat().st_size > 16384:
                raise RuntimeError('oversized audit file cannot be excluded from evidence')
            record = json.loads(path.read_bytes())
            if not isinstance(record, dict) or 'outcome' not in record or 'id' not in record:
                raise RuntimeError('unexpected audit JSON cannot be excluded from evidence')
            records.append(record)
        return records

    def probe_quota(path):
        # Observe the actual native audit guard even if the SDK keeps retrying
        # 503 until its worker deadline. This extra local fixture request carries
        # no credential, does not impersonate the VM, and must cause no effect.
        with lock:
            calls_before = len(state['calls'])
        session = path.parent.name
        before = len([record for record in all_records() if record['session'] == session])
        connection = UnixHTTP(path)
        try:
            raw = compact({'model': 'approved', 'messages': [{'role': 'user', 'content': 'synthetic audit bound probe'}]})
            connection.request('POST', '/v1/chat/completions', body=raw, headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            body = response.read(1025)
            with lock:
                calls_after = len(state['calls'])
            state['quotaProbe'] = {'status': response.status, 'bodySha256': sha(body),
                                   'exactAuditRefusal': body == b'required audit unavailable\n',
                                   'recordsBefore': before, 'recordsAfter': len([record for record in all_records() if record['session'] == session]),
                                   'providerCallsBefore': calls_before, 'providerCallsAfter': calls_after}
        finally:
            connection.close()

    class Provider(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass

        def do_POST(self):
            try:
                self.connection.settimeout(5)
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 2 << 20:
                    raise ValueError('provider request bound')
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError('provider incomplete body')
                body = json.loads(raw)
                if self.path == '/v1/logs':
                    with lock:
                        state['collector'].append(body)
                    self.send_response(503)  # Preserve actual durable spool for exact before-effect inspection.
                    self.end_headers()
                    return
                if self.path != '/v1/chat/completions' or body.get('model') != 'approved' or body.get('stream') is not True:
                    raise ValueError('unassigned provider request')
                names = [tool['function']['name'] for tool in body.get('tools', [])]
                if set(names) & {'task', 'webfetch', 'websearch', 'lsp', 'skill', 'question'}:
                    raise ValueError('unapproved worker tool')
                starts = [record for record in all_records() if record['outcome'] == 'started'
                          and record['identitySource'] == 'platform-online-check']
                configs = list((out / 'stage').glob('*/config.json'))
                if len(configs) != 1 or configs[0].stat().st_size > 4096:
                    raise ValueError('one bounded generated runtime config required before provider effect')
                runtime_raw = configs[0].read_bytes()
                with lock:
                    index = len(state['calls'])
                    used = {call['auditId'] for call in state['calls']}
                    eligible = [record for record in starts if record['id'] not in used]
                    if len(eligible) != 1:
                        raise ValueError('exact outstanding durable start missing')
                    audit = eligible[0]
                    tool_results = sum(message.get('role') == 'tool' for message in body.get('messages', []))
                    operation = 'bash' if 'bash' in names else 'shell' if 'shell' in names else ''
                    use_tool = bool(operation and tool_results == 0)
                    mode = state['mode']
                    tool_mode = mode if mode in ('symlink', 'overflow', 'timeout') else 'edit'
                    tool_command = '/toolpack/managed-uat-helper ' + tool_mode
                    if tool_mode == 'edit':
                        tool_command += ' && test "$(cat keep.txt)" = changed && /bin/sh nested/run.sh'
                    arguments = {'command': tool_command,
                                 'description': 'Perform bounded synthetic workspace edits and test', 'timeout': 10000}
                    call = {'auditId': audit['id'], 'durableStart': audit, 'bodyBytes': len(raw), 'bodySha256': sha(raw),
                            'runtimeConfig': json.loads(runtime_raw), 'runtimeConfigSha256': sha(runtime_raw),
                            'credentialMatched': bool(state['deviceTokens']) and self.headers.get('Authorization') == 'Bearer ' + state['deviceTokens'][-1],
                            'authorityAbsent': all(self.headers.get(key) is None for key in ('X-Agent-ID', 'X-Tenant-ID', 'X-Delegating-User')),
                            'callId': 'call-' + str(index) if use_tool else None, 'operation': operation if use_tool else None,
                            'arguments': arguments if use_tool else None}
                    state['calls'].append(call)
                    mutate = mode == 'revoke-during' and use_tool and not state['mutated']
                    if mutate:
                        state['mutated'] = True
                if mutate:
                    control('revoke')
                delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': call['callId'], 'type': 'function',
                         'function': {'name': operation, 'arguments': compact(arguments).decode()}}]} if use_tool else {'role': 'assistant', 'content': 'Workspace changes completed.'}
                def chunk(delta, finish):
                    return {'id': 'fixture-' + str(index), 'object': 'chat.completion.chunk', 'created': 1, 'model': 'approved',
                            'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish}]}
                response = b''.join(b'data: ' + compact(item) + b'\n\n' for item in (chunk(delta, None), chunk({}, 'tool_calls' if use_tool else 'stop')))
                if mode != 'truncated':
                    response += b'data: [DONE]\n\n'
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.end_headers()
                self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as error:
                with lock:
                    state['errors'].append(type(error).__name__ + ': ' + str(error))
                self.send_error(500)

    class Edge(Provider):
        """The model broker behind its edge, as device sign-in sees it (badger-broker device.go):
        the approval page approves at once and redirects to the session's loopback callback, the
        exchange checks the PKCE verifier and port, and /broker/v1/* is the synthetic provider."""

        def do_GET(self):
            try:
                url = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(url.query)
                if url.path != '/broker/device/authorize' or sorted(query) != ['challenge', 'device', 'port', 'state'] \
                        or any(len(v) != 1 for v in query.values()):
                    raise ValueError('unexpected approval request')
                code = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
                with lock:
                    state['deviceCodes'][code] = {k: v[0] for k, v in query.items()}
                    state['signIns'] += 1
                self.send_response(303)
                self.send_header('Location', 'http://127.0.0.1:' + query['port'][0] + '/callback?code=' + code + '&state=' + query['state'][0])
                self.end_headers()
            except Exception as error:
                with lock:
                    state['errors'].append(type(error).__name__ + ': ' + str(error))
                self.send_error(400)

        def do_POST(self):
            if self.path.startswith('/broker/v1/'):
                self.path = self.path[len('/broker'):]
                return super().do_POST()
            try:
                if self.path != '/broker/device/token':
                    raise ValueError('unexpected edge path')
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
                with lock:
                    grant = state['deviceCodes'].pop(body.get('code'), None)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(str(body.get('verifier')).encode()).digest()).rstrip(b'=').decode()
                if grant is None or grant['challenge'] != challenge or grant['port'] != str(body.get('port')):
                    raise ValueError('device code refused')
                token = 'bbt_' + base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
                with lock:
                    state['deviceTokens'].append(token)
                response = compact({'token': token, 'expires_at': '2099-01-01T00:00:00Z', 'principal': 'uat@example.test'})
                self.send_response(201)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except Exception as error:
                with lock:
                    state['errors'].append(type(error).__name__ + ': ' + str(error))
                self.send_error(400)

        def do_DELETE(self):
            with lock:
                state['signOuts'].append(self.headers.get('Authorization', ''))
            self.send_response(204)
            self.end_headers()

    class FixtureServer(ThreadingHTTPServer):
        # Join each observed handler explicitly below, with a deadline. A stuck
        # fixture thread fails the report and cannot keep the Python process alive.
        daemon_threads = True
        block_on_close = False

        def server_bind(self):
            # HTTPServer.server_bind resolves the host's FQDN, which stalls for seconds on a host
            # with slow reverse DNS; a loopback fixture has no use for the name.
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = self.server_address[:2]

        def process_request(self, request, client_address):
            handler = threading.Thread(target=self.process_request_thread, args=(request, client_address), daemon=True)
            with lock:
                handler_threads.append(handler)
            handler.start()

    try:
        # The platform is a synthetic session-check fixture built from this repository; its exact
        # Go inputs are pinned like the gateway and session builds below.
        listed = command('platform-fixture-input-list', [args.go, 'list', '-deps', '-json', './cmd/session-platform-fixture'],
                         cwd=roots['platform'], limit=32 << 20)
        platform_inputs = go_inventory(listed['stdout'])
        save(out / 'platform-go-inputs.json', platform_inputs)
        report['platformInputsSha256'] = digest(out / 'platform-go-inputs.json')
        fixture_binary = out / 'platform-fixture'
        command('build-platform-fixture', [args.go, 'build', '-trimpath', '-buildvcs=false', '-o', fixture_binary,
                                           './cmd/session-platform-fixture'], cwd=roots['platform'])
        report['platformFixtureSha256'] = digest(fixture_binary)
        check('platform-fixture-inputs-unchanged', all(digest(path) == pin for path, pin in platform_inputs.items()))
        fixture_log = (out / 'platform-fixture.log').open('xb')
        (out / 'platform-fixture.log').chmod(0o600)
        fixture = subprocess.Popen([str(fixture_binary), str(out / 'platform-state')], cwd=out, env=env,
                                   stdin=subprocess.DEVNULL, stdout=fixture_log, stderr=fixture_log, start_new_session=True)
        end = time.monotonic() + 15
        while not (out / 'platform-state/ready.json').exists():
            check('platform-fixture-starting', fixture.poll() is None and time.monotonic() < end)
            time.sleep(.1)
        ready = json.loads((out / 'platform-state/ready.json').read_bytes())
        report['platformFixture'] = ready
        check('synthetic-platform-fixture-ready', ready['schema'] == 'testifysec.aflock.vz-session-platform-fixture/v1'
              and ready['synthetic'] is True and control('observations')['fixture'] is True)

        retained = json.loads((args.worker_inputs / 'manifest.json').read_bytes())
        check('retained-root-provenance', retained['schema'] == 'testifysec.vm-worker-inputs/v1'
              and retained['containerStarted'] is False and retained['ownedContainerRemoved'] is True)
        root = out / 'worker-root'
        root.mkdir(mode=0o700)
        found = {}
        for path in sorted((args.worker_inputs / 'root').rglob('*')):
            info = path.lstat()
            check('retained-regular-' + str(path.relative_to(args.worker_inputs / 'root')),
                  stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
            if not stat.S_ISREG(info.st_mode):
                continue
            name = str(path.relative_to(args.worker_inputs / 'root'))
            found[name] = digest(path)
            check('retained-pin-' + name, name in retained['files'] and found[name] == retained['files'][name]['sha256'])
            if name == 'toolpack/opencode-worker':
                continue
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            check('copied-root-' + name, digest(target) == found[name])
        check('retained-root-complete', set(found) == set(retained['files']))
        report['retainedRootManifest'] = retained
        worker_manifest = json.loads(Path(str(args.worker) + '.manifest.json').read_bytes())
        check('actual-gateway-worker', worker_manifest['fixtureModel'] is False and worker_manifest['target'] == 'bun-linux-arm64'
              and digest(args.worker) == worker_manifest['binarySha256'])
        check('worker-selected-sources-current', all(digest(OPENCODE / name) == pin for name, pin in worker_manifest['sourceFiles'].items()))
        report['workerManifest'] = worker_manifest
        (root / 'toolpack').mkdir(exist_ok=True)
        shutil.copy2(args.worker, root / 'toolpack/opencode-worker')
        helper = root / 'toolpack/managed-uat-helper'
        command('build-workspace-fixture-helper', [args.go, 'build', '-trimpath', '-buildvcs=false', '-o', helper, SOURCE / 'fixtures/managed-worker.go'],
                extra_env={'GOOS': 'linux', 'GOARCH': 'arm64', 'CGO_ENABLED': '0'})
        report['fixtureHelperSha256'] = digest(helper)
        command('build-vm', [sys.executable, '-B', SOURCE / 'build.py', '--go', args.go, '--output', out / 'build',
                             '--mode', 'worker', '--protocol', '3', '--worker-root', root], timeout=600)
        report['vmBuildManifest'] = json.loads((out / 'build/manifest.json').read_bytes())
        command('export-backend', [sys.executable, '-B', SOURCE / 'package-backend.py', '--build', out / 'build', '--output', out / 'installation'])
        manifest_raw = (out / 'installation/backend.json').read_bytes()
        manifest = json.loads(manifest_raw)
        report['backendManifest'] = manifest
        report['backendManifestSha256'] = sha(manifest_raw)

        template = (roots['managed'] / 'fixtures-v2.go').read_bytes()
        literal = b'manifest := []byte(`{"schema":"testifysec.synthetic-backend-manifest/v1","executable":false}`)'
        check('signed-fixture-template-point', template.count(literal) == 1 and template.count(b'"uat-tenant"') == 2)
        generated = template.replace(literal, b'manifest := []byte(' + json.dumps(manifest_raw.decode()).encode() + b')')
        generated = generated.replace(b'"uat-tenant"', compact(ready['tenantId']))
        private(out / 'signed-fixtures.go', generated)
        command('generate-signed-profile', [args.go, 'run', out / 'signed-fixtures.go', out / 'profiles'], cwd=roots['native'])
        report['generatedFixtureSha256'] = sha(generated)
        command('build-native-admission', [sys.executable, '-B', roots['managed'] / 'build.py', '--go', args.go, '--bun', args.bun,
                                         '--trust', out / 'profiles/trust-v2.json', '--output', out / 'admission'], timeout=600)
        # Gateway admission requires a private bundle parent, stronger than the
        # backend reader's non-writable ancestor condition. Match real provisioning.
        (out / 'admission').chmod(0o700)
        native_manifest = json.loads((out / 'admission/manifest.json').read_bytes())
        report['admissionManifest'] = native_manifest
        check('native-build-files-current', all(digest(out / 'admission' / name) == pin for name, pin in native_manifest['files'].items()))
        envelope = (out / 'profiles/valid-v2.json').read_bytes()
        payload = base64.b64decode(json.loads(envelope)['payload'], validate=True)
        profile = json.loads(payload)
        report['profileSha256'] = sha(payload)
        check('signed-profile-exact-backend-and-tenant', profile['tenantId'] == ready['tenantId']
              and profile['backend'] == {'kind': 'darwin-vz/v1', 'manifestSha256': sha(manifest_raw)})
        for name, directory, target in [('gateway', roots['gateway'], '.'), ('session', roots['broker'], './cmd/vz-session')]:
            listing = command(name + '-go-input-list', [args.go, 'list', '-deps', '-json', target], cwd=directory, limit=32 << 20)
            inputs = go_inventory(listing['stdout'])
            save(out / (name + '-go-inputs.json'), inputs)
            # The session binary gets the UAT-only headless browser (build tag uatsignin): no person is
            # here to approve. A release build never carries it (vzsession opener_release.go).
            tags = ['-tags', 'uatsignin'] if name == 'session' else []
            command('build-' + name, [args.go, 'build', '-trimpath', '-buildvcs=false', *tags, '-o', out / name, target], cwd=directory)
            check(name + '-go-inputs-unchanged', all(digest(path) == pin for path, pin in inputs.items()))
            report[name + 'Build'] = {'sha256': digest(out / name), 'inputsSha256': digest(out / (name + '-go-inputs.json'))}

        service = FixtureServer(('127.0.0.1', 0), Provider)
        service_thread = threading.Thread(target=service.serve_forever)
        service_thread.start()
        # The provider is the broker behind a TLS edge with a self-signed, pinned certificate; the
        # session gets its token by device sign-in, never from a file.
        command('edge-certificate', ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-pkeyopt', 'ec_param_enc:named_curve',
                                     '-nodes', '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                                     '-keyout', out / 'edge.key', '-out', out / 'edge.pem'])
        spki = subprocess.run(['/usr/bin/openssl', 'x509', '-in', out / 'edge.pem', '-pubkey', '-noout'], check=True, capture_output=True).stdout
        der = subprocess.run(['/usr/bin/openssl', 'pkey', '-pubin', '-outform', 'der'], input=spki, check=True, capture_output=True).stdout
        edge_pin = hashlib.sha256(der).hexdigest()
        edge = FixtureServer(('127.0.0.1', 0), Edge)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(out / 'edge.pem', out / 'edge.key')
        # The handshake runs in each handler thread, not in accept(): one stalled client cannot
        # hold the edge for every other.
        edge.socket = tls.wrap_socket(edge.socket, server_side=True, do_handshake_on_connect=False)
        edge_thread = threading.Thread(target=edge.serve_forever)
        edge_thread.start()
        edge_url = f'https://127.0.0.1:{edge.server_port}/broker'
        backend_assignment = {'schema': 'testifysec.aflock.vz-backend-assignment/v1', 'installationDirectory': str(out / 'installation'),
                              'stagingDirectory': str(out / 'stage'), 'manifestSha256': sha(manifest_raw), 'profileSha256': sha(payload),
                              'admissionExecutable': str(out / 'admission/hardened-admission'),
                              'admissionSha256': digest(out / 'admission/hardened-admission'),
                              'tenantId': ready['tenantId'], 'deploymentId': profile['deploymentId'], 'profileId': profile['profileId']}
        save(out / 'backend-assignment.json', backend_assignment)
        gateway_template = {'schema': 'testifysec.aflock.vz-gateway-template/v1', 'protocol': 'chat-completions',
                            'providerURL': edge_url + '/v1/chat/completions',
                            'brokerSignIn': {'edgeUrl': edge_url, 'edgeCertSha256': edge_pin, 'deviceIdFile': str(out / 'device-id')},
                            'collectorURL': f'http://127.0.0.1:{service.server_port}/v1/logs', 'collectorTokenFile': '',
                            'model': 'approved', 'maxRecords': 128, 'maxOfflineSeconds': 600, 'timeoutSeconds': 10, 'developmentLoopback': True}
        save(out / 'gateway-template.json', gateway_template)
        assignment = {'schema': 'testifysec.aflock.vz-session-assignment/v1',
                      'backendAssignmentFile': str(out / 'backend-assignment.json'), 'backendAssignmentSha256': digest(out / 'backend-assignment.json'),
                      'platformConfigFile': ready['platformConfigFile'], 'platformConfigSha256': digest(ready['platformConfigFile']),
                      'signedProfileFile': str(out / 'profiles/valid-v2.json'), 'gatewayExecutable': str(out / 'gateway'), 'gatewaySha256': digest(out / 'gateway'),
                      'gatewayTemplateFile': str(out / 'gateway-template.json'), 'gatewayTemplateSha256': digest(out / 'gateway-template.json'),
                      'workspaceId': 'fixture-workspace', 'workspaceDirectory': str(out / 'workspace'),
                      'stateDirectory': str(out / 'state'), 'auditDirectory': str(out / 'audit'), 'maximumTimeoutSeconds': 45}
        save(out / 'assignment.json', assignment)
        # Cases use the stable public CLI. Native session result verification is
        # below, separate from fixture HTTP/provider assertions.
        run_session_cases(out, assignment, report, check, command, control, state, lock, all_records, ready)
        check('final-all-selected-sources-current', report['sourceFiles'] == {name: sources(root) for name, root in roots.items()})
        check('final-platform-fixture-inputs-and-binary-current', all(digest(path) == pin for path, pin in platform_inputs.items())
              and digest(fixture_binary) == report['platformFixtureSha256'])
        check('final-native-build-inputs-current', all(digest(roots['managed'] / name) == pin for name, pin in native_manifest['sourceFiles'].items())
              and all(digest(roots['native'] / name) == pin for name, pin in native_manifest['nativeBuild']['sourceFiles'].items()))
        check('final-native-go-and-tool-inputs-current', all(digest(path) == pin for path, pin in native_manifest['nativeGoInputs']['files'].items())
              and all(digest(tool['path']) == tool['sha256'] for tool in native_manifest['buildTools'].values()))
        for label in ('gateway', 'session'):
            pins = json.loads((out / (label + '-go-inputs.json')).read_bytes())
            check('final-' + label + '-inputs-and-binary-current', all(digest(path) == pin for path, pin in pins.items())
                  and digest(out / label) == report[label + 'Build']['sha256'])
        check('final-exported-backend-unchanged', (out / 'installation/backend.json').read_bytes() == manifest_raw
              and all(digest(out / 'installation' / name) == manifest['files'][role]['sha256']
                      for role, name in {'host': 'hc-vm', 'kernel': 'kernel', 'rootDisk': 'root.ext4', 'provenance': 'build.json'}.items()))
        check('device-signin-each-session', state['signIns'] >= 1 and len(state['deviceTokens']) >= 1)
        check('device-tokens-signed-out', {'Bearer ' + t for t in state['deviceTokens']} <= set(state['signOuts']))
        stored = [p for p in out.rglob('*') if p.is_file() and p.stat().st_size < (8 << 20)
                  and any(t.encode() in p.read_bytes() for t in state['deviceTokens'])]
        check('device-token-never-on-disk', not stored)
        check('final-provider-errors-absent', not state['errors'])
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if edge:
            if edge_thread and edge_thread.ident is not None:
                edge.shutdown()
            edge.server_close()
        if edge_thread:
            edge_thread.join(10)
        if service:
            if service_thread and service_thread.ident is not None:
                service.shutdown()
            service.server_close()
        if service_thread:
            service_thread.join(10)
            if service_thread.is_alive():
                report['passed'] = False
                report['cleanupError'] = 'provider accept thread did not stop'
        end = time.monotonic() + 10
        for handler in handler_threads:
            handler.join(max(0, end - time.monotonic()))
        if any(handler.is_alive() for handler in handler_threads):
            report['passed'] = False
            report['cleanupError'] = 'provider handlers did not drain'
        if fixture:
            try:
                if fixture.poll() is None and ready:
                    control('stop')
                fixture.wait(timeout=10)
                check('platform-fixture-clean-exit', fixture.returncode == 0 and group_gone(fixture.pid))
            except Exception:
                try:
                    os.killpg(fixture.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                fixture.wait(timeout=5)
                report['passed'] = False
                report['cleanupError'] = 'platform fixture did not stop cleanly'
        if fixture_log:
            fixture_log.close()
            log_path = out / 'platform-fixture.log'
            report['platformFixtureLog'] = {'sha256': digest(log_path), 'bytes': log_path.stat().st_size}
            credential_path = out / 'platform-state/refresh'
            if log_path.stat().st_size > 4 << 20 or (credential_path.exists() and credential_path.read_bytes() in log_path.read_bytes()):
                report['passed'] = False
                report['cleanupError'] = 'platform fixture log exceeded bound or exposed credential'
        report['fixtureCleanup'] = {'providerAcceptThreadStopped': not service_thread or not service_thread.is_alive(),
                                   'observedProviderHandlers': len(handler_threads),
                                   'providerHandlersDrained': not any(handler.is_alive() for handler in handler_threads),
                                   'platformExitCode': fixture.returncode if fixture else None}
        report['checkCount'] = len(report['checks'])
        save(out / 'report.json', report)
        print(json.dumps({'passed': report['passed'], 'checks': report['checkCount'], 'report': str(out / 'report.json'), 'sha256': digest(out / 'report.json')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
