# jade:ring local
"""Actual native profile-version checks before local gateway provider traffic."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def sources(root):
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob('*'))
            if p.is_file() and p.suffix in ('.go', '.py', '.mod', '.sum', '.md')
            and '__pycache__' not in p.parts}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def group_gone(pid, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass  # Transient EPERM is not proof of group absence.
        time.sleep(.01)
    return False


def run(argv, cwd, env, timeout=300, data=None):
    if data is None:
        return run_with_input(argv, cwd, env, timeout, subprocess.DEVNULL)
    if len(data) > 512 * 1024:
        raise ValueError('owned command stdin exceeds bound')
    # A child need not consume stdin. A regular private file avoids a blocking
    # pipe write outside the child deadline, and is removed on every exit path.
    with tempfile.TemporaryFile(dir=env['TMPDIR']) as input_file:
        input_file.write(data)
        input_file.seek(0)
        return run_with_input(argv, cwd, env, timeout, input_file)


def run_with_input(argv, cwd, env, timeout, input_file):
    """Bound child exit AND pipe EOF; kill the owned group even after leader exit."""
    process = subprocess.Popen([str(v) for v in argv], cwd=cwd, env=env,
                               stdin=input_file,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    complete = False
    try:
        for name in output:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        end = time.monotonic() + timeout
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= end:
                raise TimeoutError('owned command exceeded deadline or did not drain')
            for key, _ in selector.select(.05):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if len(output[key.data]) > 4 * 1024 * 1024:
                    raise ValueError('owned command output exceeded bound')
        if not group_gone(process.pid):
            raise RuntimeError('owned command left a process group after exit and EOF')
        complete = True
        return {'exitCode': process.wait(), **{k: bytes(v) for k, v in output.items()}}
    finally:
        try:
            if not complete:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
                if not group_gone(process.pid):
                    raise RuntimeError('owned command cleanup could not confirm group absence')
        finally:
            selector.close()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream and not stream.closed:
                    stream.close()


def go_inputs(go, directory, env):
    result = run([go, 'list', '-deps', '-json', '.'], directory, env)
    if result['exitCode']:
        raise RuntimeError('cannot inventory gateway Go inputs')
    raw = result['stdout'].decode()
    decoder = json.JSONDecoder()
    files = set()
    while raw.strip():
        package, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        if package.get('Standard'):
            continue
        base = Path(package['Dir'])
        for field in ('GoFiles', 'CgoFiles', 'CFiles', 'CXXFiles', 'MFiles', 'HFiles', 'FFiles', 'SFiles', 'SysoFiles', 'EmbedFiles'):
            files.update(base / name for name in package.get(field, []))
        module = package.get('Module', {})
        module = module.get('Replace', module)
        if module.get('GoMod'):
            mod = Path(module['GoMod'])
            files.add(mod)
            if mod.with_suffix('.sum').exists():
                files.add(mod.with_suffix('.sum'))
    return {str(p): digest(p) for p in sorted(files)}


class UnixHTTP(HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=15)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--bun', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.absolute()
    out.mkdir(mode=0o700)
    for name in ('home', 'tmp', 'stage'):
        (out / name).mkdir(mode=0o700)
    env = {'PATH': ':'.join([str(args.go.parent), str(args.bun.parent), str(Path(sys.executable).parent), '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
           'HOME': str(out / 'home'), 'TMPDIR': str(out / 'tmp'), 'LANG': 'C', 'GOWORK': 'off',
           'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOMAXPROCS': '2',
           'GOMODCACHE': os.environ.get('GOMODCACHE', str(Path.home() / 'go/pkg/mod')),
           'GOCACHE': os.environ.get('GOCACHE', str(out / 'go-cache')), 'GOFLAGS': '-mod=readonly -p=1', 'CGO_ENABLED': '1'}
    report = {'schema': 'testifysec.aflock.gateway-profile-v2-uat/v1', 'passed': False, 'checks': [],
              'startedAt': datetime.now(timezone.utc).isoformat(), 'cases': [], 'logs': {}, 'builds': {},
              'sourceFiles': sources(ROOT), 'platformSourceFiles': sources(ROOT.parent / 'platform'),
              'tools': {name: {'path': str(path.resolve()), 'sha256': digest(path)} for name, path in [('go', args.go), ('bun', args.bun), ('python', Path(sys.executable))]},
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'worktreeDirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
              'scope': 'native signed profile and protected backend-reference matching before local model requests',
              'limitations': ['Synthetic public signing roots and local provider only; no live platform identity or model calls.',
                              'Backend manifest reference matching does not read backend artifacts or authorize VM boot.',
                              'Development loopback uses administrator-provisioned identity labels, not authenticated SPIFFE or human presence.',
                              'Protected installation, service UID custody and OS time are assumptions; no FIPS, IL6, ALPS or release qualification.',
                              'Reports and source/path hashes are unsigned local observations, not running-image measurements.']}
    service = None
    service_thread = None
    active = None
    state = {'provider': [], 'spool': None, 'config': None, 'errors': []}
    lock = threading.Lock()

    def check(name, passed, **details):
        report['checks'].append({'id': name, 'passed': bool(passed), **details})
        if not passed:
            raise AssertionError(name)

    def command(name, argv, cwd=ROOT, data=None, expected=0, timeout=300):
        result = run(argv, cwd, env, timeout, data)
        for stream in ('stdout', 'stderr'):
            (out / (name + '.' + stream + '.log')).write_bytes(result[stream])
        report['logs'][name] = {'exitCode': result['exitCode'], 'stdoutSha256': sha(result['stdout']), 'stderrSha256': sha(result['stderr'])}
        check(name + '-exit', result['exitCode'] == expected)
        return result

    def bundle(name, trust):
        path = out / name
        command('build-' + name, [sys.executable, ROOT.parent / 'managed/build.py', '--go', args.go, '--bun', args.bun, '--trust', trust, '--output', path])
        path.chmod(0o700)
        manifest = json.loads((path / 'manifest.json').read_bytes())
        report['builds'][name] = {'manifestSha256': digest(path / 'manifest.json'), 'manifest': manifest}
        return path, manifest

    def stop_gateway():
        nonlocal active
        if active is None:
            return
        process, log, name = active
        forced = False
        try:
            if process.poll() is None:
                process.terminate()
            try:
                code = process.wait(timeout=40)
            except subprocess.TimeoutExpired:
                forced = True
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait(timeout=10)
            gone = group_gone(process.pid)
            if not gone:
                forced = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                gone = group_gone(process.pid)
            check(name + '-shutdown', code == 0 and not forced and gone)
        finally:
            log.close()
            report['logs'][name + '-gateway'] = {'sha256': digest(out / name / 'gateway.log'), 'exitCode': process.poll()}
            active = None

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            self.connection.settimeout(10)
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 1024 * 1024:
                    self.send_error(413)
                    return
                raw = self.rfile.read(size)
                if self.path == '/v1/logs':
                    self.send_response(503)
                    self.end_headers()
                    return
                if self.path not in ('/v1/chat/completions', '/v1/responses'):
                    self.send_error(404)
                    return
                with lock:
                    current = [json.loads(p.read_bytes()) for p in state['spool'].glob('*.json')]
                    starts = [v for v in current if v['outcome'] == 'started']
                    state['provider'].append({'path': self.path, 'requestSha256': sha(raw), 'startRecords': starts,
                                              'authorized': self.headers.get('Authorization') == 'Bearer synthetic-v2-provider',
                                              'forgedHeaderForwarded': self.headers.get('X-Aflock-Backend') is not None})
                payload = b'{"id":"resp_fixture","object":"response","model":"approved","status":"completed","output":[]}' if self.path.endswith('responses') else b'{"choices":[]}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as error:
                with lock:
                    state['errors'].append(type(error).__name__)
                self.close_connection = True

    try:
        for name, inventory in [('gateway', report['sourceFiles']), ('platform', report['platformSourceFiles'])]:
            for relative, expected in inventory.items():
                source = ROOT.parent / name / relative
                target = out / 'stage' / name / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                if digest(target) != expected:
                    raise ValueError('source changed during staging')
        stage = out / 'stage/gateway'
        inputs = go_inputs(args.go, stage, env)
        report['gatewayGoInputs'] = inputs
        command('gateway-build', [args.go, 'build', '-trimpath', '-buildvcs=false', '-o', out / 'gateway', '.'], cwd=stage)
        report['gatewaySha256'] = digest(out / 'gateway')
        check('gateway-build-inputs-unchanged', go_inputs(args.go, stage, env) == inputs)
        managed = ROOT.parent / 'managed'
        command('fixtures-v2', [args.go, 'run', managed / 'fixtures-v2.go', out / 'fixtures'], cwd=ROOT.parent / 'native')
        fixtures = out / 'fixtures'
        bundles = {version: bundle('bundle-v' + str(version), fixtures / ('trust-v' + str(version) + '.json')) for version in (1, 2)}
        valid = {version: (fixtures / ('valid-v' + str(version) + '.json')).read_bytes() for version in (1, 2)}
        payloads = {version: base64.b64decode(json.loads(raw)['payload'], validate=True) for version, raw in valid.items()}
        profiles = {version: json.loads(raw) for version, raw in payloads.items()}
        negative = {'expired': 'profile-time-invalid', 'future': 'profile-time-invalid', 'wrong-key': 'profile-signature-invalid',
                    'wrong-tenant': 'assignment-mismatch', 'rollback': 'profile-rollback', 'wrong-pin': 'backend-assignment-mismatch',
                    'tampered': 'profile-signature-invalid', 'weakened-controls': 'unsupported-controls', 'duplicate-backend': 'duplicate-json-key'}
        for version in (1, 2):
            result = command('native-valid-v' + str(version), [bundles[version][0] / 'hardened-admission'], data=valid[version])
            value = json.loads(result['stdout'])
            check('native-positive-v' + str(version), value['admitted'] is True and value['schemaVersion'] == version and value['payloadSha256'] == sha(payloads[version]))
        for name, reason in negative.items():
            result = command('native-' + name, [bundles[2][0] / 'hardened-admission'], data=(fixtures / (name + '.json')).read_bytes(), expected=1)
            value = json.loads(result['stdout'])
            check('native-intended-' + name, value['admitted'] is False and value['schemaVersion'] == 2 and value['reason'] == reason)
        service = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        service.daemon_threads = False
        service_thread = threading.Thread(target=service.serve_forever)
        service_thread.start()

        def start(name, protocol, config_version=2, verifier_version=2, envelope_version=2, alter=None, rejected=False):
            nonlocal active
            work = out / name
            work.mkdir(mode=0o700)
            (work / 'spool').mkdir(mode=0o700)
            (work / 'provider.token').write_text('synthetic-v2-provider')
            (work / 'provider.token').chmod(0o600)
            (work / 'profile.json').write_bytes(valid[envelope_version])
            (work / 'profile.json').chmod(0o600)
            path = '/v1/responses' if protocol == 'responses' else '/v1/chat/completions'
            configuration = {'schema': 'testifysec.hardened-opencode.gateway/v' + str(config_version),
                             'socket': str(work / 'gateway.sock'), 'spool': str(work / 'spool'), 'protocol': protocol,
                             'providerURL': f'http://127.0.0.1:{service.server_port}' + path, 'providerTokenFile': str(work / 'provider.token'),
                             'collectorURL': f'http://127.0.0.1:{service.server_port}/v1/logs', 'collectorTokenFile': '',
                             'model': 'approved', 'tenant': profiles[envelope_version]['tenantId'], 'session': name,
                             'agent': 'spiffe://fixture.test/tenant/uat-tenant/agent/gateway-v2', 'profileDigest': sha(payloads[envelope_version]),
                             'maxRecords': 100, 'maxOfflineSeconds': 600, 'timeoutSeconds': 10, 'developmentLoopback': True,
                             'signedProfileFile': str(work / 'profile.json'), 'admissionExecutable': str(bundles[verifier_version][0] / 'hardened-admission'),
                             'admissionSha256': bundles[verifier_version][1]['files']['hardened-admission']}
            if config_version == 2:
                configuration['backend'] = dict(profiles[2]['backend'])
            if alter:
                alter(configuration)
            save(work / 'config.json', configuration)
            before = len(state['provider'])
            if rejected:
                result = command(name + '-refused', [out / 'gateway', '--config', work / 'config.json'], timeout=15, expected=1)
                check(name + '-no-listener-or-provider', not (work / 'gateway.sock').exists() and len(state['provider']) == before
                      and b'invalid protected configuration' in result['stderr'])
                return None
            with lock:
                state['spool'], state['config'] = work / 'spool', configuration
            log = (work / 'gateway.log').open('wb')
            process = subprocess.Popen([str(out / 'gateway'), '--config', str(work / 'config.json')], stdout=log, stderr=log,
                                       start_new_session=True, env={'PATH': '/nonexistent', 'BUN_OPTIONS': '--preload /nonexistent/poison.js',
                                                                   'NODE_OPTIONS': '--require /nonexistent/poison.js', 'MANAGED_PROFILE_VERSION': '1'})
            active = (process, log, name)
            end = time.monotonic() + 10
            while process.poll() is None and not (work / 'gateway.sock').exists() and time.monotonic() < end:
                time.sleep(.02)
            check(name + '-ready', process.poll() is None and (work / 'gateway.sock').exists())
            return work, configuration

        def call(name, work, config, status=200, outcome='completed', extra=None, headers=None):
            if status == 200 and config['protocol'] == 'responses':
                outcome = 'provider-response-completed'
            body = {'model': 'approved', 'store': False, 'input': 'synthetic input'} if config['protocol'] == 'responses' else {'model': 'approved', 'messages': [{'role': 'user', 'content': 'synthetic input'}]}
            body.update(extra or {})
            raw = json.dumps(body).encode()
            before = len(state['provider'])
            existing = {p.name for p in (work / 'spool').glob('*.json')}
            connection = UnixHTTP(work / 'gateway.sock')
            try:
                connection.request('POST', '/v1/responses' if config['protocol'] == 'responses' else '/v1/chat/completions', raw,
                                   {'Content-Type': 'application/json', **(headers or {})})
                response = connection.getresponse()
                actual = response.status
                response_body = response.read(1 << 20)
                request_id = response.getheader('X-Hardened-Request-ID')
            finally:
                connection.close()
            check(name + '-decision', actual == status and len(state['provider']) == before + (1 if status == 200 else 0))
            record = None
            end = time.monotonic() + 5
            while time.monotonic() < end:
                new = [p for p in (work / 'spool').glob('*.json') if p.name not in existing]
                if len(new) == 1:
                    value = json.loads(new[0].read_bytes())
                    if value['outcome'] != 'started':
                        record = value
                        break
                time.sleep(.01)
            check(name + '-terminal-audit', record is not None and record['status'] == status and record['outcome'] == outcome
                  and record['requestBytes'] == len(raw) and datetime.fromisoformat(record['finished'].replace('Z', '+00:00')) >= datetime.fromisoformat(record['started'].replace('Z', '+00:00')))
            check(name + '-audit-assignment', all(record[key] == config[key] for key in ('tenant', 'session', 'agent', 'profileDigest', 'model'))
                  and record['identitySource'] == 'administrator-provisioned' and record['repositoryId'] == ''
                  and record['delegatingUserId'] == '' and record['enrollmentAal'] == '')
            if status == 200:
                observed = state['provider'][-1]
                check(name + '-durable-start-before-provider', len(observed['startRecords']) == 1 and observed['startRecords'][0]['id'] == record['id'] == request_id
                      and observed['requestSha256'] == sha(raw) and observed['authorized'] and not observed['forgedHeaderForwarded'])
            report['cases'].append({'name': name, 'status': actual, 'providerDelta': len(state['provider']) - before,
                                    'requestSha256': sha(raw), 'responseSha256': sha(response_body), 'audit': record})

        for protocol in ('chat-completions', 'responses'):
            prefix = 'chat' if protocol == 'chat-completions' else 'responses'
            work, config = start(prefix + '-v2', protocol)
            call(prefix + '-v2-positive', work, config)
            for name in negative:
                (work / 'profile.json').write_bytes((fixtures / (name + '.json')).read_bytes())
                call(prefix + '-' + name, work, config, 403, 'profile-refused')
            (work / 'profile.json').write_bytes(valid[2])
            call(prefix + '-restored', work, config)
            call(prefix + '-header-has-no-authority', work, config, headers={'X-Aflock-Backend': 'forged', 'Authorization': 'Bearer forged'})
            call(prefix + '-body-cannot-choose-backend', work, config, 400, 'request-denied', extra={'backend': {'kind': 'forged'}})
            stop_gateway()
            work, config = start(prefix + '-wrong-config-pin', protocol, alter=lambda c: c['backend'].update(manifestSha256='0' * 64))
            call(prefix + '-signed-profile-vs-wrong-config-pin', work, config, 403, 'profile-refused')
            stop_gateway()
            for config_version, verifier_version, envelope_version in [(1, 1, 1), (2, 1, 1), (1, 2, 2), (2, 2, 1), (1, 1, 2), (1, 2, 1), (2, 1, 2)]:
                name = f'{prefix}-c{config_version}-v{verifier_version}-e{envelope_version}'
                work, config = start(name, protocol, config_version, verifier_version, envelope_version)
                accepted = config_version == verifier_version == envelope_version == 1
                call(name, work, config, 200 if accepted else 403, 'completed' if accepted else 'profile-refused')
                stop_gateway()
        for name, version, alter in [('v2-missing-backend', 2, lambda c: c.pop('backend')),
                                     ('v2-null-backend', 2, lambda c: c.update(backend=None)),
                                     ('v2-wrong-kind', 2, lambda c: c['backend'].update(kind='linux-docker/v1')),
                                     ('v2-no-profile', 2, lambda c: c.pop('signedProfileFile')),
                                     ('v1-with-backend', 1, lambda c: c.update(backend=dict(profiles[2]['backend'])))]:
            start(name, 'responses', version, alter=alter, rejected=True)
        check('provider-fixture-no-errors', not state['errors'])
        report['providerRequests'] = len(state['provider'])
        report['providerObservations'] = state['provider']
        command('legacy-fixtures', [args.go, 'run', managed / 'fixtures.go', out / 'legacy-fixtures'], cwd=ROOT.parent / 'native')
        legacy, _ = bundle('legacy-bundle', out / 'legacy-fixtures/trust.json')
        for protocol in ('chat-completions', 'responses'):
            name = 'legacy-' + protocol
            # The unchanged script records real Git state. Invoke its exact
            # source in the worktree, not a fake Git revision for the snapshot.
            command(name, [sys.executable, ROOT / 'uat-profile.py', '--go', args.go, '--protocol', protocol,
                           '--admission-directory', legacy, '--fixtures', out / 'legacy-fixtures', '--report', out / (name + '.json')], cwd=ROOT)
            value = json.loads((out / (name + '.json')).read_bytes())
            check(name + '-unchanged-regression', value['passed'] is True and len(value['checks']) == 12 and all(x['passed'] for x in value['checks']))
            check(name + '-source-binding', all(report['sourceFiles'][path] == expected for path, expected in value['sourceFiles'].items()))
            report.setdefault('legacyReports', {})[protocol] = {'path': str(out / (name + '.json')), 'sha256': digest(out / (name + '.json')), 'checks': len(value['checks'])}
        for name, value in report['builds'].items():
            manifest = value['manifest']
            check(name + '-final-inputs', all(digest(ROOT.parent / 'managed' / path) == expected for path, expected in manifest['sourceFiles'].items())
                  and all(digest(ROOT.parent / 'native' / path) == expected for path, expected in manifest['nativeBuild']['sourceFiles'].items())
                  and all(digest(path) == expected for path, expected in manifest['nativeGoInputs']['files'].items())
                  and all(digest(tool['path']) == tool['sha256'] for tool in manifest['buildTools'].values()))
            check(name + '-final-artifacts', digest(out / name / 'manifest.json') == value['manifestSha256']
                  and all(digest(out / name / path) == expected for path, expected in manifest['files'].items()))
        check('all-selected-sources-unchanged', sources(ROOT) == report['sourceFiles'] and sources(ROOT.parent / 'platform') == report['platformSourceFiles'])
        check('gateway-binary-and-go-inputs-unchanged', digest(out / 'gateway') == report['gatewaySha256'] and go_inputs(args.go, stage, env) == inputs)
        check('all-selected-tools-unchanged', all(digest(value['path']) == value['sha256'] for value in report['tools'].values()))
        report['fixtures'] = {str(path.relative_to(out)): digest(path) for directory in ('fixtures', 'legacy-fixtures') for path in sorted((out / directory).glob('*.json'))}
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            stop_gateway()
        except Exception as error:
            report['cleanupError'] = str(error)
            report['passed'] = False
        if service:
            service.shutdown()
            service.server_close()
        if service_thread:
            service_thread.join(timeout=15)
            if service_thread.is_alive():
                report['cleanupError'] = 'local provider did not drain'
                report['passed'] = False
        report['finishedAt'] = datetime.now(timezone.utc).isoformat()
        report['checkCount'] = len(report['checks'])
        save(out / 'report.json', report)
        print(json.dumps({'passed': report['passed'], 'checks': report['checkCount'], 'report': str(out / 'report.json'), 'sha256': digest(out / 'report.json'), 'error': report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
