# jade:ring local
"""Real native Rookery admission before each compiled gateway provider request."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time

from uat import UnixHTTP


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--protocol', choices=['chat-completions', 'responses'], default='chat-completions')
    parser.add_argument('--admission-directory', required=True, type=Path)
    parser.add_argument('--fixtures', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    request_path = '/v1/responses' if args.protocol == 'responses' else '/v1/chat/completions'
    root = Path(__file__).resolve().parent
    sources = lambda: {p.name: sha(p.read_bytes()) for p in root.iterdir() if p.suffix in ('.go', '.py', '.mod', '.sum')}
    report = {'schema': 'testifysec.hardened-opencode.gateway-profile-uat/v1', 'passed': False,
              'checks': [], 'sourceFiles': sources(), 'releaseQualified': False, 'protocol': args.protocol,
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
              'worktreeDirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)),
              'limitations': ['Synthetic local signed profiles and provider; no production credentials or model calls.',
                              'Protected admission installation and service UID custody are assumed; no hardware, FIPS, ALPS or IL6 qualification.',
                              'Profile expiry stops new provider requests; an already admitted response stream is not retroactively cancelled.',
                              'Live platform identity is tested in the separate platform/gateway fixture.']}
    state = {'provider': 0}

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', 0)))
            if self.path == '/v1/logs':
                self.send_response(503)
                self.end_headers()
                return
            state['provider'] += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"id":"resp_fixture","object":"response","model":"approved","status":"completed","output":[]}' if args.protocol == 'responses' else b'{"choices":[]}')

    service = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    threading.Thread(target=service.serve_forever, daemon=True).start()
    process = None

    def check(name, condition):
        report['checks'].append({'id': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    try:
        with tempfile.TemporaryDirectory(prefix='hc-gateway-profile-', dir='/private/tmp' if Path('/private/tmp').exists() else None) as temporary:
            work = Path(temporary).resolve()
            binary = work / 'hardened-gateway'
            subprocess.run([args.go, 'build', '-trimpath', '-o', str(binary), '.'], cwd=root,
                           env=dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off'), check=True)
            report['gatewaySha256'] = sha(binary.read_bytes())
            original = json.loads((args.admission_directory / 'manifest.json').read_text())
            admission = work / 'admission'
            admission.mkdir(mode=0o700)
            for name, digest in original['files'].items():
                entry = args.admission_directory / name
                if Path(name).name != name or not entry.is_file() or entry.is_symlink() or sha(entry.read_bytes()) != digest:
                    raise ValueError('admission builder inventory changed')
                shutil.copy2(entry, admission / name)
            report['admissionFiles'] = original['files']
            valid = (args.fixtures / 'valid.json').read_bytes()
            payload = base64.b64decode(json.loads(valid)['payload'])
            assigned = json.loads(payload)
            profile = work / 'profile.json'
            profile.write_bytes(valid)
            profile.chmod(0o600)
            (work / 'provider.token').write_text('synthetic-provider-credential')
            (work / 'provider.token').chmod(0o600)
            (work / 'spool').mkdir(mode=0o700)
            config = {'schema': 'testifysec.hardened-opencode.gateway/v1', 'socket': str(work / 'gateway.sock'),
                      'spool': str(work / 'spool'), 'providerURL': f'http://127.0.0.1:{service.server_port}{request_path}',
                      'providerTokenFile': str(work / 'provider.token'), 'collectorURL': f'http://127.0.0.1:{service.server_port}/v1/logs',
                      'collectorTokenFile': '', 'model': 'approved', 'tenant': assigned['tenantId'], 'session': 'profile-uat',
                      'agent': f"spiffe://fixture.test/tenant/{assigned['tenantId']}/agent/profile-uat", 'profileDigest': sha(payload),
                      'maxRecords': 32, 'maxOfflineSeconds': 120, 'timeoutSeconds': 10, 'developmentLoopback': True,
                      'signedProfileFile': str(profile), 'admissionExecutable': str(admission / 'hardened-admission'),
                      'admissionSha256': original['files']['hardened-admission']}
            config['protocol'] = args.protocol
            config_path = work / 'config.json'
            config_path.write_text(json.dumps(config))
            config_path.chmod(0o600)
            with (work / 'gateway.log').open('wb') as log:
                process = subprocess.Popen([str(binary), '--config', str(config_path)], stdout=log, stderr=log,
                                           env={'PATH': '/nonexistent', 'BUN_OPTIONS': '--preload /nonexistent/hostile.js'})
                deadline = time.monotonic() + 8
                while not Path(config['socket']).exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.025)
                check('native-gateway-startup', process.poll() is None and Path(config['socket']).exists())

                def call():
                    connection = UnixHTTP(config['socket'])
                    connection.request('POST', request_path, json.dumps({'model': 'approved', 'store': False, 'input': 'synthetic input'} if args.protocol == 'responses' else {'model': 'approved', 'messages': [{}]}), {'Content-Type': 'application/json'})
                    response = connection.getresponse()
                    status = response.status
                    response.read()
                    connection.close()
                    return status

                check('real-rookery-profile-admits-provider', call() == 200 and state['provider'] == 1)
                for name in ('expired', 'wrong-key'):
                    profile.write_bytes((args.fixtures / (name + '.json')).read_bytes())
                    before = state['provider']
                    check(name + '-replacement-refused-without-restart', call() == 403 and state['provider'] == before)
                tampered = json.loads(valid)
                altered = dict(assigned, sequence=assigned['sequence'] + 1)
                tampered['payload'] = base64.b64encode(json.dumps(altered).encode()).decode()
                profile.write_text(json.dumps(tampered))
                check('tampered-signature-refused', call() == 403 and state['provider'] == 1)
                profile.unlink()
                check('missing-profile-refused', call() == 403 and state['provider'] == 1)
                os.mkfifo(profile, 0o600)
                check('fifo-profile-refused-without-blocking', call() == 403 and state['provider'] == 1)
                profile.unlink()
                profile.write_bytes(valid)
                profile.chmod(0o600)
                check('valid-profile-restored-without-restart', call() == 200 and state['provider'] == 2)
                native = admission / 'hardened-admission'
                saved = native.read_bytes()
                native.write_bytes(saved + b'tampered')
                check('substituted-admission-binary-refused', call() == 403 and state['provider'] == 2)
                native.write_bytes(saved)
                library = next(admission / name for name in original['files'] if name.startswith('librookery'))
                saved_library = library.read_bytes()
                library.write_bytes(saved_library + b'tampered')
                check('substituted-rookery-library-refused', call() == 403 and state['provider'] == 2)
                library.write_bytes(saved_library)
                check('restored-native-package-admits', call() == 200 and state['provider'] == 3)
                process.terminate()
                process.wait(timeout=10)
                records = [json.loads(p.read_text()) for p in (work / 'spool').glob('*.json')]
                check('all-profile-denials-durably-audited', len(records) == 10 and sum(r['outcome'] == 'profile-refused' for r in records) == 7)
                report['providerRequests'] = state['provider']
                report['profileSha256'] = sha(payload)
            if sources() != report['sourceFiles']:
                raise ValueError('selected source files changed during UAT')
            report['passed'] = True
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        report['failure'] = str(error)
    finally:
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        service.shutdown()
        service.server_close()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']), 'report': str(args.report), 'failure': report.get('failure')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
