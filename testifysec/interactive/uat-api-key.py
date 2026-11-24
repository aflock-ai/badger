#!/usr/bin/env python3
# jade:ring local
"""A managed build never takes a user's API key: login is refused, and a key or provider set in the
environment or config is neither used nor stored. Synthetic secrets and a loopback fixture only.

macOS local harness under a network guard.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

from managed_harness import (GUARD, PRODUCT, REFUSED, FixtureModel, Report, contains_fixture_model, network_guard_holds,
                             no_package_or_credential_files, private_env, require_macos, run, sha, terminal)


class Fixture(http.server.BaseHTTPRequestHandler):
    """Records every request; it never answers successfully, so nothing could depend on it."""
    requests = []

    def handle_one(self):
        Fixture.requests.append({'method': self.command, 'path': self.path})
        self.send_response(500); self.end_headers()

    do_GET = do_POST = handle_one

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path, help='darwin binary from build.ts --managed')
    parser.add_argument('--fixture-binary', required=True, type=Path,
                        help='the same build with --fixture-model, used only for the model round trip')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    fixture_binary = args.fixture_binary.resolve(strict=True)
    report = Report('testifysec.badger.interactive-api-key-uat/v2', binary, __file__, liveCredentialsUsed=False,
                    fixtureBinarySha256=sha(fixture_binary))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    secret = 'sk-badger-uat-config-' + os.urandom(12).hex()
    env_secret = 'sk-badger-uat-env-' + os.urandom(12).hex()
    error = None
    try:
        require_macos()
        with tempfile.TemporaryDirectory(prefix='badger-api-key-uat-') as tmp:
            tmp = Path(tmp)
            workspace = tmp / 'workspace'; workspace.mkdir()
            base = f'http://127.0.0.1:{server.server_port}/v1'
            env = private_env(tmp, OPENAI_API_KEY=env_secret, OPENCODE_CONFIG_CONTENT=json.dumps({
                'model': 'openai/gpt-4.1', 'enabled_providers': ['openai'], 'autoupdate': False,
                'provider': {'openai': {'options': {'apiKey': secret, 'baseURL': base}}}}))
            report.check('test-guard-denies-external-network', network_guard_holds(env))

            outputs = []
            for argv in (['auth', 'login'], ['auth', 'list']):
                result = run(binary, argv, workspace, env)
                outputs.append(result.stdout + result.stderr)
                report.check('refuses-' + '-'.join(argv), result.returncode == 1 and result.stdout == b'' and result.stderr == REFUSED)

            result = run(binary, ['models'], workspace, env)
            outputs.append(result.stdout + result.stderr)
            report.check('configured-provider-not-listed', result.returncode == 0 and result.stdout == b'managed/approved\n',
                         output=result.stdout.decode(errors='replace'))

            # The TUI needs its gateway to start, so it runs the UAT build against the fixture model.
            model = FixtureModel()
            try:
                code, plain, raw, ready, quit_sent = terminal(
                    [str(fixture_binary)], workspace, env, lambda text: b'Ask anything' in text and PRODUCT['providerName'].encode() in text,
                    args.report.with_suffix('.pty'))
            finally:
                model.close()
            outputs.append(raw)
            report.check('tui-renders-and-exits', ready and quit_sent and code == 0)
            report.check('tui-offers-only-the-managed-model', PRODUCT['modelName'] in plain and 'gpt-4.1' not in plain)

            # A prompt naming the configured model gets a fixed window; the provider must not hear from it.
            process = subprocess.Popen(GUARD + [str(binary), 'run', '--model', 'openai/gpt-4.1', 'hello'], cwd=workspace,
                                       env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
            outputs.append(stdout + stderr)
            time.sleep(0.5)
            report.check('configured-provider-never-contacted', Fixture.requests == [], requests=Fixture.requests)

            # With a model to reach, a session goes to the gateway's one model, carrying neither key; the configured
            # provider still hears nothing. The UAT build reaches the fixture model; the release binary cannot.
            report.check('only-the-uat-build-carries-the-fixture-model',
                         contains_fixture_model(fixture_binary) and not contains_fixture_model(binary))
            model = FixtureModel()
            try:
                result = run(fixture_binary, ['run', 'hello'], workspace, env, timeout=60)
                outputs.append(result.stdout + result.stderr)
                report.check('session-round-trip-through-the-managed-gateway', result.returncode == 0
                             and result.stdout == b'Managed verification\n' and len(model.requests) >= 1
                             and all(r['model'] == 'approved' and r['path'] == '/v1/chat/completions' for r in model.requests),
                             requests=[{k: v for k, v in r.items() if k != 'headers'} for r in model.requests])
                sent = json.dumps(model.requests)
                report.check('gateway-requests-carry-no-user-key', secret not in sent and env_secret not in sent)
                report.check('configured-provider-still-never-contacted', Fixture.requests == [], requests=Fixture.requests)
            finally:
                model.close()

            report.check('no-package-or-credential-files', no_package_or_credential_files(tmp))
            leaks = [str(p.relative_to(tmp)) for p in tmp.rglob('*') if p.is_file()
                     and (secret.encode() in p.read_bytes() or env_secret.encode() in p.read_bytes())]
            report.check('secrets-absent-from-state', leaks == [], files=leaks)
            report.check('secrets-absent-from-output', not any(secret.encode() in o or env_secret.encode() in o for o in outputs))
        report.check('binaries-and-harness-unchanged', sha(binary) == report.data['binarySha256']
                     and sha(fixture_binary) == report.data['fixtureBinarySha256'] and sha(__file__) == report.data['harnessSha256'])
    except Exception as caught:
        error = caught
    finally:
        server.shutdown()
    return report.finish(args.report, error)


if __name__ == '__main__':
    raise SystemExit(main())
