#!/usr/bin/env python3
# jade:ring local
"""Exercise the compiled Aflock settings and enrollment boundary with private fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GUARD = '(version 1)(allow default)(deny network*)(allow network-inbound (local ip "localhost:*"))(allow network-outbound (remote ip "localhost:*"))'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        raise RuntimeError('This harness verifies macOS; other OS runtimes require their own guarded run.')
    binary = args.binary.resolve(strict=True)
    manifest_file = Path(str(binary) + '.manifest.json')
    manifest = json.loads(manifest_file.read_bytes())
    report = {'schema': 'testifysec.aflock.commands-uat/v1', 'passed': False, 'binarySha256': sha(binary),
              'manifestSha256': sha(manifest_file), 'harnessSha256': sha(__file__), 'checks': [],
              'scope': 'compiled CLI settings/native local enrollment and missing-evidence refusals',
              'liveCredentialsUsed': False, 'livePlatformCalls': False, 'runtimeQualified': False}

    def check(name, passed):
        report['checks'].append({'name': name, 'passed': bool(passed)})
        if not passed:
            raise RuntimeError(name)

    try:
        check('binary-and-embedded-roles-match-manifest', report['binarySha256'] == manifest['binarySha256']
              and sorted(a['role'] for a in manifest['nativeAssets']) == ['attest', 'enroll'])
        check('selected-build-sources-match', all(sha(ROOT / name) == digest for name, digest in manifest['sourceFiles'].items()))
        with tempfile.TemporaryDirectory(prefix='aflock-cli-uat-') as private_name:
            private = Path(private_name).resolve()
            home = private / 'home'; home.mkdir(mode=0o700)
            workspace = private / 'workspace'; workspace.mkdir(mode=0o700)
            state = private / 'state'
            base = {'PATH': '/nonexistent', 'HOME': str(home), 'TMPDIR': str(private), 'LANG': 'en_US.UTF-8',
                    'XDG_CONFIG_HOME': str(private / 'config'), 'XDG_DATA_HOME': str(private / 'data'),
                    'XDG_CACHE_HOME': str(private / 'cache'), 'XDG_STATE_HOME': str(private / 'xdg-state'),
                    'OPENCODE_DISABLE_PROJECT_CONFIG': '1', 'OPENCODE_DISABLE_EXTERNAL_SKILLS': '1',
                    'OPENCODE_DISABLE_CLAUDE_CODE_SKILLS': '1'}

            def invoke(arguments, extra=None):
                return subprocess.run(['/usr/bin/sandbox-exec', '-p', GUARD, str(binary), *arguments],
                                      env={**base, **(extra or {})}, cwd=workspace, capture_output=True, timeout=40)

            def events(result):
                return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

            def settings(name, value):
                file = private / name
                file.write_text(json.dumps({'schema': 'testifysec.aflock.settings/v1', **value}) + '\n')
                file.chmod(0o600)
                return str(file)

            result = invoke(['enroll', '--help'])
            help_text = result.stdout + result.stderr
            check('branded-help-exposes-settings-and-native-commands', result.returncode == 0 and b'aflock enroll' in help_text
                  and b'--settings' in help_text and b'AFLOCK_TRUST_MODE' in help_text)
            configured = settings('operator.json', {'trustMode': 'local-self-signed', 'stateDirectory': str(state)})
            result = invoke(['enroll', '--settings', configured, '--json'])
            output = events(result)
            check('settings-drive-actual-native-local-enrollment', result.returncode == 0 and len(output) == 1
                  and output[0]['event'] == 'enrolled' and output[0]['trustMode'] == 'local-self-signed'
                  and output[0]['assurance'] == 'local-self-signed-untrusted')
            identity = output[0]['identityReference']
            fingerprint = output[0]['publicKeySha256']
            check('local-identity-is-public-key-bound', identity == 'urn:testifysec:local-self-signed:sha256:' + fingerprint
                  and len(fingerprint) == 64 and not (state / 'platform').exists())
            result = invoke(['enroll', '--state-dir', str(state), '--json'], {'AFLOCK_TRUST_MODE': 'local-self-signed'})
            check('environment-mode-reuses-same-persistent-native-identity', result.returncode == 0 and events(result)[0]['identityReference'] == identity)
            result = invoke(['attest', '--settings', configured, '--json'])
            check('attest-uses-same-settings-and-refuses-chat-as-evidence', result.returncode != 0
                  and events(result)[0]['trustMode'] == 'local-self-signed' and events(result)[0]['code'] == 'no-finalized-worker-session')
            result = invoke(['attest', '--state-dir', str(state), '--json'])
            check('platform-is-default-with-no-local-downgrade', result.returncode != 0 and events(result)[0]['trustMode'] == 'platform'
                  and events(result)[0]['code'] == 'no-finalized-worker-session')
            result = invoke(['attest', '--settings', configured, '--trust-mode', 'platform', '--json'], {'AFLOCK_TRUST_MODE': 'local-self-signed'})
            check('explicit-flag-overrides-env-and-settings', result.returncode != 0 and events(result)[0]['trustMode'] == 'platform')
            result = invoke(['enroll', '--settings', configured, '--json'], {'AFLOCK_TRUST_MODE': 'INSECURE_SELFSIGNED'})
            check('invalid-env-refused-before-native-success', result.returncode != 0 and b'"event":"enrolled"' not in result.stdout)
            result = invoke(['enroll', '--settings', configured, '--platform', 'https://platform.testifysec.com', '--json'])
            check('explicit-platform-cannot-enter-local-mode', result.returncode != 0 and not (state / 'platform').exists())
            injected = settings('injected.json', {'trustMode': 'local-self-signed', 'spiffeID': 'spiffe://claimed/agent'})
            result = invoke(['enroll', '--settings', injected, '--json'])
            check('operator-file-cannot-declare-signer-identity', result.returncode != 0)
            result = invoke(['attest', '--state-dir', str(state), '--json'], {
                'OPENCODE_CONFIG_CONTENT': '{"trustMode":"local-self-signed","platformURL":"https://attacker.example.test"}',
                'CILOCK_STATE_DIR': str(private / 'unrelated-credential-store')})
            check('project-config-and-ambient-cilock-state-do-not-select-authority', result.returncode != 0
                  and events(result)[0]['trustMode'] == 'platform' and events(result)[0]['code'] == 'no-finalized-worker-session')
            default_file = home / 'Library/Application Support/TestifySec/Aflock/settings.json'
            default_file.parent.mkdir(parents=True, mode=0o700)
            default_file.write_text(Path(configured).read_text()); default_file.chmod(0o600)
            result = invoke(['enroll', '--json'])
            check('default-user-settings-thread-through-with-no-flags', result.returncode == 0 and events(result)[0]['identityReference'] == identity)
            check('native-local-secret-never-printed', b'PRIVATE KEY' not in result.stdout + result.stderr
                  and 'privateKey' not in events(result)[0] and 'credential' not in events(result)[0])
        check('binary-unchanged-after-uat', sha(binary) == report['binarySha256'])
        report['passed'] = True
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']), 'report': str(args.report)}))


if __name__ == '__main__':
    main()
