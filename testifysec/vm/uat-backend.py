#!/usr/bin/env python3
# jade:ring local
"""Offline backend export/native signed-admission preparation UAT; never boot VZ."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent
CACHES = {}
ROLES = {'host': 'hc-vm', 'kernel': 'kernel', 'rootDisk': 'root.ext4', 'provenance': 'build.json'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(raw)
    return value.hexdigest()


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'


def private(path, raw):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)


def source_hashes():
    selected = [SOURCE / name for name in ('package-backend.py', 'uat-backend.py', 'BACKEND.md')]
    selected += [path for name in ("go.mod", "go.sum") if (path := SOURCE.parent / "broker" / name).is_file()]
    selected += [p for base in (SOURCE.parent / 'broker/vzbackend', SOURCE.parent / 'broker/cmd/vz-backend-check',
                               SOURCE.parent / 'managed', SOURCE.parent / 'native')
                 for p in sorted(base.rglob('*')) if p.is_file() and p.suffix in ('.go', '.ts', '.py', '.md', '.mod', '.sum')]
    return {str(p.relative_to(SOURCE.parent.parent)): digest(p) for p in selected}


def run(command, cwd, out, name, data=None, timeout=180, extra_env=None):
    env = {'PATH': str(Path(sys.executable).parent) + ':/usr/bin:/bin', 'HOME': str(out), 'TMPDIR': str(out),
           'LANG': 'C', 'GOWORK': 'off', 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOFLAGS': '-mod=readonly'}
    env.update(CACHES)
    env.update(extra_env or {})
    input_path = out / (name + '.input')
    private(input_path, data or b'')
    stdout = bytearray()
    stderr = bytearray()
    selected = selectors.DefaultSelector()
    process = None
    forced = False
    observed = False
    failure = None
    started = time.monotonic()
    try:
        with input_path.open('rb') as stream:
            process = subprocess.Popen([str(x) for x in command], stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       cwd=cwd, env=env, start_new_session=True)
        for pipe, target in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(pipe.fileno(), False)
            selected.register(pipe, selectors.EVENT_READ, target)
        while selected.get_map():
            if time.monotonic() - started > timeout:
                raise TimeoutError('process/output deadline')
            for key, _ in selected.select(.05):
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    selected.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(key.data) + len(raw) > 1024 * 1024:
                    raise ValueError('process output cap')
                key.data.extend(raw)
        process.wait(timeout=max(.01, timeout - (time.monotonic() - started)))
        observed = True
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as error:
        failure = type(error).__name__
    finally:
        if process is not None and not observed:
            forced = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
                observed = True
            except subprocess.TimeoutExpired:
                failure = 'exit-unobserved'
        for key in list(selected.get_map().values()):
            key.fileobj.close()
        selected.close()
    for suffix, raw in (('stdout', stdout), ('stderr', stderr)):
        private(out / (name + '.' + suffix + '.log'), bytes(raw))
    return {'exitCode': process.returncode if process else None, 'stdout': bytes(stdout), 'stderr': bytes(stderr),
            'exitObserved': observed, 'forcedKill': forced, 'error': failure, 'elapsedSeconds': time.monotonic() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path, help='Retained real current V3 worker build directory')
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--bun', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.absolute()
    out.mkdir(mode=0o700)
    cached = subprocess.check_output([str(args.go), 'env', 'GOMODCACHE', 'GOCACHE'], text=True, timeout=15,
        env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'GOWORK': 'off', 'GOTOOLCHAIN': 'local'}).splitlines()
    if len(cached) != 2 or not all(Path(path).is_absolute() and Path(path).is_dir() for path in cached):
        raise ValueError('cached Go module/build inputs required')
    CACHES.update(dict(zip(('GOMODCACHE', 'GOCACHE'), cached)))
    checks = []
    report = {'schema': 'testifysec.aflock.vz-backend-uat/v1', 'passed': False, 'checks': checks,
              'sourceFiles': source_hashes(), 'runs': {}, 'fixtures': {}, 'nativeBundles': {},
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip(),
              'worktreeDirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=SOURCE)),
              'scope': 'build-time export and native signed-v2 backend preparation; no VM launch',
              'vmBoots': 0, 'dockerInvocations': 0, 'liveProviderCalls': False, 'releaseQualified': False,
              'limitations': ['Same-user developer-owned local fixtures; no installed service privilege boundary.',
                             'Exact disk byte binding does not independently inspect guest init/worker files.',
                             'Retained root includes an explicit UAT utility; not a production image.',
                             'Build provenance is descriptive and not runtime authority or hardware measurement.',
                             'No platform identity, revocation, launch authorization, signing receipt or FIPS/IL6 qualification.']}

    def check(name, condition, **details):
        checks.append({'name': name, 'passed': bool(condition), **details})
        if not condition:
            raise AssertionError(name)

    def command(name, argv, cwd=SOURCE, data=None, expected=0, timeout=180, extra_env=None):
        value = run(argv, cwd, out, name, data, timeout, extra_env)
        report['runs'][name] = {key: item for key, item in value.items() if key not in ('stdout', 'stderr')}
        report['runs'][name].update(stdoutSha256=sha(value['stdout']), stderrSha256=sha(value['stderr']))
        check(name + '-bounded-exit', value['exitObserved'] and not value['forcedKill'] and value['error'] is None
              and value['exitCode'] == expected)
        return value

    spec = importlib.util.spec_from_file_location('backend_export', SOURCE / 'package-backend.py')
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    try:
        original = args.build.absolute()
        build_raw = (original / 'manifest.json').read_bytes()
        build = json.loads(build_raw)
        report['retainedBuild'] = {'directory': str(original), 'manifestSha256': sha(build_raw), 'manifest': build}
        check('retained-build-selected-sources-current', all(digest(SOURCE / name) == pin for name, pin in build['sourceFiles'].items()))
        bundle = out / 'installation'
        result = command('export-real-v3', [sys.executable, '-B', SOURCE / 'package-backend.py', '--build', original, '--output', bundle])
        exported = json.loads(result['stdout'])
        manifest_raw = (bundle / 'backend.json').read_bytes()
        manifest = json.loads(manifest_raw)
        report['export'] = exported
        check('real-export-fixed-files', set(p.name for p in bundle.iterdir()) == {'backend.json', *ROLES.values()})
        check('export-is-preparation-only', exported['exported'] and not exported['vmExecuted']
              and not exported['releaseQualified'] and not exported['admissionIntegrated'])
        check('export-exact-manifest-pin', sha(manifest_raw) == exported['manifestSha256'])
        for role, name in ROLES.items():
            origin = original / ('manifest.json' if role == 'provenance' else name)
            check('export-' + role + '-exact-bytes', digest(bundle / name) == digest(origin) == manifest['files'][role]['sha256']
                  and (bundle / name).stat().st_size == manifest['files'][role]['size'])
            check('export-' + role + '-private-readonly', stat.S_IMODE((bundle / name).stat().st_mode) == (0o500 if role == 'host' else 0o400))
        check('export-normal-host-only', manifest['files']['host']['sha256'] == build['binaries']['hc-vm']
              and manifest['files']['host']['sha256'] != build['binaries']['hc-vm-uat'])
        # Small, explicit byte-export fixtures test filesystem failure handling;
        # only the real bundle below is used for native admission/staging.
        small = out / 'small-build'
        small.mkdir(mode=0o700)
        for name, content in (('hc-vm', b'fixed-host'), ('kernel', b'fixed-kernel'), ('root.ext4', b'fixed-root')):
            private(small / name, content)
        config = {'schema': 'testifysec.vm-config/v3', 'kernelSha256': digest(small / 'kernel'), 'rootDiskSha256': digest(small / 'root.ext4')}
        private(small / 'config.json', compact(config))
        metadata = {'schema': 'testifysec.vm-build/v2', 'configSha256': digest(small / 'config.json'),
                    'kernelSha256': config['kernelSha256'], 'rootDiskSha256': config['rootDiskSha256'],
                    'protocolFaultInjection': 'separate hc-vm-uat binary only', 'releaseQualified': False,
                    'binaries': {'hc-vm': digest(small / 'hc-vm'), 'hc-vm-uat': '0' * 64}}
        private(small / 'manifest.json', compact(metadata))

        def export_refusal(name, modify=None, restore=None):
            target = out / ('refused-' + name)
            if modify:
                modify()
            refused = False
            try:
                exporter.export(small, target)
            except (OSError, ValueError, KeyError, TypeError, RuntimeError):
                refused = True
            finally:
                if restore:
                    restore()
            check('export-refuses-' + name, refused and not target.exists())

        saved_metadata = (small / 'manifest.json').read_bytes()
        export_refusal('metadata-duplicate', lambda: (small / 'manifest.json').write_bytes(b'{"schema":"x",' + saved_metadata[1:]),
                       lambda: (small / 'manifest.json').write_bytes(saved_metadata))
        saved_host = (small / 'hc-vm').read_bytes()
        export_refusal('normal-host-substitution', lambda: (small / 'hc-vm').write_bytes(b'fault-host'), lambda: (small / 'hc-vm').write_bytes(saved_host))
        saved_config = (small / 'config.json').read_bytes()
        export_refusal('config-digest', lambda: (small / 'config.json').write_bytes(saved_config + b' '), lambda: (small / 'config.json').write_bytes(saved_config))
        def link_host():
            (small / 'hc-vm').rename(small / 'held-host')
            (small / 'hc-vm').symlink_to('held-host')
        def unlink_host():
            (small / 'hc-vm').unlink()
            (small / 'held-host').rename(small / 'hc-vm')
        export_refusal('symlink', link_host, unlink_host)
        export_refusal('hardlink', lambda: os.link(small / 'hc-vm', small / 'other-host'), lambda: (small / 'other-host').unlink())
        export_refusal('group-writable', lambda: (small / 'hc-vm').chmod(0o620), lambda: (small / 'hc-vm').chmod(0o600))
        existing = out / 'already-owned'
        existing.mkdir(mode=0o700)
        private(existing / 'sentinel', b'leave-this-alone')
        refused = False
        try:
            exporter.export(small, existing)
        except FileExistsError:
            refused = True
        check('export-existing-directory-not-deleted', refused and (existing / 'sentinel').read_bytes() == b'leave-this-alone')
        original_write = exporter.os.write
        partial = {'bytes': 0}
        def fault_write(descriptor, raw):
            if partial['bytes'] == 0:
                partial['bytes'] = original_write(descriptor, raw[:1])
                return partial['bytes']
            raise OSError('synthetic output write failure')
        exporter.os.write = fault_write
        try:
            export_refusal('partial-copy-write-fault')
        finally:
            exporter.os.write = original_write
        check('export-write-fault-followed-real-partial-write', partial['bytes'] == 1)

        # Native integration continues below. All fixture private keys are
        # ephemeral, held only by the existing Go generator, and never saved.
        run_native(args, out, bundle, manifest_raw, report, command, check)
        check('final-source-closure', source_hashes() == report['sourceFiles'])
        check('final-retained-build-unchanged', digest(original / 'manifest.json') == sha(build_raw)
              and all(digest(original / ('manifest.json' if role == 'provenance' else name)) == manifest['files'][role]['sha256']
                      for role, name in ROLES.items()))
        check('final-exported-bytes-unchanged', digest(bundle / 'backend.json') == sha(manifest_raw)
              and all(digest(bundle / name) == manifest['files'][role]['sha256'] for role, name in ROLES.items()))
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['checkCount'] = len(checks)
        destination = out / 'report.json'
        private(destination, json.dumps(report, indent=2).encode() + b'\n')
        print(json.dumps({'passed': report['passed'], 'checks': len(checks), 'report': str(destination), 'sha256': digest(destination)}))
    return 0 if report['passed'] else 1


def run_native(args, out, bundle, manifest_raw, report, command, check):
    broker = SOURCE.parent / 'broker'
    managed = SOURCE.parent / 'managed'
    native = SOURCE.parent / 'native'
    checker = out / 'vz-backend-check'
    command('build-native-checker', [args.go, 'build', '-trimpath', '-o', checker, './cmd/vz-backend-check'], cwd=broker)
    report['checkerSha256'] = digest(checker)
    tested = command('native-package-tests', [args.go, 'test', '-json', '-count=1', './vzbackend', './cmd/vz-backend-check'], cwd=broker)
    events = [json.loads(raw) for raw in tested['stdout'].splitlines()]
    report['nativeTests'] = {'passed': sorted(event['Test'] for event in events if event.get('Action') == 'pass' and event.get('Test')),
                             'skipped': sorted(event['Test'] for event in events if event.get('Action') == 'skip' and event.get('Test'))}
    required = {'TestStrictManifest', 'TestStrictUnicode', 'TestAdmissionOutputBinding', 'TestAssignmentVersionAndOverlap',
                'TestPreparedCopyInspectClose', 'TestPreparedFreshStages', 'TestPreparedExpiryAndCancellation',
                'TestPreparedTamperRefusal', 'TestPartialCopyFailureCleanup', 'TestCleanupRetainsUnknownContent',
                'TestCustodyAndInventoryRefusals', 'TestProtectedAncestorAndAssignment',
                'TestNativeOwnedProcessGroup', 'TestNativeCancellation', 'TestCleanupUncertaintyRetainsStage',
                'TestOwnedInputCancellation', 'TestInheritedInputCancellation', 'TestOwnedInputPreservesFlags'}
    check('native-tests-executed', required.issubset(report['nativeTests']['passed']) and not report['nativeTests']['skipped'])
    template = (managed / 'fixtures-v2.go').read_bytes()
    literal = b'manifest := []byte(`{"schema":"testifysec.synthetic-backend-manifest/v1","executable":false}`)'
    check('fixture-template-exact-adaptation-point', template.count(literal) == 1)
    report['fixtureTemplateSha256'] = sha(template)
    stage = out / 'stage'
    stage.mkdir(mode=0o700)
    prepared_files = json.loads(manifest_raw)['files']
    assignments = {}

    def admission(label, raw):
        generated = template.replace(literal, b'manifest := []byte(' + json.dumps(raw.decode('ascii')).encode() + b')')
        generator = out / (label + '-fixtures.go')
        private(generator, generated)
        fixtures = out / (label + '-fixtures')
        command(label + '-fixtures', [args.go, 'run', generator, fixtures], cwd=native)
        check(label + '-fixture-exact-manifest', (fixtures / 'backend-manifest.json').read_bytes() == raw)
        native_bundle = out / (label + '-admission')
        command(label + '-native-admission-build', [sys.executable, '-B', managed / 'build.py', '--go', args.go,
                                                  '--bun', args.bun, '--trust', fixtures / 'trust-v2.json', '--output', native_bundle], timeout=300)
        built = json.loads((native_bundle / 'manifest.json').read_bytes())
        check(label + '-native-build-pins', built['profileVersion'] == 2
              and built['assignment']['backend'] == {'kind': 'darwin-vz/v1', 'manifestSha256': sha(raw)}
              and all(digest(native_bundle / name) == pin for name, pin in built['files'].items()))
        envelope = (fixtures / 'valid-v2.json').read_bytes()
        trust = json.loads((fixtures / 'trust-v2.json').read_bytes())
        payload = base64.b64decode(json.loads(envelope)['payload'], validate=True)
        assignment = {'schema': 'testifysec.aflock.vz-backend-assignment/v1', 'installationDirectory': str(bundle),
                      'stagingDirectory': str(stage), 'manifestSha256': sha(raw), 'profileSha256': sha(payload),
                      'admissionExecutable': str(native_bundle / 'hardened-admission'),
                      'admissionSha256': digest(native_bundle / 'hardened-admission'),
                      'tenantId': trust['tenantId'], 'deploymentId': trust['deploymentId'], 'profileId': trust['profileId']}
        report['fixtures'][label] = {'generatorSha256': sha(generated),
                                    'files': {p.name: digest(p) for p in sorted(fixtures.iterdir()) if p.is_file()}}
        report['nativeBundles'][label] = {'directory': str(native_bundle), 'manifestSha256': digest(native_bundle / 'manifest.json'),
                                         'manifest': built}
        assignments[label] = assignment
        return assignment, envelope, fixtures

    def invoke(name, assignment, envelope, success=False, expected_code=None, raw_assignment=None, extra_env=None):
        path = out / (name + '-assignment.json')
        private(path, raw_assignment if raw_assignment is not None else compact(assignment))
        result = command(name, [checker, '--assignment', path], data=envelope, expected=0 if success else 1, extra_env=extra_env)
        value = json.loads(result['stdout'])
        report['runs'][name]['decision'] = value
        report['runs'][name]['assignmentSha256'] = digest(path)
        check(name + '-typed-decision', value.get('schema') == 'testifysec.aflock.vz-backend-check/v1'
              and value.get('scope') == 'backend-preparation-only' and value.get('prepared') is success)
        if success:
            check(name + '-staged-bytes-rechecked', value.get('cleaned') is True and value.get('executionEnabled') is False
                  and value.get('files') == prepared_files and value.get('manifestSha256') == assignment['manifestSha256']
                  and value.get('profileSha256') == assignment['profileSha256'])
        else:
            check(name + '-explicit-refusal', isinstance(value.get('code'), str) and bool(value['code'])
                  and (expected_code is None or value['code'] == expected_code))
        check(name + '-stage-empty-after-exit', not list(stage.iterdir()))
        return value

    valid, envelope, fixtures = admission('valid', manifest_raw)
    invoke('actual-signed-v2-prepare', valid, envelope, success=True)
    reasons = {'valid-v1': 'unsupported-profile-type', 'tampered': 'profile-signature-invalid',
               'wrong-key': 'profile-signature-invalid', 'expired': 'profile-time-invalid', 'rollback': 'profile-rollback',
               'wrong-tenant': 'assignment-mismatch', 'wrong-pin': 'backend-assignment-mismatch'}
    for label, reason in reasons.items():
        raw = (fixtures / (label + '.json')).read_bytes()
        direct = command('direct-native-refuses-' + label, [valid['admissionExecutable']], data=raw, expected=1)
        check(label + '-native-refusal-reason', json.loads(direct['stdout']).get('reason') == reason)
        invoke('profile-refuses-' + label, valid, raw)
    for label, key, value in (('manifest-pin', 'manifestSha256', '0' * 64), ('profile-pin', 'profileSha256', '0' * 64),
                              ('native-admission-pin', 'admissionSha256', '0' * 64), ('tenant', 'tenantId', 'other'),
                              ('deployment', 'deploymentId', 'other'), ('profile', 'profileId', 'other')):
        invoke('assignment-refuses-' + label, {**valid, key: value}, envelope)
    invoke('assignment-refuses-unknown-field', {**valid, 'override': True}, envelope)
    invoke('assignment-refuses-duplicate-alias', valid, envelope,
           raw_assignment=b'{"\\u0073chema":"ignored",' + compact(valid)[1:])
    invoke('envelope-refuses-trailing-object', valid, envelope + b'{}')
    invoke('envelope-refuses-oversize', valid, b' ' * (512 * 1024 + 1))

    def replace_manifest(raw):
        path = bundle / 'backend.json'
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400)

    try:
        replace_manifest(manifest_raw + b' ')
        invoke('installation-refuses-raw-manifest-tamper', valid, envelope)
    finally:
        replace_manifest(manifest_raw)
    host = bundle / 'hc-vm'
    original_mode = stat.S_IMODE(host.stat().st_mode)
    with host.open('rb') as stream:
        first = stream.read(1)
    try:
        host.chmod(0o600)
        with host.open('r+b') as stream:
            stream.write(bytes([first[0] ^ 1]))
        host.chmod(original_mode)
        invoke('installation-refuses-host-byte-tamper', valid, envelope)
    finally:
        host.chmod(0o600)
        with host.open('r+b') as stream:
            stream.write(first)
        host.chmod(original_mode)
    kernel = bundle / 'kernel'
    with kernel.open('rb') as stream:
        first_kernel = stream.read(1)
    try:
        kernel.chmod(0o600)
        with kernel.open('r+b') as stream:
            stream.write(bytes([first_kernel[0] ^ 1]))
        kernel.chmod(0o400)
        invoke('installation-refuses-kernel-byte-digest', valid, envelope, expected_code='file_digest')
    finally:
        kernel.chmod(0o600)
        with kernel.open('r+b') as stream:
            stream.write(first_kernel)
        kernel.chmod(0o400)
    held = out / 'held-host'
    bundle.chmod(0o700)
    try:
        host.rename(held)
        host.symlink_to(held)
        bundle.chmod(0o500)
        invoke('installation-refuses-host-symlink', valid, envelope)
    finally:
        bundle.chmod(0o700)
        if host.is_symlink():
            host.unlink()
        if held.exists():
            held.rename(host)
        bundle.chmod(0o500)
    link = out / 'hardlinked-host'
    try:
        os.link(host, link)
        invoke('installation-refuses-host-hardlink', valid, envelope)
    finally:
        link.unlink()
    try:
        host.chmod(0o520)
        invoke('installation-refuses-group-writable-host', valid, envelope)
    finally:
        host.chmod(original_mode)

    # These variants have fresh, valid native signed profiles and protected pins
    # for the exact invalid manifest bytes. Their refusal must therefore come
    # from native manifest validation, not a stale signature or digest mismatch.
    variants = {
        'duplicate-manifest-alias': b'{"\\u006bind":"darwin-vz/v1",' + manifest_raw[1:],
        'unsupported-job-schema': compact({**json.loads(manifest_raw), 'jobSchema': 'testifysec.vm-job/v2'}),
        'null-host-size': compact({**json.loads(manifest_raw), 'files': {**prepared_files, 'host': {**prepared_files['host'], 'size': None}}}),
    }
    for label, raw in variants.items():
        assigned, signed, _ = admission(label, raw)
        direct = command(label + '-direct-native-admission', [assigned['admissionExecutable']], data=signed)
        decision = json.loads(direct['stdout'])
        check(label + '-actually-admitted-exact-backend', decision.get('admitted') is True
              and decision.get('schemaVersion') == 2 and decision['profile']['backend']['manifestSha256'] == sha(raw))
        try:
            replace_manifest(raw)
            expected = 'manifest_contract' if label == 'unsupported-job-schema' else 'manifest_invalid'
            refused = invoke('manifest-refuses-' + label, assigned, signed, expected_code=expected)
            check(label + '-reaches-manifest-validator', refused['code'] == expected)
        finally:
            replace_manifest(manifest_raw)
    traps = out / 'path-traps'
    traps.mkdir(mode=0o700)
    marker = out / 'unexpected-runtime-install'
    for name in ('node', 'npm', 'bun', 'docker'):
        path = traps / name
        private(path, ('#!/bin/sh\necho unexpected > ' + shlex.quote(str(marker)) + '\nexit 90\n').encode())
        path.chmod(0o700)
    poison = out / 'poison.js'
    private(poison, b'throw new Error("ambient preload executed")\n')
    invoke('pinned-native-no-runtime-install-or-preload', valid, envelope, success=True,
           extra_env={'PATH': str(traps), 'BUN_OPTIONS': '--preload ' + str(poison), 'NODE_OPTIONS': '--require ' + str(poison),
                      'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1'})
    check('no-path-trap-executed', not marker.exists())
    check('final-checker-bytes', digest(checker) == report['checkerSha256'])
    for label, item in report['nativeBundles'].items():
        path = Path(item['directory'])
        built = item['manifest']
        check(label + '-native-final-byte-bindings', digest(path / 'manifest.json') == item['manifestSha256']
              and all(digest(path / name) == pin for name, pin in built['files'].items())
              and all(digest(managed / name) == pin for name, pin in built['sourceFiles'].items())
              and all(digest(native / name) == pin for name, pin in built['nativeBuild']['sourceFiles'].items())
              and all(digest(Path(name)) == pin for name, pin in built['nativeGoInputs']['files'].items())
              and all(digest(Path(tool['path'])) == tool['sha256'] for tool in built['buildTools'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
