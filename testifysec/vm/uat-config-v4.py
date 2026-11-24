#!/usr/bin/env python3
# jade:ring local
"""Actual Swift pre-launch validation of explicit config-v4/gateway-v2 binding."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

SOURCE = Path(__file__).resolve().parent
SELECTED = ('host/main.swift', 'host/managed.swift', 'host/relay.swift',
            'fixtures/config-v4-probe.swift', 'uat-config-v4.py', 'CONFIG-V4.md', 'build.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()


def private(path, raw):
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(raw)


def group_absent(pid):
    try:
        os.killpg(pid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return False


def run(argv, cwd, timeout, limit=1 << 20):
    """Bound local compiler/fixture IO, observing exit, EOF and owned group drain."""
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(cwd), 'TMPDIR': str(cwd), 'LANG': 'C'}
    process = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=environment,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    selector = selectors.DefaultSelector()
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + timeout
    completed = False
    try:
        for key, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, key)
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                raise TimeoutError('owned fixture deadline')
            for key, _ in selector.select(.05):
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output[key.data].extend(raw)
                if len(output[key.data]) > limit:
                    raise ValueError('owned fixture output bound')
        process.wait(timeout=1)
        while not group_absent(process.pid) and time.monotonic() < deadline:
            time.sleep(.01)
        if not group_absent(process.pid):
            raise RuntimeError('owned process group retained')
        completed = True
        return process.returncode, bytes(output['stdout']), bytes(output['stderr'])
    finally:
        try:
            if not completed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                end = time.monotonic() + 3
                while not group_absent(process.pid) and time.monotonic() < end:
                    time.sleep(.01)
                if not group_absent(process.pid):
                    raise RuntimeError('owned fixture cleanup incomplete')
        finally:
            for key in list(selector.get_map().values()):
                key.fileobj.close()
            selector.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    report = {'schema': 'testifysec.aflock.vm-config-v4-uat/v1', 'passed': False, 'checks': [], 'cases': [],
              'scope': 'Compiled actual Swift validation, serial pipe lifecycle, and normal-host pre-boot refusals; no VM boot or profile authentication',
              'limitations': ['Positive cases stop after real pre-launch validation; the fixture never constructs Runner.',
                              'Dummy kernel/root bytes are public pinned fixture files, not bootable release artifacts.',
                              'No native backend file authority, live platform identity, provider traffic or execution qualification.',
                              'Runtime config-v4 is generated after an independently chosen manifest pin; build.py remains unchanged.']}

    def check(name, condition):
        report['checks'].append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    try:
        before = {name: digest((SOURCE / name).read_bytes()) for name in SELECTED}
        report['sourceFiles'] = before
        code, stdout, stderr = run(['/usr/bin/xcrun', '--find', 'swiftc'], output, 10)
        private(output / 'swift-discovery.stdout', stdout)
        private(output / 'swift-discovery.stderr', stderr)
        check('swift-tool-discovery', code == 0 and Path(stdout.decode().strip()).is_absolute())
        swift = Path(stdout.decode().strip())
        report['swift'] = {'path': str(swift), 'sha256': digest(swift.read_bytes())}
        code, stdout, stderr = run(['/usr/bin/xcrun', '--show-sdk-path'], output, 10)
        private(output / 'sdk-discovery.stdout', stdout)
        private(output / 'sdk-discovery.stderr', stderr)
        check('sdk-path-discovery', code == 0 and Path(stdout.decode().strip()).is_absolute())
        sdk = stdout.decode().strip()
        report['sdkPath'] = sdk
        stage = output / 'source'
        stage.mkdir(mode=0o700)
        for name in SELECTED:
            target = stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            private(target, (SOURCE / name).read_bytes())
        original = (stage / 'host/main.swift').read_text()
        marker = '@main struct Main {'
        check('exact-single-main-adapter', original.count(marker) == 1)
        adapted = original.replace(marker, 'struct Main {')
        private(stage / 'host/validation-main.swift', adapted.encode())
        report['entryAdapter'] = {'originalSha256': digest(original.encode()), 'adaptedSha256': digest(adapted.encode()),
                                  'change': 'Remove only @main attribute; production Main implementation and all validation retained.'}
        executables = {}
        for name, sources in [('probe', ['host/validation-main.swift', 'host/managed.swift', 'host/relay.swift', 'fixtures/config-v4-probe.swift']),
                              ('host', ['host/main.swift', 'host/managed.swift', 'host/relay.swift'])]:
            executable = output / name
            code, stdout, stderr = run([swift, '-parse-as-library', '-sdk', sdk, '-module-cache-path', output / 'swift-cache',
                                       *[stage / source for source in sources], '-o', executable], output, 120)
            private(output / (name + '-build.stdout'), stdout)
            private(output / (name + '-build.stderr'), stderr)
            check(name + '-compiled', code == 0)
            executables[name] = executable
        report['executables'] = {name: {'path': str(path), 'sha256': digest(path.read_bytes())} for name, path in executables.items()}
        report['serialCases'] = []
        for mode in ('empty-eof', 'bytes-eof', 'read-error', 'held-writer'):
            code, stdout, stderr = run([executables['probe'], '--serial-case', mode], output, 5)
            private(output / ('serial-' + mode + '.stdout'), stdout)
            private(output / ('serial-' + mode + '.stderr'), stderr)
            check('serial-' + mode + '-process-completed', code == 0 and not stderr)
            value = json.loads(stdout)
            expected_eof = mode in ('empty-eof', 'bytes-eof')
            check('serial-' + mode + '-actual-read-result', value['eof'] is expected_eof
                  and value['failed'] is (mode == 'read-error') and value['drained'] is (mode != 'held-writer')
                  and value['bytesBase64'] == ('YWN0dWFsIHNlcmlhbCBieXRlcwo=' if mode == 'bytes-eof' else ''))
            for version in (2, 3):
                check('serial-' + mode + '-v' + str(version) + '-shape-unchanged',
                      value['observations'][str(version)] == {'schema': 'testifysec.vm-observation/v' + str(version),
                                                             'passed': True, 'admissionIntegrated': False})
            check('serial-' + mode + '-v4-independent-flags', value['observations']['4'] == {
                'schema': 'testifysec.vm-observation/v4', 'passed': expected_eof, 'admissionIntegrated': False,
                'serialReaderDrained': mode != 'held-writer', 'serialEOFObserved': expected_eof})
            if mode == 'held-writer':
                check('serial-held-writer-eventually-eof-after-close', value['followup'] == {'drained': True, 'eof': True, 'failed': False})
            report['serialCases'].append({'mode': mode, 'stdoutSha256': digest(stdout), 'stderrSha256': digest(stderr), **value})
        kernel, root = b'public fixture kernel bytes\n', b'public fixture immutable root bytes\n'
        private(output / 'kernel', kernel)
        private(output / 'root.ext4', root)
        kernel_hash, root_hash = digest(kernel), digest(root)
        pair_hash = digest((kernel_hash + '\n' + root_hash + '\n').encode())
        manifest_hash = digest(b'independent exported backend manifest fixture')
        check('manifest-distinct-from-kernel-root-pair', pair_hash != manifest_hash)
        request = {'prompt': 'public fixture prompt', 'timeoutSeconds': 1}
        material = []
        binding = {'requestSha256': digest(compact(request)), 'profileSha256': 'b' * 64,
                   'sessionId': 'service-assigned-session', 'materialsSha256': digest(compact(material)), 'backendSha256': pair_hash}
        job = {'schema': 'testifysec.vm-job/v3', 'binding': binding, 'request': request, 'materials': material}
        private(output / 'job.json', compact(job))
        config = {'schema': 'testifysec.vm-config/v4', 'kernel': str(output / 'kernel'), 'kernelSha256': kernel_hash,
                  'rootDisk': str(output / 'root.ext4'), 'rootDiskSha256': root_hash, 'jobFile': str(output / 'job.json'),
                  'jobSha256': digest(compact(job)), 'binding': binding, 'memoryMiB': 1024, 'cpus': 1, 'timeoutSeconds': 11,
                  'gatewayConfigFile': '', 'gatewayConfigSha256': '', 'backendManifestSha256': manifest_hash}
        gateway = {'schema': 'testifysec.hardened-opencode.gateway/v2', 'session': binding['sessionId'],
                   'profileDigest': binding['profileSha256'], 'socket': str(output / 'g.sock'),
                   'backend': {'kind': 'darwin-vz/v1', 'manifestSha256': manifest_hash}}
        tasks = []

        def add(name, config_mutation=None, gateway_mutation=None, *, expected=None, raw_config=None, raw_gateway=None):
            c, g = copy.deepcopy(config), copy.deepcopy(gateway)
            if config_mutation:
                config_mutation(c)
            if gateway_mutation:
                gateway_mutation(g)
            tasks.append((name, c, g, expected, raw_config, raw_gateway))

        add('v4-gateway-v2')
        def legacy(version, without_gateway=False):
            def mutation(c):
                c['schema'] = 'testifysec.vm-config/v' + str(version)
                del c['backendManifestSha256']
                if without_gateway:
                    del c['gatewayConfigFile']; del c['gatewayConfigSha256']
            return mutation
        def v1(g):
            g['schema'] = 'testifysec.hardened-opencode.gateway/v1'
            del g['backend']
        for version in (2, 3):
            add(f'v{version}-gateway-v1', legacy(version), v1)
            add(f'v{version}-without-gateway', legacy(version, True), v1)
            add(f'v{version}-gateway-v2-refused', legacy(version), expected='gateway-assignment')
            add(f'v{version}-manifest-refused', lambda c, v=version: c.update(schema=f'testifysec.vm-config/v{v}'), v1, expected='config-fields')
            add(f'v{version}-null-manifest-refused', lambda c, v=version: c.update(schema=f'testifysec.vm-config/v{v}', backendManifestSha256=None), v1, expected='config-fields')
        add('v4-gateway-v1-refused', gateway_mutation=v1, expected='gateway-backend-assignment')
        add('v4-missing-manifest', lambda c: c.pop('backendManifestSha256'), expected='managed-fields')
        for value, label in [(None, 'null'), ('A' * 64, 'uppercase'), ('f' * 63, 'short')]:
            add('v4-' + label + '-manifest', lambda c, v=value: c.update(backendManifestSha256=v), expected='backend-manifest-config')
        add('v4-manifest-is-not-pair', lambda c: c.update(backendManifestSha256=pair_hash), expected='gateway-backend-assignment')
        add('v4-pair-is-not-manifest', lambda c: c['binding'].update(backendSha256=manifest_hash), expected='backend-binding')
        for field in ('gatewayConfigFile', 'gatewayConfigSha256'):
            add('v4-missing-' + field, lambda c, f=field: c.pop(f), expected='managed-fields')
            add('v4-null-' + field, lambda c, f=field: c.update({f: None}), expected='backend-manifest-config')
        for label, key, value in [('wrong-kind', 'kind', 'docker/v1'), ('wrong-digest', 'manifestSha256', 'c' * 64), ('null-digest', 'manifestSha256', None)]:
            add('v4-backend-' + label, gateway_mutation=lambda g, k=key, v=value: g['backend'].update({k: v}), expected='gateway-backend-assignment')
        add('v4-null-backend', gateway_mutation=lambda g: g.update(backend=None), expected='gateway-backend-assignment')
        add('v4-extra-backend-key', gateway_mutation=lambda g: g['backend'].update(extra=True), expected='gateway-backend-assignment')
        add('v4-aliased-backend-key', gateway_mutation=lambda g: g['backend'].update(ManifestSha256=g['backend'].pop('manifestSha256')), expected='gateway-backend-assignment')
        add('v4-wrong-session', gateway_mutation=lambda g: g.update(session='caller-session'), expected='gateway-assignment')
        add('v4-wrong-profile', gateway_mutation=lambda g: g.update(profileDigest='c' * 64), expected='gateway-assignment')
        add('v4-wrong-gateway-digest', lambda c: c.update(gatewayConfigSha256='a' * 64), expected='gateway-assignment')
        add('v4-extra-config', lambda c: c.update(providerURL='https://untrusted.invalid'), expected='managed-fields')
        add('v4-fixture-field', lambda c: c.update(fixtureFault='hold-open'), expected='managed-fields')
        add('v4-duplicate-manifest', expected='managed-json-duplicate', raw_config=lambda raw: raw[:-1] + b',"backendManifestSha256":"' + manifest_hash.encode() + b'"}')
        add('v4-escaped-duplicate-backend-key', expected='managed-json-duplicate', raw_gateway=lambda raw: raw.replace(b'"manifestSha256":', b'"manifest\\u0053ha256":"' + manifest_hash.encode() + b'","manifestSha256":'))
        add('v4-null-binding', lambda c: c.update(binding=None), expected='decode-refused')
        add('v4-decimal-cpus', expected='managed-json-object', raw_config=lambda raw: raw.replace(b'"cpus":1,', b'"cpus":1.0,'))
        for name, current, assigned, expected, raw_config, raw_gateway in tasks:
            case = output / name
            case.mkdir(mode=0o700)
            if current['schema'] == 'testifysec.vm-config/v2':
                legacy_request = {'mode': 'worker', 'prompt': 'public fixture prompt'}
                current['binding']['requestSha256'] = digest(compact(legacy_request))
                legacy_job = {'schema': 'testifysec.vm-job/v2', 'binding': current['binding'],
                              'request': legacy_request, 'materials': []}
                private(case / 'job.json', compact(legacy_job))
                current['jobFile'] = str(case / 'job.json')
                current['jobSha256'] = digest(compact(legacy_job))
            gateway_raw = compact(assigned)
            if raw_gateway:
                gateway_raw = raw_gateway(gateway_raw)
            private(case / 'gateway.json', gateway_raw)
            if 'gatewayConfigFile' in current and current['gatewayConfigFile'] is not None:
                current['gatewayConfigFile'] = str(case / 'gateway.json')
            if current.get('gatewayConfigSha256') == '':
                current['gatewayConfigSha256'] = digest(gateway_raw)
            raw = compact(current)
            if raw_config:
                raw = raw_config(raw)
            private(case / 'config.json', raw)
            code, stdout, stderr = run([executables['probe'], case / 'config.json'], case, 5)
            private(case / 'probe.stdout', stdout)
            private(case / 'probe.stderr', stderr)
            value = json.loads(stdout)
            accepted = expected is None
            check(name + '-exact-validator-result', code == (0 if accepted else 2) and value['accepted'] is accepted
                  and value['vmStarted'] is False and (accepted or value['code'] == expected))
            if accepted:
                check(name + '-exact-selected-version', value['configSchema'] == current['schema']
                      and value['managed'] is (current['schema'] != 'testifysec.vm-config/v2')
                      and value['backendPairSha256'] == pair_hash)
            else:
                code, hostout, hosterr = run([executables['host'], case / 'config.json'], case, 5)
                private(case / 'host.stdout', hostout)
                private(case / 'host.stderr', hosterr)
                reason = b'refused("' + expected.encode() + b'")'
                check(name + '-normal-host-refuses-before-boot', code == 2 and not hostout
                      and (reason in hosterr if expected != 'decode-refused' else b'VM fixture refused:' in hosterr))
            report['cases'].append({'name': name, 'accepted': accepted, 'expectedCode': expected,
                                    'configSha256': digest(raw), 'gatewayConfigSha256': digest(gateway_raw),
                                    'probeStdoutSha256': digest(stdout), 'probeStderrSha256': digest(stderr)})
        check('source-bytes-unchanged', before == {name: digest((SOURCE / name).read_bytes()) for name in SELECTED})
        check('selected-artifacts-unchanged', all(digest(Path(item['path']).read_bytes()) == item['sha256'] for item in report['executables'].values())
              and digest(swift.read_bytes()) == report['swift']['sha256'])
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['checkCount'] = len(report['checks'])
        private(output / 'report.json', json.dumps(report, indent=2).encode() + b'\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']), 'cases': len(report['cases']),
                      'report': str(output / 'report.json'), 'sha256': digest((output / 'report.json').read_bytes())}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
