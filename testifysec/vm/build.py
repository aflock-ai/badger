#!/usr/bin/env python3
"""Build a reusable local VZ development image and a separate bounded session job."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

SOURCE = Path(__file__).resolve().parent


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def source_hashes():
    return {str(path.relative_to(SOURCE)): digest(path) for path in sorted(SOURCE.rglob('*'))
            if path.is_file() and path.suffix in ('.go', '.mod', '.swift', '.py', '.md', '.plist')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--kernel', type=Path, default=Path('/Applications/Docker.app/Contents/Resources/linuxkit/kernel'))
    parser.add_argument('--mke2fs', type=Path, default=Path('/opt/homebrew/opt/e2fsprogs/sbin/mke2fs'))
    parser.add_argument('--mode', choices=('edit', 'timeout', 'overflow', 'symlink', 'descendant', 'worker', 'gateway'), default='edit')
    parser.add_argument('--reuse', type=Path, help='Same-source build; reuse immutable image unless --worker-root adds a new toolpack')
    parser.add_argument('--worker-root', type=Path)
    parser.add_argument('--protocol', type=int, choices=(2,3), default=2, help='V2 fixture or V3 managed-shaped job/result; neither authorizes execution')
    args = parser.parse_args()
    if args.protocol == 3 and args.mode != 'worker':
        raise RuntimeError('V3 permits only the pinned worker entry')
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    before = source_hashes()
    staging = output / 'source'
    for name, expected in before.items():
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, target)
        if digest(target) != expected:
            raise RuntimeError('source changed during copy')
    tools = {}
    env = {'PATH': str(args.go.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': os.environ.get('HOME', ''),
           'GOWORK': 'off', 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOMAXPROCS': '2',
           'GOCACHE': os.environ.get('GOCACHE', str(output / 'gocache')), 'TMPDIR': str(output)}

    def tool(name, path):
        path = Path(path).resolve(strict=True)
        tools[name] = {'path': str(path), 'sha256': digest(path)}
        return path

    def run(argv, name, cwd=staging, extra=None):
        result = subprocess.run([str(arg) for arg in argv], cwd=cwd, env={**env, **(extra or {})}, capture_output=True, timeout=180)
        (output / (name + '.log')).write_bytes(result.stdout + b'\n--- STDERR ---\n' + result.stderr)
        if result.returncode:
            raise RuntimeError(name + ' failed; inspect ' + str(output / (name + '.log')))

    prior = None
    if args.reuse:
        prior = json.loads((args.reuse / 'manifest.json').read_text())
        if prior['schema'] != 'testifysec.vm-build/v2' or prior['sourceFiles'] != before:
            raise RuntimeError('reuse build has different schema or sources')
        for name in ('hc-vm', 'hc-vm-uat', 'init'):
            if digest(args.reuse / name) != prior['binaries'][name]:
                raise RuntimeError('reuse binary changed')
            shutil.copy2(args.reuse / name, output / name)
    else:
        go = tool('go', args.go)
        swift = tool('swiftc', '/usr/bin/swiftc')
        sign = tool('codesign', '/usr/bin/codesign')
        run([go, 'build', '-mod=readonly', '-p', '1', '-trimpath', '-buildvcs=false', '-o', output / 'init', '.'],
            'guest-build', staging / 'guest', {'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': 'arm64'})
        for name, flags in [('hc-vm', []), ('hc-vm-uat', ['-D', 'HC_VM_PROTOCOL_UAT'])]:
            run([swift, '-swift-version', '5', '-module-cache-path', output / 'swift-cache', '-O', '-parse-as-library',
                 *flags, *sorted((staging / 'host').glob('*.swift')), '-o', output / name], name + '-build')
            run([sign, '--force', '--sign', '-', '--entitlements', staging / 'entitlements.plist', output / name], name + '-dev-sign')
    reuse_disk = bool(prior and not args.worker_root)
    worker_sources = prior['workerFiles'] if reuse_disk else {}
    if reuse_disk:
        disk = Path(prior['rootDisk'])
        kernel = Path(prior['kernel'])
        if digest(disk) != prior['rootDiskSha256'] or digest(kernel) != prior['kernelSha256']:
            raise RuntimeError('reused immutable inputs changed')
    else:
        root = output / 'root'
        for name in ('proc', 'sys', 'dev', 'tmp', 'run', 'workspace', 'toolpack'):
            (root / name).mkdir(parents=True)
        shutil.copy2(output / 'init', root / 'init')
        if args.worker_root:
            for path in sorted(args.worker_root.rglob('*')):
                name = path.relative_to(args.worker_root)
                if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                    raise RuntimeError('worker root must contain directories and regular files only')
                destination = root / name
                if str(name) in ('init', 'request.json'):
                    raise RuntimeError('worker root replaces fixture authority')
                if path.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    worker_sources[str(name)] = digest(path)
                    shutil.copy2(path, destination)
                    if digest(destination) != worker_sources[str(name)]:
                        raise RuntimeError('worker source changed while copying')
        kernel = output / 'kernel'
        shutil.copyfile(args.kernel, kernel)
        kernel.chmod(0o400)
        disk = output / 'root.ext4'
        with disk.open('xb') as stream:
            stream.truncate((512 if worker_sources else 64) * 1024 * 1024)
        mke2fs = tool('mke2fs', args.mke2fs)
        run([mke2fs, '-q', '-F', '-t', 'ext4', '-O', '^has_journal', '-E', 'root_owner=0:0,lazy_itable_init=0', '-d', root, disk], 'root-image')
        disk.chmod(0o400)
    if args.mode == 'worker' and 'toolpack/opencode-worker' not in worker_sources:
        raise RuntimeError('worker mode requires prepared worker root')
    compact = lambda value: json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    request = {'mode': args.mode, 'prompt': 'Write result.txt and run its test.' if args.mode == 'worker' else ''}
    if args.protocol == 3:
        request = {'prompt': 'Complete the requested workspace task.', 'timeoutSeconds': 45}
    materials = []
    binding = {'requestSha256': sha(compact(request)), 'profileSha256': 'a' * 64, 'sessionId': uuid.uuid4().hex,
               'materialsSha256': sha(compact(materials)), 'backendSha256': sha((digest(kernel)+'\n'+digest(disk)+'\n').encode())}
    job = {'schema': 'testifysec.vm-job/v' + str(args.protocol), 'binding': binding, 'request': request, 'materials': materials}
    job_file = output / 'job.json'
    job_file.write_bytes(compact(job)); job_file.chmod(0o600)
    config = {'schema': 'testifysec.vm-config/v' + str(args.protocol), 'kernel': str(kernel), 'kernelSha256': digest(kernel),
              'rootDisk': str(disk), 'rootDiskSha256': digest(disk), 'jobFile': str(job_file), 'jobSha256': digest(job_file),
              'binding': binding, 'memoryMiB': 1024 if args.mode == 'worker' else 512, 'cpus': 1,
              'timeoutSeconds': 60 if args.mode == 'worker' else 15}
    (output / 'config.json').write_text(json.dumps(config, indent=2)+'\n'); (output / 'config.json').chmod(0o600)
    if source_hashes() != before or any(digest(value['path']) != value['sha256'] for value in tools.values()):
        raise RuntimeError('source/tool pathname changed during build')
    manifest = {'schema': 'testifysec.vm-build/v2', 'sourceFiles': before, 'tools': tools,
                'kernel': str(kernel), 'kernelSha256': config['kernelSha256'], 'rootDisk': str(disk),
                'rootDiskSha256': config['rootDiskSha256'], 'imageReused': reuse_disk,
                'jobSha256': config['jobSha256'], 'configSha256': digest(output/'config.json'), 'workerFiles': worker_sources,
                'binaries': {name: digest(output/name) for name in ('hc-vm', 'hc-vm-uat', 'init')},
                'signature': 'developer-ad-hoc-entitlement-not-publisher-signature', 'releaseQualified': False,
                'digestSource': 'pathname-byte-readback-not-runtime-measurement', 'vmExecuted': False,
                'protocolFaultInjection': 'separate hc-vm-uat binary only'}
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'build': str(output), 'manifestSha256': digest(output/'manifest.json')}))


if __name__ == '__main__':
    main()
