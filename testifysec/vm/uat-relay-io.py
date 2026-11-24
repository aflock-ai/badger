#!/usr/bin/env python3
# jade:ring local
"""Compile exact current macOS relay code; exercise local I/O and lifecycle."""
import argparse
import errno
import hashlib
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

SOURCE = Path(__file__).resolve().parent
SELECTED = ('host/relay.swift', 'host/main.swift', 'uat-relay-io.py', 'RELAY-IO-UAT.md',
            'fixtures/relay-io-probe.swift', 'fixtures/relay-lifecycle-probe.swift')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(argv, directory, timeout, *, close_stdout=False, output_limit=65536):
    """Bound both pipes and wall time; observe child exit before returning."""
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(directory), 'TMPDIR': str(directory), 'LANG': 'C'}
    process = subprocess.Popen([str(x) for x in argv], cwd=directory, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = selectors.DefaultSelector()
    started = time.monotonic()
    failure = None
    forced = False
    observed = False
    try:
        for name, pipe in (('stdout', process.stdout), ('stderr', process.stderr)):
            if close_stdout and name == 'stdout':
                pipe.close()
                continue
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map():
            if time.monotonic() - started > timeout:
                raise TimeoutError('fixture process or pipe deadline')
            for key, _ in selector.select(.05):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                streams[key.data].extend(chunk)
                if len(streams[key.data]) > output_limit:
                    raise ValueError('fixture output limit')
        process.wait(timeout=max(.01, timeout - (time.monotonic() - started)))
        observed = True
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as error:
        failure = type(error).__name__ + ': ' + str(error)
    finally:
        if not observed:
            forced = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
                observed = True
            except subprocess.TimeoutExpired:
                failure = 'fixture exit unobserved after kill'
        for key in list(selector.get_map().values()):
            key.fileobj.close()
        selector.close()
    return {'stdout': bytes(streams['stdout']), 'stderr': bytes(streams['stderr']),
            'exitCode': process.returncode, 'elapsedSeconds': time.monotonic() - started,
            'exitObserved': observed, 'forcedKill': forced, 'error': failure}


def cases():
    return [
        ('normal-200', False, b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok', None),
        ('chunked-200', False, b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n', None),
        ('split-chunked-200', False, b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n', None),
        ('close-delimited', False, b'HTTP/1.0 200 OK\r\n\r\nok', None),
        ('no-content', False, b'HTTP/1.1 204 No Content\r\n\r\n', None),
        ('early-429', True, b'HTTP/1.1 429 Too Many Requests\r\nContent-Length: 4\r\n\r\nbusy', None),
        ('split-early-429', True, b'HTTP/1.1 429 Too Many Requests\r\nContent-Length: 4\r\n\r\nbusy', None),
        ('early-503', True, b'HTTP/1.1 503 Unavailable\r\nContent-Length: 4\r\n\r\ndeny', None),
        ('early-200', True, b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok', 'gateway-request-write'),
        ('early-empty', True, b'', 'gateway-response-truncated'),
        ('truncated-length', False, b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok', 'gateway-response-truncated'),
        ('truncated-denial', True, b'HTTP/1.1 429 Busy\r\nContent-Length: 4\r\n\r\nx', 'gateway-response-truncated'),
        ('truncated-chunk', False, b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nok', 'gateway-response-truncated'),
        ('missing-chunk-terminal', False, b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n', 'gateway-response-truncated'),
        ('invalid-chunk', False, b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\ng\r\n', 'gateway-response-chunk'),
        ('extra-chunk-bytes', False, b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nx', 'gateway-response-extra'),
        ('invalid-status', True, b'HTTP/1.1 BAD Failed\r\nContent-Length: 0\r\n\r\n', 'gateway-response-status'),
        ('dual-framing', True, b'HTTP/1.1 429 Busy\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n', 'gateway-response-framing'),
        ('duplicate-length', True, b'HTTP/1.1 429 Busy\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n', 'gateway-response-header'),
        ('extra-response', False, b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\n\r\n', 'gateway-response-extra'),
        ('oversize-length', False, b'HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\n\r\n', 'gateway-response-framing'),
        ('header-limit', True, b'HTTP/1.1 429 Busy\r\nX-Fill: ' + b'x' * 17000, 'gateway-response-header-limit'),
        ('idle-no-response', True, None, 'gateway-exchange-deadline'),
        ('response-peer-cancel', False, b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok', None),
    ]


def exercise(out, executable, request, case):
    name, early, response, refusal = case
    directory = Path(tempfile.mkdtemp(prefix='aflock-io-', dir='/private/tmp'))
    pathname = str(directory / 'gateway.sock')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.settimeout(5)
    state = {}
    thread = None
    cleanup = False
    try:
        listener.bind(pathname)
        listener.listen(1)

        def serve():
            try:
                conn, _ = listener.accept()
                conn.settimeout(5)
                with conn:
                    received = b''
                    while b'\r\n\r\n' not in received:
                        part = conn.recv(1024)
                        if not part or len(received) + len(part) > 16384:
                            raise ValueError('fixture request header missing or oversized')
                        received += part
                    if not early:
                        while len(received) < len(request):
                            part = conn.recv(min(65536, len(request) - len(received)))
                            if not part:
                                raise ValueError('fixture request truncated')
                            received += part
                        state['requestMatched'] = received == request
                    else:
                        state['partialRequest'] = len(received) < len(request)
                        conn.shutdown(socket.SHUT_RD)
                    if response is None:
                        time.sleep(3.3)
                    elif name.startswith('split-'):
                        for byte in response:
                            conn.sendall(bytes([byte]))
                            time.sleep(.0002)
                    else:
                        conn.sendall(response)
                    try:
                        conn.shutdown(socket.SHUT_WR)
                    except OSError as error:
                        if response is not None or error.errno != errno.ENOTCONN:
                            raise
                        state['deadlineClientClosed'] = True
            except (BrokenPipeError, ConnectionResetError):
                state['clientAborted'] = True
            except Exception as error:
                state['error'] = type(error).__name__ + ': ' + str(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        result = run([executable, pathname, out / 'request.bin'], out, 7,
                     close_stdout=name == 'response-peer-cancel')
    finally:
        if thread is not None:
            thread.join(timeout=6)
        listener.close()
        cleanup = thread is None or not thread.is_alive()
        if cleanup:
            shutil.rmtree(directory)
    if not cleanup:
        raise RuntimeError('fixture thread not drained; retained ' + str(directory))
    (out / (name + '.stdout')).write_bytes(result['stdout'])
    (out / (name + '.stderr')).write_bytes(result['stderr'])
    decoded = json.loads(result['stderr'])
    passed = result['exitObserved'] and not result['forcedKill'] and result['error'] is None and 'error' not in state
    passed = passed and result['exitCode'] == (2 if refusal else 0) and decoded['passed'] is (refusal is None)
    if refusal:
        passed = passed and decoded.get('error') == 'refused("' + refusal + '")'
    elif name == 'response-peer-cancel':
        passed = passed and decoded['responseCancelled'] is True and decoded['requestSent'] is True
    else:
        passed = passed and result['stdout'] == response and decoded['earlyRefusal'] is early
        passed = passed and decoded['requestComplete'] is (not early) and decoded['requestSent'] is (not early)
        passed = passed and decoded['responseCancelled'] is False
    passed = passed and state.get('partialRequest' if early else 'requestMatched') is True
    if name == 'idle-no-response':
        passed = passed and 2.8 <= result['elapsedSeconds'] < 4.5
    return {'name': name, 'passed': passed, 'response': decoded, 'server': state,
            'elapsedSeconds': result['elapsedSeconds'], 'exitObserved': result['exitObserved'],
            'forcedKill': result['forcedKill'], 'processError': result['error'], 'fixtureCleanup': cleanup,
            'stdoutSha256': sha(result['stdout']), 'stderrSha256': sha(result['stderr'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--swiftc', type=Path, default=Path('/usr/bin/swiftc'))
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise RuntimeError('this component harness requires macOS; no other platform is claimed')
    out = args.output.absolute()
    out.mkdir(mode=0o700)
    swift = args.swiftc.resolve(strict=True)
    inputs = {name: (SOURCE / name).read_bytes() for name in SELECTED}
    report = {'schema': 'testifysec.vm-relay-io-uat/v1', 'passed': False, 'cases': [], 'lifecycle': {},
              'sourceFiles': {name: sha(raw) for name, raw in inputs.items()}, 'compiler': str(swift),
              'compilerSha256': sha(swift.read_bytes()), 'scope': 'macOS native I/O and lifecycle only; no VM or provider calls',
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip(),
              'worktreeDirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=SOURCE)),
              'virtualizationConnection': 'test FD holder only; actual socket shutdown and real30s deadline'}
    try:
        relay = inputs['host/relay.swift'].decode()
        start, connection, end = ('private struct RelayHTTPResponse {', 'private final class RelayConnection {', 'final class ModelRelay:')
        if any(relay.count(marker) != 1 for marker in (start, connection, end)):
            raise RuntimeError('current relay extraction boundaries missing or ambiguous')
        a, b, c = (relay.index(marker) for marker in (start, connection, end))
        if not a < b < c:
            raise RuntimeError('current relay extraction order differs')
        constants = []
        for name in ('relayRequestLimit', 'relayResponseLimit'):
            lines = [line for line in relay.splitlines() if line.startswith('private let ' + name + ' = ')]
            if len(lines) != 1:
                raise RuntimeError('current relay bound missing or ambiguous')
            constants.extend(lines)
        error = 'enum FixtureError: Error { case refused(String) }'
        if inputs['host/main.swift'].decode().count(error) != 1:
            raise RuntimeError('current refusal type differs')
        header = 'import Foundation\nimport Darwin\n' + error + '\n'
        generated = {
            'io': header + '\n'.join(constants) + '\n' + relay[a:b] + inputs['fixtures/relay-io-probe.swift'].decode(),
            'lifecycle': header + 'final class VZVirtioSocketConnection { let fileDescriptor:Int32; init(_ fd:Int32) { fileDescriptor=fd } }\n'
                         + relay[b:c] + inputs['fixtures/relay-lifecycle-probe.swift'].decode(),
        }
        report['extractedSha256'] = {'exchange': sha(relay[a:b].encode()), 'connection': sha(relay[b:c].encode())}
        report['generatedFiles'] = {}
        report['binaries'] = {}
        version = run([swift, '--version'], out, 10)
        if version['exitCode'] != 0 or version['error']:
            raise RuntimeError('compiler version unavailable')
        report['compilerVersion'] = version['stdout'].decode()
        for name, text in generated.items():
            source = out / (name + '.swift')
            source.write_text(text)
            report['generatedFiles'][source.name] = sha(source.read_bytes())
            result = run([swift, '-module-cache-path', out / 'swift-cache', source, '-o', out / name], out, 120,
                         output_limit=1024 * 1024)
            log = result['stdout'] + result['stderr']
            (out / (name + '-build.log')).write_bytes(log)
            if result['exitCode'] != 0 or result['error'] or result['forcedKill']:
                raise RuntimeError(name + ' fixture build failed')
            report['binaries'][name] = sha((out / name).read_bytes())
        body = b'a' * (1024 * 1024)
        request = (b'POST /v1/chat/completions HTTP/1.1\r\nHost: hardened-gateway\r\nContent-Length: '
                   + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
        (out / 'request.bin').write_bytes(request)
        for case in cases():
            report['cases'].append(exercise(out, out / 'io', request, case))
        life = run([out / 'lifecycle'], out, 36)
        (out / 'lifecycle.stdout').write_bytes(life['stdout'])
        (out / 'lifecycle.stderr').write_bytes(life['stderr'])
        report['lifecycle'] = json.loads(life['stdout'])
        expected = ['cancel-before-complete', 'complete-before-cancel', 'real-deadline-downstream-close']
        life_ok = life['exitCode'] == 0 and life['error'] is None and not life['forcedKill'] and life['exitObserved']
        life_ok = life_ok and report['lifecycle']['passed'] is True and [x['name'] for x in report['lifecycle']['cases']] == expected
        life_ok = life_ok and all(x['passed'] is True for x in report['lifecycle']['cases'])
        life_ok = life_ok and 29.5 <= report['lifecycle']['cases'][-1]['elapsedSeconds'] < 32
        stable = all((SOURCE / name).read_bytes() == raw for name, raw in inputs.items())
        stable = stable and sha(swift.read_bytes()) == report['compilerSha256']
        stable = stable and all(sha((out / name).read_bytes()) == value for name, value in report['binaries'].items())
        report['sourceAndCompilerUnchanged'] = stable
        report['passed'] = len(report['cases']) == 24 and all(x['passed'] for x in report['cases']) and life_ok and stable
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        report['logSha256'] = {p.name: sha(p.read_bytes()) for p in out.iterdir()
                               if p.is_file() and p.suffix in ('.stdout', '.stderr', '.log')}
        target = out / 'report.json'
        target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(target), 'sha256': sha(target.read_bytes()), 'passed': report['passed'],
                      'socketCases': len(report['cases']), 'lifecycleCases': len(report['lifecycle'].get('cases', []))}))
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
