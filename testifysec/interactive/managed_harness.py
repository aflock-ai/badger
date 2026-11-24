# jade:ring local
"""Shared pieces of the interactive UAT harnesses for the 2.0 managed binary.

macOS only. The binary is built separately (`packages/cli/script/build.ts --managed`); each
harness takes it as `--binary` and never builds or modifies it. sandbox-exec here is a test guard
against external network access, not part of the product.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# Loopback and Unix sockets stay open: the binary's in-process server and the harness fixtures use them.
SANDBOX = ('(version 1)(allow default)(deny network*)'
           '(allow network-inbound (local ip "localhost:*"))(allow network-outbound (remote ip "localhost:*"))'
           '(allow network* (local unix))(allow network* (remote unix))')
GUARD = ['/usr/bin/sandbox-exec', '-p', SANDBOX]
ANSI = re.compile(rb'\x1b\[[0-?]*[ -/]*[@-~]')
REFUSED = b'This command is not available in this build\n'
VERSION = (ROOT / 'VERSION').read_text().strip()
PRODUCT = json.loads((ROOT / 'testifysec/branding/product.json').read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(root):
    """Every regular file under root, by relative path, with its digest."""
    return {str(p.relative_to(root)): sha(p) for p in Path(root).rglob('*') if p.is_file()}


def private_env(root, **extra):
    """A minimal environment whose home and XDG directories all sit under root."""
    root = Path(root)
    (root / 'home').mkdir(exist_ok=True)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'home'), 'TMPDIR': str(root), 'TERM': 'xterm-256color',
           'LANG': 'en_US.UTF-8', 'XDG_DATA_HOME': str(root / 'data'), 'XDG_CACHE_HOME': str(root / 'cache'),
           'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_STATE_HOME': str(root / 'state'),
           'OPENCODE_DISABLE_PROJECT_CONFIG': '1', 'OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER': '1'}
    env.update(extra)
    return env


class Report:
    """Collects checks; the first failure stops the harness. The report is written either way."""

    def __init__(self, schema, binary, harness, **fields):
        self.path = None
        self.data = {'schema': schema, 'passed': False, 'binarySha256': sha(binary), 'harnessSha256': sha(harness),
                     'sharedSha256': sha(__file__), 'productVersion': VERSION, 'checks': [], **fields}

    def check(self, name, condition, **evidence):
        self.data['checks'].append({'id': name, 'passed': bool(condition), **evidence})
        if not condition:
            raise RuntimeError(name)

    def finish(self, path, error=None):
        if error is None:
            self.data['passed'] = True
        else:
            self.data['error'] = type(error).__name__ + ': ' + str(error)
        Path(path).write_text(json.dumps(self.data, indent=2) + '\n')
        print(json.dumps({'passed': self.data['passed'], 'checks': len(self.data['checks']), 'report': str(path),
                          'error': self.data.get('error')}))
        return 0 if self.data['passed'] else 1


def require_macos():
    if platform.system() != 'Darwin':
        raise RuntimeError('These harnesses use macOS sandbox-exec and run the darwin managed binary.')


def network_guard_holds(env):
    """The guard refuses an external connection (a documentation-only address)."""
    probe = subprocess.run(GUARD + [sys.executable, '-c',
        'import socket\ns=socket.socket();s.settimeout(2)\ntry:s.connect(("192.0.2.1",80));print("unexpected")\nexcept OSError as e:print(e.errno)'],
        env=env, capture_output=True, timeout=10)
    return probe.returncode == 0 and probe.stdout.strip() in (b'1', b'13')


def run(binary, argv, cwd, env, timeout=30):
    # stdin is closed: `run` reads a non-terminal stdin as part of the prompt and would wait on an inherited one.
    return subprocess.run(GUARD + [str(binary)] + argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=timeout)


def terminal(argv, cwd, env, ready, transcript, deadline=40):
    """Runs argv on a 120x36 PTY until ready(plain text + window titles) holds, then sends Ctrl+C twice.

    Returns (exit code, plain text, raw bytes, ready, quit sent). The raw transcript is written to `transcript`.
    """
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 36, 120, 0, 0))
    process = subprocess.Popen(GUARD + argv, cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave,
                               start_new_session=True)
    os.close(slave)
    raw = bytearray(); seen = False; quit_sent = False
    end = time.monotonic() + deadline
    try:
        while time.monotonic() < end:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                raw.extend(chunk)
                if len(raw) > 4 << 20:
                    raise RuntimeError('terminal-output-bound')
                if b'\x1b[6n' in chunk:
                    os.write(master, b'\x1b[1;1R')
                if b'\x1b[c' in chunk or b'\x1b[0c' in chunk:
                    os.write(master, b'\x1b[?1;2c')
                titles = b' '.join(re.findall(rb'\x1b\]0;([^\x07]*)\x07', raw))
                seen = seen or ready(ANSI.sub(b'', raw) + b'\n' + titles)
            if seen and not quit_sent:
                os.write(master, b'\x03'); time.sleep(0.3); os.write(master, b'\x03')
                quit_sent = True
            if process.poll() is not None and not select.select([master], [], [], 0)[0]:
                break
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL); process.wait()
        os.close(master)
        Path(transcript).write_bytes(raw)
    return process.returncode, ANSI.sub(b'', raw).decode('utf-8', 'replace'), bytes(raw), seen, quit_sent


def no_package_or_credential_files(root):
    root = Path(root)
    return not any(list(root.rglob(name)) for name in ('node_modules', 'package-lock.json', 'auth.json'))


FIXTURE_SOCKET = '/tmp/hardened-fixture-model.sock'


class FixtureModel:
    """The UAT fixture model a `--fixture-model` build reaches instead of the gateway: OpenAI Chat Completions over
    FIXTURE_SOCKET, answering every request with one short streamed reply. Records what each request carried."""

    def __init__(self, reply='Managed verification'):
        import http.server
        import socketserver
        import threading
        self.requests = []
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def address_string(self):
                return 'unix'

            def log_message(self, *args):
                pass

            def body(self):
                if 'chunked' not in self.headers.get('Transfer-Encoding', '').lower():
                    return self.rfile.read(int(self.headers.get('Content-Length', '0')))
                data = b''
                while True:
                    size = int(self.rfile.readline().split(b';')[0].strip() or b'0', 16)
                    if size == 0:
                        self.rfile.readline()
                        return data
                    data += self.rfile.read(size)
                    self.rfile.readline()

            def do_POST(self):
                body = json.loads(self.body())
                fixture.requests.append({'path': self.path, 'model': body.get('model'), 'headers': dict(self.headers),
                                         'tools': [tool['function']['name'] for tool in body.get('tools', [])]})
                chunk = lambda delta, finish=None: {'id': 'fixture', 'object': 'chat.completion.chunk', 'created': 1,
                                                    'model': 'approved', 'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish}]}
                events = [chunk({'role': 'assistant', 'content': reply}), chunk({}, 'stop')]
                raw = (''.join('data: ' + json.dumps(event) + '\n\n' for event in events) + 'data: [DONE]\n\n').encode()
                self.send_response(200)
                self.send_header('content-type', 'text/event-stream')
                self.send_header('content-length', str(len(raw)))
                self.send_header('connection', 'close')
                self.end_headers()
                self.wfile.write(raw)
                self.close_connection = True

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        if os.path.exists(FIXTURE_SOCKET):
            raise RuntimeError(FIXTURE_SOCKET + ' already exists; another fixture model is running')
        self.server = Server(FIXTURE_SOCKET, Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        if os.path.exists(FIXTURE_SOCKET):
            os.unlink(FIXTURE_SOCKET)


def contains_fixture_model(binary):
    return FIXTURE_SOCKET.encode() in Path(binary).read_bytes()
