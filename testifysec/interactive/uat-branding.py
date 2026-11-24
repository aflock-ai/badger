#!/usr/bin/env python3
# jade:ring local
"""What the 2.0 managed binary shows: command name, version, about text and the real TUI home screen.

macOS local harness under a network guard; private state only.
"""
import argparse
from pathlib import Path
import re
import tempfile

from managed_harness import (PRODUCT, ROOT, VERSION, FixtureModel, Report, contains_fixture_model, network_guard_holds,
                             private_env, require_macos, run, sha, terminal)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path, help='darwin binary from build.ts --managed')
    parser.add_argument('--fixture-binary', required=True, type=Path,
                        help='the same build with --fixture-model, used only for the session checks')
    parser.add_argument('--output-directory', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    fixture_binary = args.fixture_binary.resolve(strict=True)
    output = args.output_directory.absolute()
    output.mkdir(mode=0o700)
    report = Report('testifysec.badger.interactive-branding-uat/v2', binary, __file__, liveCredentialsUsed=False,
                    fixtureBinarySha256=sha(fixture_binary))
    error = None
    try:
        require_macos()
        # A quote and a space in the path: nothing below may depend on a tidy one.
        with tempfile.TemporaryDirectory(prefix="badger-branding quote's-") as private:
            private = Path(private)
            workspace = private / 'workspace'; workspace.mkdir()
            env = private_env(private)
            report.check('test-guard-denies-external-network', network_guard_holds(env))

            for name, argv in [('help', ['--help']), ('version', ['--version']), ('about', ['about'])]:
                result = run(binary, argv, workspace, env)
                (output / (name + '.txt')).write_bytes(result.stdout + result.stderr)
                report.check(name + '-exits-cleanly', result.returncode == 0 and result.stderr == b'')
            text = (output / 'help.txt').read_text()
            report.check('help-names-the-command-and-product', f'USAGE\n  {PRODUCT["command"]} ' in text
                         and 'Badger command line interface' in text and 'Directory to start Badger in' in text)
            report.check('version-shows-product-and-upstream',
                         (output / 'version.txt').read_text().startswith(f'{PRODUCT["command"]} v{VERSION} (OpenCode '))
            about = (output / 'about.txt').read_bytes()
            report.check('about-names-product-version-and-attribution', about.startswith(
                f'{PRODUCT["name"]} {VERSION}\nOpenCode '.encode()) and PRODUCT['attribution'].encode() in about)
            report.check('about-preserves-exact-upstream-license', (ROOT / 'LICENSE').read_bytes() in about)

            # The TUI needs its gateway to start, so the screens below run the UAT build against the fixture model.
            model = FixtureModel()
            try:
                code, plain, raw, ready, quit_sent = terminal(
                    [str(fixture_binary)], workspace, env,
                    lambda text: b'Ask anything' in text and b'EAT THE WORK.' in text and VERSION.encode() in text,
                    output / 'home.pty')
            finally:
                model.close()
            report.check('home-actual-render-and-keyboard-exit', ready and quit_sent and code == 0)
            report.check('window-title-is-the-product', b'\x1b]0;' + PRODUCT['name'].encode() + b'\x07' in raw)
            report.check('home-shows-badger-welcome-art', 'EAT THE WORK.' in plain and '▀' in plain)
            report.check('home-footer-shows-product-version', VERSION in plain)
            report.check('home-never-names-opencode', 'OpenCode' not in plain and 'opencode -s' not in plain)

            # A session needs a model. The UAT build reaches the fixture model; the release binary must not contain it.
            report.check('only-the-uat-build-carries-the-fixture-model',
                         contains_fixture_model(fixture_binary) and not contains_fixture_model(binary))
            model = FixtureModel()
            try:
                result = run(fixture_binary, ['run', 'Branding synthetic session'], workspace, env, timeout=60)
                report.check('fixture-session-runs', result.returncode == 0 and result.stdout == b'Managed verification\n')
                listing = run(fixture_binary, ['session', 'list'], workspace, env).stdout.decode()
                sessions = re.findall(r'^(ses_\w+)\t([^\t]+)\t', listing, re.M)
                report.check('one-session-recorded', len(sessions) == 1, listing=listing)
                session, title = sessions[0]
                code, plain, raw, ready, quit_sent = terminal(
                    [str(fixture_binary), '-s', session], workspace, env,
                    lambda text: b'Branding synthetic session' in text and b'Build' in text, output / 'session.pty')
                report.check('session-actual-render-and-keyboard-exit', ready and quit_sent and code == 0)
                match = re.search(r"Continue\s+('[^\r\n]+' -s '" + session + "')", plain)
                report.check('exit-prints-badger-resume-command', match is not None and PRODUCT['name'] in plain
                             and f'Session   {title}' in plain and 'opencode -s ' not in plain,
                             tail=plain[-600:])
                resume = match.group(1)
                report.check('resume-command-names-this-binary-and-session',
                             resume == f"'{fixture_binary}' -s '{session}'")
                elsewhere = private / 'elsewhere'; elsewhere.mkdir()
                code, resumed, raw, ready, quit_sent = terminal(
                    ['/bin/sh', '-c', resume], elsewhere, env,
                    lambda text: b'Branding synthetic session' in text and b'Build' in text, output / 'resume.pty')
                report.check('resume-command-reopens-the-same-session', ready and quit_sent and code == 0
                             and f"-s '{session}'" in resumed)
            finally:
                model.close()
        report.check('binaries-and-harness-unchanged', sha(binary) == report.data['binarySha256']
                     and sha(fixture_binary) == report.data['fixtureBinarySha256'] and sha(__file__) == report.data['harnessSha256'])
    except Exception as caught:
        error = caught
    return report.finish(output / 'report.json', error)


if __name__ == '__main__':
    raise SystemExit(main())
