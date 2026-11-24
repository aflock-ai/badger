#!/usr/bin/env python3
# jade:ring local
"""The 2.0 managed binary's command surface, plugin handling and real TUI, under a network guard.

macOS local harness. No credentials, no model requests, no package downloads.
"""
import argparse
import json
from pathlib import Path
import tempfile

from managed_harness import (PRODUCT, REFUSED, VERSION, FixtureModel, Report, contains_fixture_model, files, network_guard_holds,
                             no_package_or_credential_files, private_env, require_macos, run, sha, terminal)

# Commands a managed build refuses: release management, services, credentials, plugins and raw server access.
REFUSALS = [['upgrade'], ['uninstall'], ['--print-logs', 'upgrade'], ['serve'], ['service', 'start'],
            ['auth', 'login'], ['auth', 'list'], ['plugin', 'add', 'testifysec-uat-unapproved-plugin@0.0.0'],
            ['mcp', 'add', 'fixture', '--url', 'http://127.0.0.1:9/mcp'], ['api', 'GET', '/config'],
            ['debug', 'paths'], ['pair'], ['enroll'], ['attest']]
AUTO = b'--auto, --yolo and --dangerously-skip-permissions are not available in this build\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path, help='darwin binary from build.ts --managed')
    parser.add_argument('--fixture-binary', required=True, type=Path,
                        help='the same build with --fixture-model; the TUI needs a model gateway to start')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    fixture_binary = args.fixture_binary.resolve(strict=True)
    report = Report('testifysec.badger.interactive-uat/v2', binary, __file__, releaseQualified=False,
                    fixtureBinarySha256=sha(fixture_binary),
                    modelRequestMade=False, liveCredentialsUsed=False,
                    limitations=['Only the macOS managed binary is exercised.',
                                 'No model is available to this build, so no session is run here.'])
    error = None
    try:
        require_macos()
        with tempfile.TemporaryDirectory(prefix='badger-interactive-uat-') as tmp:
            tmp = Path(tmp)
            workspace = tmp / 'workspace'; workspace.mkdir()
            env = private_env(tmp)
            report.check('harness-external-network-refused', network_guard_holds(env))

            result = run(binary, ['--help'], workspace, env)
            text = result.stdout.decode(errors='replace')
            report.check('help-names-badger', result.returncode == 0 and f'USAGE\n  {PRODUCT["command"]} <subcommand>' in text
                         and 'Badger command line interface' in text and 'opencode' not in text, output=text[-3000:])
            result = run(binary, ['--version'], workspace, env)
            report.check('version-is-product-version', result.returncode == 0
                         and result.stdout.decode().startswith(f'{PRODUCT["command"]} v{VERSION} (OpenCode '), output=result.stdout.decode(errors='replace'))

            # A refusal is one line on stderr and exit 1, and it leaves nothing behind but, at most, the CLI's own log.
            before = files(tmp)
            for argv in REFUSALS:
                result = run(binary, argv, workspace, env)
                # --print-logs asks for the CLI's log lines on stderr; the refusal is still the last line.
                clean = (result.stderr.endswith(REFUSED) and b'    at ' not in result.stderr if '--print-logs' in argv
                         else result.stderr == REFUSED)
                report.check('refuses-' + '-'.join(a for a in argv if not a.startswith('http')),
                             result.returncode == 1 and result.stdout == b'' and clean,
                             stderr=result.stderr.decode(errors='replace')[-500:])
            for flag in ['--auto', '--yolo', '--dangerously-skip-permissions']:
                result = run(binary, ['run', flag, 'hello'], workspace, env)
                report.check('refuses-' + flag.strip('-'), result.returncode == 1 and result.stdout == b'' and result.stderr == AUTO,
                             stderr=result.stderr.decode(errors='replace')[-500:])
            created = sorted(set(files(tmp)) - set(before))
            report.check('refusals-leave-at-most-the-cli-log', set(created) <= {'data/opencode/log/opencode.log'}, created=created)

            result = run(binary, ['models'], workspace, env)
            report.check('only-the-managed-model-is-listed', result.returncode == 0 and result.stdout == b'managed/approved\n',
                         output=result.stdout.decode(errors='replace'))

            # Plugins named in config, a local file and an npm package, are neither loaded nor installed.
            # Importing a module runs its top-level code, so loading is detected at import, not only on a call.
            imported, called = tmp / 'plugin-imported', tmp / 'plugin-called'
            plugin = tmp / 'fixture-plugin.mjs'
            plugin.write_text('import { writeFileSync } from "node:fs"\n'
                              f'writeFileSync({json.dumps(str(imported))}, "imported")\n'
                              f'export const Fixture = async () => {{ writeFileSync({json.dumps(str(called))}, "called"); return {{}} }}\n')
            plugin_env = dict(env, OPENCODE_CONFIG_CONTENT=json.dumps(
                {'plugin': [plugin.as_uri(), 'testifysec-uat-unapproved-plugin@0.0.0'], 'autoupdate': False}))
            # Without its gateway the release TUI does not start: it says where the gateway should be.
            code, plain, raw, ready, quit_sent = terminal(
                [str(binary)], workspace, env, lambda text: b'model gateway is not available' in text,
                args.report.with_suffix('.no-gateway.pty'))
            report.check('tui-refuses-without-its-gateway', ready and code != 0
                         and '/run/hardened-gateway/gateway.sock' in plain and 'Ask anything' not in plain)
            report.check('only-the-uat-build-carries-the-fixture-model',
                         contains_fixture_model(fixture_binary) and not contains_fixture_model(binary))
            model = FixtureModel()
            try:
                code, plain, raw, ready, quit_sent = terminal(
                    [str(fixture_binary)], workspace, plugin_env,
                    lambda text: b'Ask anything' in text and b'EAT THE WORK.' in text,
                    args.report.with_suffix('.pty'))
            finally:
                model.close()
            report.data['ptyExit'] = code
            report.check('real-tui-render-and-keyboard-exit', ready and quit_sent and code == 0)
            report.check('tui-names-the-product-gateway-and-model', PRODUCT['modelName'] in plain and PRODUCT['providerName'] in plain)
            report.check('config-plugins-not-loaded', not imported.exists() and not called.exists())
            report.check('no-package-or-credential-files', no_package_or_credential_files(tmp))
        report.check('binaries-and-harness-unchanged', sha(binary) == report.data['binarySha256']
                     and sha(fixture_binary) == report.data['fixtureBinarySha256'] and sha(__file__) == report.data['harnessSha256'])
    except Exception as caught:
        error = caught
    return report.finish(args.report, error)


if __name__ == '__main__':
    raise SystemExit(main())
