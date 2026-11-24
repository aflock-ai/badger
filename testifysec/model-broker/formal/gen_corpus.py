"""Generate the shared decision corpus and its Lean check.

    python3 formal/gen_corpus.py          # writes testdata/decisions.json, formal/BadgerBroker/Corpus.lean
    python3 formal/gen_corpus.py --check  # exit 1 if either file is out of date

The answers are recorded from mirror.py. `lake build` then proves every one of them against the
Lean definition (`by decide`), and policy_test.go checks the Go implementation against the same
file, so Lean, Python and Go agree on every case or something fails.
"""
import itertools
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import mirror

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / 'testdata' / 'decisions.json'
LEAN = ROOT / 'formal' / 'BadgerBroker' / 'Corpus.lean'

NOW = 1_800_000_000          # 2027-01-15T08:00:00Z
DAY = 86_400
OPERATOR = {
    'issuer': 'https://gitlab.example.com', 'audience': 'badger-broker',
    'ci_config_ref_template': 'gitlab.example.com/{project_path}//.gitlab-ci.yml@refs/heads/{ref}',
    'routed_models': ['model-a', 'model-b'], 'sources': ['web', 'push', 'schedule'],
    'admin_roles': ['superAdmin'], 'two_person_rule': True, 'max_named_ttl': 14 * DAY,
}
ALPHA, BETA, GAMMA = 'group/alpha', 'group/sub/beta', 'group/gamma'
ENTRIES = [
    {'id': 'alpha', 'kind': 'protected_branch', 'project_path': ALPHA, 'ref': 'main', 'sources': ['web'],
     'models': ['model-a'], 'trigger_users': [], 'expires_at': None, 'minted_before': None, 'enabled': True},
    {'id': 'beta', 'kind': 'protected_branch', 'project_path': BETA, 'ref': 'stable',
     'sources': ['schedule', 'web'], 'models': ['model-b'], 'trigger_users': [], 'expires_at': None, 'minted_before': None, 'enabled': True},
    {'id': 'beta-feature', 'kind': 'named_branch', 'project_path': BETA, 'ref': 'feat/x-1', 'sources': ['web'],
     'models': ['model-b'], 'trigger_users': ['alice', 'bob'], 'expires_at': NOW + 7 * DAY,
     'minted_before': NOW - 300, 'enabled': True},
    {'id': 'gamma', 'kind': 'protected_branch', 'project_path': GAMMA, 'ref': 'main', 'sources': ['web'],
     'models': ['model-a'], 'trigger_users': [], 'expires_at': None, 'minted_before': None, 'enabled': False},
]


def claims_for(project, ref, **over):
    c = {'iss': OPERATOR['issuer'], 'aud': OPERATOR['audience'], 'exp': NOW + 3000, 'iat': NOW - 600,
         'project_path': project, 'ref': ref, 'ref_type': 'branch', 'ref_protected': 'true',
         'pipeline_source': 'web', 'ci_config_ref_uri': mirror.config_ref(OPERATOR, project, ref),
         'user_login': 'alice', 'namespace_path': project.rsplit('/', 1)[0]}
    c.update(over)
    return {k: v for k, v in c.items() if v is not DROP}


DROP = object()
TOKENS = {
    'alpha': claims_for(ALPHA, 'main'),
    'alpha-other-user': claims_for(ALPHA, 'main', user_login='mallory'),
    'alpha-no-user': claims_for(ALPHA, 'main', user_login=DROP),
    'alpha-unprotected': claims_for(ALPHA, 'main', ref_protected='false'),
    'alpha-bool-protected': claims_for(ALPHA, 'main', ref_protected=True),
    'alpha-no-protected': claims_for(ALPHA, 'main', ref_protected=DROP),
    'alpha-tag': claims_for(ALPHA, 'main', ref_type='tag'),
    'alpha-other-branch': claims_for(ALPHA, 'dev', ci_config_ref_uri=mirror.config_ref(OPERATOR, ALPHA, 'dev')),
    'alpha-push': claims_for(ALPHA, 'main', pipeline_source='push'),
    'alpha-mr': claims_for(ALPHA, 'refs/merge-requests/7/head', ref_protected='false',
                           pipeline_source='merge_request_event'),
    'alpha-foreign-config': claims_for(ALPHA, 'main', ci_config_ref_uri='gitlab.example.com/x/y//ci.yml@refs/heads/main'),
    'alpha-expired': claims_for(ALPHA, 'main', exp=NOW),
    'alpha-wrong-iss': claims_for(ALPHA, 'main', iss='https://gitlab.com'),
    'alpha-wrong-aud': claims_for(ALPHA, 'main', aud='someone-else'),
    'alpha-list-aud': claims_for(ALPHA, 'main', aud=[OPERATOR['audience']]),
    'alpha-float-exp': claims_for(ALPHA, 'main', exp=float(NOW + 3000)),
    'alpha-string-exp': claims_for(ALPHA, 'main', exp=str(NOW + 3000)),
    'alpha-no-project': claims_for(ALPHA, 'main', project_path=DROP),
    'beta-schedule': claims_for(BETA, 'stable', pipeline_source='schedule', user_login=DROP),
    'beta-web': claims_for(BETA, 'stable'),
    'beta-push': claims_for(BETA, 'stable', pipeline_source='push'),
    'beta-unprotected': claims_for(BETA, 'stable', ref_protected='false'),
    'feature-alice': claims_for(BETA, 'feat/x-1', ref_protected='false'),
    'feature-bob': claims_for(BETA, 'feat/x-1', ref_protected='false', user_login='bob'),
    'feature-protected': claims_for(BETA, 'feat/x-1'),
    'feature-mallory': claims_for(BETA, 'feat/x-1', ref_protected='false', user_login='mallory'),
    'feature-no-user': claims_for(BETA, 'feat/x-1', ref_protected='false', user_login=DROP),
    'feature-minted-late': claims_for(BETA, 'feat/x-1', ref_protected='false', iat=NOW - 300),
    'feature-no-iat': claims_for(BETA, 'feat/x-1', ref_protected='false', iat=DROP),
    'feature-schedule': claims_for(BETA, 'feat/x-1', ref_protected='false', pipeline_source='schedule'),
    'feature-other-branch': claims_for(BETA, 'feat/x-2', ref_protected='false',
                                       ci_config_ref_uri=mirror.config_ref(OPERATOR, BETA, 'feat/x-2')),
    'feature-stable-config': claims_for(BETA, 'feat/x-1', ref_protected='false',
                                        ci_config_ref_uri=mirror.config_ref(OPERATOR, BETA, 'stable')),
    'gamma-disabled': claims_for(GAMMA, 'main'),
    'unlisted': claims_for('group/other', 'main'),
    'principal-lookalike': claims_for('ci:group/alpha', 'main'),
    'not-json': '{"iss":',
    'not-object': '[1,2]',
}
OPS = ('chat', 'other')
MODELS = (None, 'model-a', 'model-b', 'model-z')
NOWS = {'now': NOW, 'after-feature-expiry': NOW + 7 * DAY, 'way-later': NOW + 2 * 3600}


def cases():
    for (name, token), op, model, (when, now) in itertools.product(TOKENS.items(), OPS, MODELS, NOWS.items()):
        if op == 'other' and model not in (None, 'model-a'):
            continue
        raw = token if isinstance(token, str) else json.dumps(token, sort_keys=True)
        c = mirror.parse_claims(raw)
        if c is not None and when == 'after-feature-expiry' and name != 'alpha-expired':
            # Keep the token alive past the entry's expiry so only the entry's expiry decides.
            raw = json.dumps({**json.loads(raw), 'exp': now + 3000}, sort_keys=True)  # iat unchanged
            c = mirror.parse_claims(raw)
        yield {'name': f'{name}/{op}/{model}/{when}', 'payload': raw, 'now': now, 'op': op, 'model': model,
               'want': list(mirror.evaluate(OPERATOR, ENTRIES, now, c, op, model))}
    for op in OPS:
        yield {'name': f'no-policy/{op}', 'payload': json.dumps(TOKENS['alpha'], sort_keys=True), 'now': NOW,
               'op': op, 'model': 'model-a', 'no_policy': True,
               'want': list(mirror.evaluate(OPERATOR, None, NOW, mirror.parse_claims(json.dumps(TOKENS['alpha'])),
                                            op, 'model-a'))}


def iso(t):
    return None if t is None else datetime.fromtimestamp(t, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


VALIDITY = [  # (name, entries, write time) on model-level rules only; Go adds syntax rules on top
    ('policy', ENTRIES, NOW),
    ('named-without-users', [{**ENTRIES[2], 'trigger_users': []}], NOW),
    ('named-without-expiry', [{**ENTRIES[2], 'expires_at': None}], NOW),
    ('named-over-ttl', [{**ENTRIES[2], 'expires_at': NOW + 15 * DAY}], NOW),
    ('named-at-ttl', [{**ENTRIES[2], 'expires_at': NOW + 14 * DAY}], NOW),
    ('unrouted-model', [{**ENTRIES[0], 'models': ['model-z']}], NOW),
    ('unknown-source', [{**ENTRIES[0], 'sources': ['merge_request_event']}], NOW),
    ('no-models', [{**ENTRIES[0], 'models': []}], NOW),
    ('two-protected-same-project', [ENTRIES[0], {**ENTRIES[0], 'id': 'alpha-2', 'ref': 'dev'}], NOW),
    ('protected-and-named-same-ref', [ENTRIES[0], {**ENTRIES[2], 'project_path': ALPHA, 'ref': 'main'}], NOW),
    ('duplicate-id', [ENTRIES[0], {**ENTRIES[1], 'id': 'alpha'}], NOW),
    ('protected-with-users', [{**ENTRIES[0], 'trigger_users': ['alice']}], NOW),
]


def corpus():
    entries = [{**e, 'expires_at': iso(e['expires_at']), 'minted_before': iso(e['minted_before'])} for e in ENTRIES]
    operator = {k: v for k, v in OPERATOR.items() if k != 'max_named_ttl'}
    operator['max_named_branch_ttl_seconds'] = OPERATOR['max_named_ttl']
    return {
        'comment': 'Generated by formal/gen_corpus.py from formal/mirror.py; proved in Lean by Corpus.lean. Do not edit.',
        'operator': operator, 'entries': entries,
        'cases': list(cases()),
        'validity': [{'name': n, 'now': t, 'entries': [{**e, 'expires_at': iso(e['expires_at']),
                                                          'minted_before': iso(e['minted_before'])} for e in es],
                      'well_formed': mirror.well_formed(OPERATOR, t, es)} for n, es, t in VALIDITY],
    }


# ---- Lean ----------------------------------------------------------------------------------

def lstr(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def llist(xs):
    return '[' + ', '.join(lstr(x) for x in xs) + ']'


def lentry(e):
    kind = '.protectedBranch' if e['kind'] == 'protected_branch' else '.namedBranch'
    exp = 'none' if e['expires_at'] is None else f"some {e['expires_at']}"
    minted = 'none' if e['minted_before'] is None else f"some {e['minted_before']}"
    return (f"{{ id := {lstr(e['id'])}, kind := {kind}, projectPath := {lstr(e['project_path'])}, "
            f"ref := {lstr(e['ref'])}, sources := {llist(e['sources'])}, models := {llist(e['models'])}, "
            f"triggerUsers := {llist(e['trigger_users'])}, expiresAt := {exp}, mintedBefore := {minted}, enabled := {str(e['enabled']).lower()} }}")


def lclaims(c):
    aud = f"(.one {lstr(c['aud'][1])})" if c['aud'][0] == 'one' else f"(.many {llist(c['aud'][1])})"
    return (f"{{ iss := {lstr(c['iss'])}, aud := {aud}, exp := {c['exp']}, iat := {c['iat']}, projectPath := {lstr(c['project_path'])}, "
            f"ref := {lstr(c['ref'])}, refType := {lstr(c['ref_type'])}, refProtected := {lstr(c['ref_protected'])}, "
            f"pipelineSource := {lstr(c['pipeline_source'])}, ciConfigRefUri := {lstr(c['ci_config_ref_uri'])}, "
            f"userLogin := {lstr(c['user_login'])} }}")


REASON_LEAN = {'no_policy': 'noPolicy', 'bad_claims': 'badClaims', 'wrong_issuer': 'wrongIssuer',
               'wrong_audience': 'wrongAudience', 'token_expired': 'tokenExpired',
               'wrong_operation': 'wrongOperation', 'no_match': 'noMatch', 'model_missing': 'modelMissing',
               'model_not_allowed': 'modelNotAllowed'}


def ldecision(want):
    if want[0] == 'deny':
        return f'.deny .{REASON_LEAN[want[1]]}'
    _, principal, entry_id, model = want
    e = next(e for e in ENTRIES if e['id'] == entry_id)
    branch = f"(some {lstr(e['ref'])})" if e['kind'] == 'named_branch' else 'none'
    assert mirror.principal(e) == principal
    return f".allow (.ci {lstr(e['project_path'])} {branch}) {lstr(entry_id)} {lstr(model)}"


def lean(data):
    t = OPERATOR['ci_config_ref_template']
    pre, rest = t.split('{project_path}')
    mid, post = rest.split('{ref}')
    out = ['-- Generated by formal/gen_corpus.py. Do not edit; regenerate and rebuild.',
           'import BadgerBroker.BrokerPolicy', '', 'namespace BadgerBroker.Corpus', '',
           'def op : OperatorCfg where',
           f"  issuer := {lstr(OPERATOR['issuer'])}", f"  audience := {lstr(OPERATOR['audience'])}",
           f'  configRef := fun p r => {lstr(pre)} ++ p ++ {lstr(mid)} ++ r ++ {lstr(post)}',
           f"  routedModels := {llist(OPERATOR['routed_models'])}", f"  sources := {llist(OPERATOR['sources'])}",
           f"  adminRoles := {llist(OPERATOR['admin_roles'])}", '  twoPerson := true',
           f"  maxNamedTtl := {OPERATOR['max_named_ttl']}", '',
           'def entries : List Entry := [', ',\n'.join('  ' + lentry(e) for e in ENTRIES), ']', '']
    claims = {}
    for i, case in enumerate(data['cases']):
        c = mirror.parse_claims(case['payload'])
        if c is None:
            cl = 'none'
        else:
            key = json.dumps(c, sort_keys=True)
            if key not in claims:
                claims[key] = f'c{len(claims)}'
                out.append(f'def {claims[key]} : Claims := {lclaims(c)}')
            cl = f'(some {claims[key]})'
        pol = 'none' if case.get('no_policy') else '(some entries)'
        model = 'none' if case['model'] is None else f"(some {lstr(case['model'])})"
        out.append(f"/-- {case['name']} -/\ntheorem case_{i} : evaluate op {pol} {case['now']} {cl} .{case['op']} {model} = "
                   f"{ldecision(case['want'])} := by decide")
    for i, v in enumerate(VALIDITY):
        name, es, t = v
        expect = 'wellFormed' if mirror.well_formed(OPERATOR, t, es) else '¬ wellFormed'
        out.append(f'/-- validity: {name} -/\ntheorem valid_{i} : {expect} op {t} '
                   f"[{', '.join(lentry(e) for e in es)}] := by decide")
    out += ['', 'end BadgerBroker.Corpus', '']
    return '\n'.join(out)


def main():
    data = corpus()
    text = json.dumps(data, indent=1, sort_keys=True) + '\n'
    lean_text = lean(data)
    if '--check' in sys.argv:
        stale = [p for p, t in ((CORPUS, text), (LEAN, lean_text)) if not p.exists() or p.read_text() != t]
        if stale:
            print('out of date:', *stale)
            sys.exit(1)
        print(f"corpus up to date: {len(data['cases'])} cases, {len(data['validity'])} validity checks")
        return
    CORPUS.parent.mkdir(exist_ok=True)
    CORPUS.write_text(text)
    LEAN.write_text(lean_text)
    print(f"wrote {len(data['cases'])} cases, {len(data['validity'])} validity checks")


if __name__ == '__main__':
    main()
