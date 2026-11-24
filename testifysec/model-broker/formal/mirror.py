"""BrokerPolicy.lean transcribed to Python, plus the claim parser from policy.go.

Used by gen_corpus.py to record answers that Lean (Corpus.lean, by `decide`) and Go
(policy_test.go) must both reproduce, and by deployments that cross-check their edge against the
broker (a deployment can import it). Keep in step with the Lean definitions of the same
names. Times are unix seconds.
"""
import json
import math

REASONS = ('no_policy', 'bad_claims', 'wrong_issuer', 'wrong_audience', 'token_expired',
           'wrong_operation', 'no_match', 'model_missing', 'model_not_allowed')


def parse_claims(raw):
    """policy.go ParseClaims: a dict of Lean `Claims` fields, or None."""
    try:
        m = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except ValueError:
        return None
    if not isinstance(m, dict):
        return None
    out = {}
    for name, required in (('iss', True), ('project_path', True), ('ref', True), ('ref_type', True),
                           ('pipeline_source', True), ('ci_config_ref_uri', True),
                           ('ref_protected', False), ('user_login', False)):
        if name not in m:
            if required:
                return None
            out[name] = ''
        elif isinstance(m[name], str):
            out[name] = m[name]
        else:
            return None
    aud = m.get('aud')
    if isinstance(aud, str):
        out['aud'] = ('one', aud)
    elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
        out['aud'] = ('many', tuple(aud))
    else:
        return None
    for name in ('exp', 'iat'):
        v = m.get(name)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None
        if isinstance(v, float) and (v != math.trunc(v) or v < 0 or v > 2 ** 53):
            return None
        out[name] = int(v)
    return out


def config_ref(o, project, ref):
    return o['ci_config_ref_template'].replace('{project_path}', project).replace('{ref}', ref)


def principal(e):
    """Entry.principal rendered (Principal.render)."""
    if e['kind'] == 'named_branch':
        return f"ci:{e['project_path']}@{e['ref']}"
    return f"ci:{e['project_path']}"


def not_expired(now, e):
    return e.get('expires_at') is None or now < e['expires_at']


def entry_matches(o, now, c, e):
    return (e['enabled'] and not_expired(now, e) and c['project_path'] == e['project_path']
            and c['ref'] == e['ref'] and c['ref_type'] == 'branch'
            and c['ref_protected'] == ('true' if e['kind'] == 'protected_branch' else 'false')
            and c['ci_config_ref_uri'] == config_ref(o, e['project_path'], e['ref'])
            and c['pipeline_source'] in e['sources']
            and (not e['trigger_users'] or c['user_login'] in e['trigger_users'])
            and (e.get('minted_before') is None or c['iat'] < e['minted_before']))


def evaluate(o, entries, now, c, op, model):
    """Lean `evaluate`: ('allow', principal, entry_id, model) or ('deny', reason)."""
    if entries is None:
        return ('deny', 'no_policy')
    if c is None:
        return ('deny', 'bad_claims')
    if c['iss'] != o['issuer']:
        return ('deny', 'wrong_issuer')
    if c['aud'] != ('one', o['audience']):
        return ('deny', 'wrong_audience')
    if not now < c['exp']:
        return ('deny', 'token_expired')
    if op != 'chat':
        return ('deny', 'wrong_operation')
    e = next((e for e in entries if entry_matches(o, now, c, e)), None)
    if e is None:
        return ('deny', 'no_match')
    if model is None:
        return ('deny', 'model_missing')
    if model in e['models'] and model in o['routed_models']:
        return ('allow', principal(e), e['id'], model)
    return ('deny', 'model_not_allowed')


def entry_ok(o, now, e):
    """Lean `entryOk`. expires_at is unix seconds or None."""
    ok = ('@' not in e['project_path'] and '@' not in e['ref'] and e['project_path'] != '' and e['ref'] != ''
          and e['sources'] and all(s in o['sources'] for s in e['sources'])
          and e['models'] and all(m in o['routed_models'] for m in e['models'])
          and '' not in e['trigger_users'])
    if not ok:
        return False
    if e['kind'] == 'named_branch':
        return bool(e['trigger_users']) and e.get('expires_at') is not None \
            and e['expires_at'] <= now + o['max_named_ttl']
    return True


def well_formed(o, now, entries):
    """Lean `wellFormed`."""
    def nodup(xs):
        return len(xs) == len(set(xs))
    return (all(entry_ok(o, now, e) for e in entries) and nodup([e['id'] for e in entries])
            and nodup([principal(e) for e in entries])
            and nodup([(e['project_path'], e['ref']) for e in entries]))

