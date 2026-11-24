#!/usr/bin/env python3
"""Offline compiled enrollment checks; never completes a platform ceremony."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    binary=args.binary.resolve()
    before=digest(binary)
    checks=[]
    def check(name,value):
        checks.append({'name':name,'passed':bool(value)})
        if not value:
            raise AssertionError(name)
    with tempfile.TemporaryDirectory(prefix='hc-enroll-uat-') as scratch:
        base=Path(scratch).resolve()
        base.chmod(0o700)
        env={'HOME':str(base),'PATH':'/usr/bin:/bin','HTTPS_PROXY':'http://127.0.0.1:1','CILOCK_STATE_DIR':str(base/'ambient'), 'JUDGE_SHARED_SESSION':'true'}
        req={'schema':'testifysec.hardened-code.enroll/v1','trustMode':'local-self-signed','stateDirectory':str(base)}
        def run(value,argv=('enroll',)):
            return subprocess.run([str(binary),*argv],input=value if isinstance(value,str) else json.dumps(value),text=True,capture_output=True,env=env,timeout=15)
        first=run(req)
        check('compiled-local-enrollment-succeeds',first.returncode==0)
        events=[json.loads(line) for line in first.stdout.splitlines()]
        check('one-public-result',len(events)==1 and events[0]['event']=='enrolled' and events[0]['schema']=='testifysec.hardened-code.command-event/v1')
        result=events[0]
        check('explicit-local-untrusted-without-platform-authority',result['trustMode']=='local-self-signed' and result['assurance']=='local-self-signed-untrusted' and not any(key in result for key in ('spiffeID','tenantID','agentID','platformURL')))
        state=base/'local-self-signed'
        check('fixed-mode-child',result['stateDirectory']==str(state))
        snapshot={name:digest(state/name) for name in ('identity-key.pem','identity-public.pem','local-identity.json')}
        check('private-stored-files',all((state/name).stat().st_mode&0o777==0o600 for name in snapshot))
        check('no-secret-or-pem-output','PRIVATE KEY' not in first.stdout+first.stderr and 'refresh_credential' not in first.stdout+first.stderr)
        check('no-platform-or-ambient-store-created',not (base/'platform').exists() and not (base/'ambient').exists())
        second=run(req)
        check('repeated-local-enroll-preserves-identity',second.returncode==0 and json.loads(second.stdout)==result and snapshot=={name:digest(state/name) for name in snapshot})
        pem=(state/'identity-public.pem').read_text()
        import base64
        der=base64.b64decode(''.join(pem.splitlines()[1:-1]),validate=True)
        check('identity-is-derived-from-public-SPKI',hashlib.sha256(der).hexdigest()==result['publicKeySha256'] and result['identityReference']=='urn:testifysec:local-self-signed:sha256:'+result['publicKeySha256'])
        cases={
            'invalid-trust-mode':{**req,'trustMode':'INSECURE_SELFSIGNED'},
            'empty-explicit-mode':{**req,'trustMode':''},
            'local-rejects-platform-scope':{**req,'platformURL':'https://platform.testifysec.com'},
            'local-rejects-lifetime':{**req,'ttlSeconds':900},
            'case-alias':{**req,'TrustMode':'platform'},
            'unknown-field':{**req,'credential':'synthetic-never-used'},
            'null-mode':{**req,'trustMode':None},
            'duplicate-mode':json.dumps(req)[:-1]+',"trustMode":"platform"}',
            'escaped-duplicate-mode':json.dumps(req)[:-1]+',"trust\\u004dode":"platform"}',
            'trailing-JSON':json.dumps(req)+' {}',
            'oversized-input':' '*16385,
            'noncanonical-state':{**req,'stateDirectory':str(base)+'/.'},
            'cleartext-platform':{**req,'trustMode':'platform','platformURL':'http://127.0.0.1'},
            'platform-userinfo':{**req,'trustMode':'platform','platformURL':'https://name:secret@platform.testifysec.com'},
        }
        for name,value in cases.items():
            refused=run(value)
            check(name,refused.returncode==2 and len(refused.stdout.splitlines())==1 and json.loads(refused.stdout)['event']=='error' and json.loads(refused.stdout)['code']=='enrollment-refused' and not refused.stderr)
        refused=run(req,('enroll','--preload'))
        check('arbitrary-runtime-argv-refused',refused.returncode==2)
        check('all-refusals-preserve-existing-local-key',snapshot=={name:digest(state/name) for name in snapshot})
        (state/'identity-key.pem').chmod(0o644)
        check('unsafe-private-key-mode-refused',run(req).returncode==2)
        (state/'identity-key.pem').chmod(0o600)
        metadata=state/'local-identity.json'
        original=metadata.read_bytes()
        data=json.loads(original);data['publicKeySha256']='0'*64;metadata.write_text(json.dumps(data))
        check('metadata-cannot-forge-key-identity',run(req).returncode==2)
        metadata.write_bytes(original)
        check('untampered-identity-still-loads',run(req).returncode==0)
    check('native-executable-path-readback-unchanged',digest(binary)==before)
    report={'schema':'testifysec.hardened-code.enrollment-uat/v1','passed':True,'checks':checks,'binarySha256':before,'harnessSha256':digest(HERE/'uat.py'),'scope':'actual compiled local enrollment; canonical Go tests separately exercise real sealed loopback; no platform human ceremony, live enrollment, release qualification or Windows runtime claim'}
    args.report.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'passed':True,'checks':len(checks),'report':str(args.report)}))

if __name__=='__main__':
    main()
