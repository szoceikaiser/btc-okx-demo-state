"""Static workflow entry. No capsule pin is embedded in workflow bytes."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from bounded_http import Budget,Wire,PublicError,strict_json,canonical
from exact_git import TARGET,REPOSITORY_ID,ExactGit,sha

PUBLIC_FILES=('.github/workflows/okx-demo.yml','bounded_http.py','exact_git.py','bootstrap_fetch.py',
    'private_envelope.py','private_capsule.py','public_status.py','child_runner.py','launch_runtime.py',
    'dependency_install.py','requirements.lock','wheels.lock.json','README.md','.gitattributes','.gitignore')

def fetch_public(git):
    git.root();raw=git.blob('PUBLIC-MANIFEST.json',32768);m=strict_json(raw)
    if (canonical(m)!=raw or set(m)!={'schema','repository','repository_id','store_id','runtime_review_sha256','capsule','capsule_class','files','deployment_reviewed','execution_enabled','allow_demo_writes','first_demo_close_ms','close_ms','trust','workflow_id','code_commit','runner_evidence'}
            or m['schema']!='public-encrypted-demo-v1' or m['repository']!=TARGET
            or type(m['repository_id']) is not int or m['repository_id']!=REPOSITORY_ID
            or set(m['files'])!=set(PUBLIC_FILES)
            or any(m[n] is not False for n in ('deployment_reviewed','execution_enabled','allow_demo_writes'))
            or any(m[n] is not None for n in ('first_demo_close_ms','close_ms','trust','workflow_id','code_commit','runner_evidence'))):raise PublicError('public_manifest_invalid')
    files={}
    for n in PUBLIC_FILES:
        b=git.blob(n)
        if m['files'][n]!=dict(bytes=len(b),sha256=sha(b)):raise PublicError('public_member_pin')
        files[n]=b
    if m['capsule'] is not None:
        pin=m['capsule']
        if not isinstance(pin,dict) or set(pin)!={'bytes','sha256'} or type(pin['bytes']) is not int or not 36<pin['bytes']<=2*1024*1024+36:raise PublicError('public_capsule_size')
        b=git.blob('runtime.capsule',2*1024*1024+36)
        if pin!=dict(bytes=len(b),sha256=sha(b)):raise PublicError('public_capsule_pin')
        files['runtime.capsule']=b
    else:
        if m['store_id'] is not None or m['runtime_review_sha256'] is not None or m['capsule_class']!='UNBOUND_NO_CAPSULE':raise PublicError('public_unbound_invalid')
    # Reject extra committed root paths, including concealed plaintext copies.
    expected={n.split('/')[0] for n in files}|{'PUBLIC-MANIFEST.json'}
    if set(git.rows(git.tree))!=expected:raise PublicError('public_extra_root_member')
    for directory in ('.github','.github/workflows'):
        obj=git.tree
        for part in directory.split('/'):obj=git.rows(obj)[part]['sha']
        allowed={'workflows'} if directory=='.github' else {'okx-demo.yml'}
        if set(git.rows(obj))!=allowed:raise PublicError('public_extra_workflow_member')
    files['PUBLIC-MANIFEST.json']=raw
    return m,files

def main():
    payload={}
    try:
        env=os.environ
        if (env.get('GITHUB_REPOSITORY')!=TARGET or env.get('GITHUB_REPOSITORY_ID')!=str(REPOSITORY_ID)
                or env.get('GITHUB_WORKFLOW_SHA')!=env.get('GITHUB_SHA')
                or env.get('GITHUB_EVENT_NAME')!='workflow_dispatch'
                or env.get('GITHUB_WORKFLOW_REF')!=TARGET+'/.github/workflows/okx-demo.yml@refs/heads/main'
                or env.get('GITHUB_ACTIONS')!='true' or env.get('RUNNER_ENVIRONMENT')!='github-hosted'
                or env.get('RUNNER_OS')!='Linux'):raise PublicError('public_hosted_context')
        token=env.pop('DEMO_JOB_TOKEN','');budget=Budget();wire=Wire(budget)
        git=ExactGit(wire,token,TARGET,REPOSITORY_ID,env.get('GITHUB_SHA'));m,files=fetch_public(git)
        if m['capsule_class']!='PERSONALLY_PACKAGED_REQUIRES_REVIEW':raise PublicError('capsule_unbound')
        with tempfile.TemporaryDirectory(prefix='btc-public-') as tmp:
            root=Path(tmp)
            for n,b in files.items():
                p=root/n;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with open(p,'xb') as f:f.write(b)
            # Verified code is loaded only after all public member pins passed.
            sys.path.insert(0,str(root))
            from dependency_install import install
            python=install(root,wire)
            payload=dict(data_key=env.pop('BTC_DEMO_DATA_KEY',''),github_token=token,
                github_usage=budget.value(),deployment=strict_json(env.pop('DEMO_DEPLOYMENT_JSON','')),
                credentials={k:env.pop(v,'') for k,v in {'key':'OKX_DEMO_KEY','secret':'OKX_DEMO_SECRET','passphrase':'OKX_DEMO_PASSPHRASE'}.items()},
                coinalyze_key=env.pop('COINALYZE_API_KEY',''))
            from child_runner import run_child
            value,code=run_child([python,'-B',str(root/'launch_runtime.py')],payload,root,timeout=350)
        print(json.dumps(value,separators=(',',':')));return code
    except BaseException:
        print('{"status":"BLOCKED","reason":"public_launch_blocked"}');return 20
    finally:payload.clear()
if __name__=='__main__':sys.exit(main())
