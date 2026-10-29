"""Authenticate complete capsule, restore exclusively, review, invoke locked child."""
import hashlib
import json
from pathlib import Path
import sys
from private_envelope import Cipher,Context,parse_key,PrivacyError
import private_capsule as capsule
from exact_git import TARGET,REPOSITORY_ID,sha
from child_runner import run_child,child_environment

def authenticate_restore(manifest,encrypted,key,parent,workflow):
    pin=manifest.get('capsule')
    if (not isinstance(pin,dict) or pin.get('bytes')!=len(encrypted) or pin.get('sha256')!=sha(encrypted)
            or manifest.get('repository')!=TARGET or type(manifest.get('repository_id')) is not int
            or manifest['repository_id']!=REPOSITORY_ID):raise PrivacyError('public_capsule_binding')
    cipher=Cipher(key,Context(TARGET,REPOSITORY_ID,manifest.get('store_id'),'private-runtime-capsule'),maximum=capsule.MAX_ZIP)
    raw=cipher.open(encrypted)
    files=capsule.unpack(raw,expected_source_manifest_sha256=manifest['runtime_review_sha256'])
    if files.get('.github/workflows/okx-demo.yml')!=workflow:raise PrivacyError('public_workflow_runtime_mismatch')
    # Exact inner review bytes are an authenticated member, not a metadata label.
    import io,zipfile
    with zipfile.ZipFile(io.BytesIO(raw)) as z:review=z.read(capsule.REVIEW)
    return capsule.restore(files,review,parent)

def invoke_locked(root,payload,python=sys.executable):
    # Review and runtime verification run in the restored tree, before secret stdin.
    check=("from operation import verify_package; verify_package(); "
           "from public_policy import verify_runtime_review; "
           "verify_runtime_review('.',"+repr(payload.pop('_runtime_review_pin'))+")")
    import subprocess
    r=subprocess.run([python,'-B','-c',check],cwd=root,env=child_environment(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
    if r.returncode:raise PrivacyError('private_runtime_review_failed')
    return run_child([python,'-B','hosted_launch.py'],payload,root,timeout=960)

def main():
    payload={};phase='PUBLIC_VERIFY'
    try:
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError()
        from bounded_http import strict_json
        payload=strict_json(raw)
        if type(payload) is not dict or set(payload)!={'operation','data_key','github_token','github_usage','credentials','coinalyze_key'} or payload['operation']!='control':raise ValueError()
        root=Path.cwd();manifest=json.loads((root/'PUBLIC-MANIFEST.json').read_bytes())
        if manifest.get('capsule_class')!='PERSONALLY_PACKAGED_REQUIRES_REVIEW':raise ValueError()
        import tempfile
        with tempfile.TemporaryDirectory(prefix='btc-private-') as parent:
            key=parse_key(payload.get('data_key'))
            phase='CAPSULE_RESTORE'
            restored=authenticate_restore(manifest,(root/'runtime.capsule').read_bytes(),key,parent,(root/'.github/workflows/okx-demo.yml').read_bytes())
            payload.update(runtime_review_sha256=manifest['runtime_review_sha256'],
                public_manifest_sha256=sha((root/'PUBLIC-MANIFEST.json').read_bytes()),capsule_sha256=sha((root/'runtime.capsule').read_bytes()))
            payload['_runtime_review_pin']=manifest['runtime_review_sha256']
            phase='INNER_VERIFY'
            value,code=invoke_locked(restored,payload)
        print(json.dumps(value,separators=(',',':')));return code
    except BaseException:
        print(json.dumps(dict(status='BLOCKED',reason='public_launch_blocked',phase=phase),separators=(',',':')));return 20
    finally:payload.clear()
if __name__=='__main__':sys.exit(main())
