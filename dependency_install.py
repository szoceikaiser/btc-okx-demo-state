"""Exact Linux CPython 3.12 wheel acquisition followed by offline hash install."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
from bounded_http import PublicError,strict_json
from child_runner import child_environment

def install(root,wire):
    root=Path(root)
    if sys.version_info[:2]!=(3,12) or sys.platform!='linux' or platform.machine()!='x86_64':raise PublicError('linux_cp312_required')
    lock=strict_json((root/'wheels.lock.json').read_bytes());rows=lock['wheels']
    if lock['schema']!='linux-cp312-x86_64-wheels-v1' or len(rows)!=3 or [(r['name'],r['version']) for r in rows]!=[('cryptography','50.0.2'),('cffi','2.0.0'),('pycparser','2.23')]:raise PublicError('wheel_lock_invalid')
    dest=root/'wheelhouse';dest.mkdir(mode=0o700)
    for r in rows:
        if not r['url'].startswith('https://files.pythonhosted.org/packages/') or '/' in r['filename'] or not r['filename'].endswith('.whl'):raise PublicError('wheel_url_invalid')
        b=wire.fetch(r['url'],{'User-Agent':'btc-pinned-wheels-v1'},maximum=8*1024*1024)
        if len(b)!=r['bytes'] or hashlib.sha256(b).hexdigest()!=r['sha256']:raise PublicError('wheel_digest')
        with open(dest/r['filename'],'xb') as f:f.write(b)
    def run(args):
        wire.budget.check()
        left=min(60,wire.budget.started+240-wire.budget.clock())
        if left<=0:raise PublicError('install_deadline')
        r=subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=left,
            env=child_environment())
        if r.returncode:raise PublicError('pinned_install_failed')
        wire.budget.check()
    run([sys.executable,'-I','-m','venv',str(root/'venv')])
    python=str(root/'venv/bin/python')
    run([python,'-I','-m','pip','--isolated','install','--no-index','--no-deps','--require-hashes','--only-binary=:all:',
         '--no-compile','--disable-pip-version-check','--no-cache-dir','--find-links',str(dest),'-r',str(root/'requirements.lock')])
    run([python,'-I','-c',"from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV; c=AESGCMSIV(bytes(range(32))); assert c.decrypt(b'LinuxTEST123',c.encrypt(b'LinuxTEST123',b'test',b'test'),b'test')==b'test'"])
    return python
