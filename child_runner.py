"""Bounded child output capture. Never forward raw stdout/stderr or exceptions."""
import json
import os
import subprocess
import threading
import time
from public_status import child_summary

def child_environment():
    allowed={'PATH','SYSTEMROOT','WINDIR','TEMP','TMP','LANG','LC_ALL','HOME','VIRTUAL_ENV',
        'GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_OS','GITHUB_EVENT_NAME','GITHUB_REPOSITORY',
        'GITHUB_REPOSITORY_ID','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_WORKFLOW_REF',
        'GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REPOSITORY_OWNER_ID','GITHUB_ACTOR','GITHUB_ACTOR_ID',
        'GITHUB_TRIGGERING_ACTOR','GITHUB_JOB','RUNNER_NAME','RUNNER_TEMP'}
    env={k:v for k,v in os.environ.items() if k in allowed};env['PYTHONDONTWRITEBYTECODE']='1'
    return env

def run_child(args,payload,cwd,*,timeout=330):
    # No ambient Python injection, credential environment, output files or keylog.
    env=child_environment()
    raw=json.dumps(payload,separators=(',',':'),allow_nan=False).encode()
    if len(raw)>65536:return {'status':'BLOCKED','reason':'child_failed'},20
    proc=None
    try:
        proc=subprocess.Popen(args,cwd=cwd,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        capture=bytearray();overflow=threading.Event()
        def read():
            while True:
                b=proc.stdout.read(512)
                if not b:break
                if len(capture)+len(b)>2048:
                    overflow.set();proc.kill();break
                capture.extend(b)
        reader=threading.Thread(target=read,daemon=True);reader.start()
        # Input is small and child reads immediately after the immutable gate;
        # a blocked child may exit without reading, which is expected.
        def write():
            try:proc.stdin.write(raw);proc.stdin.close()
            except (BrokenPipeError,OSError):pass
        writer=threading.Thread(target=write,daemon=True);writer.start()
        try:code=proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill();proc.wait(timeout=5);return {'status':'BLOCKED','reason':'child_timeout'},20
        reader.join(timeout=5);writer.join(timeout=5)
        if reader.is_alive() or overflow.is_set():return {'status':'BLOCKED','reason':'child_output_rejected'},20
        value=child_summary(bytes(capture),code)
        # Rejected output and BLOCKED status must never become a successful job.
        if value['status']=='BLOCKED':return value,24 if code==24 else 20
        return value,0
    except BaseException:
        if proc and proc.poll() is None:proc.kill()
        return {'status':'BLOCKED','reason':'child_failed'},20
    finally:
        if proc:
            for stream in (proc.stdin,proc.stdout):
                if stream:
                    try:stream.close()
                    except Exception:pass
