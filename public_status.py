"""Only fixed reasons/status and bounded integer counters may leave a child."""
import json
from bounded_http import strict_json
STATUSES={'BLOCKED','BOOTSTRAPPED_ONLY','CONTROL_ONLY','COMPLETED','DISPATCH_DISABLED','WAIT'}
REASONS={'runtime_blocked','first_demo_close_and_read_authorization_missing','hosted_launch_failed','child_output_rejected','child_failed','child_timeout','public_launch_blocked'}
COUNTERS={'collector_calls':1200,'collector_bytes':24*1024*1024,'github_calls':400,'exchange_writes':3}
def summary(value):
    out={'status':value.get('status') if value.get('status') in STATUSES else 'BLOCKED'}
    for n,limit in COUNTERS.items():
        v=value.get(n)
        if type(v) is int and 0<=v<=limit:out[n]=v
    if out['status']=='BLOCKED':out['reason']=value.get('reason') if value.get('reason') in REASONS else 'runtime_blocked'
    return out
def child_summary(raw,returncode):
    try:
        if type(raw) is not bytes or len(raw)>2048 or returncode not in (0,20,24):raise ValueError()
        value=strict_json(raw)
        if not isinstance(value,dict) or set(value)-({'status','reason'}|set(COUNTERS)):raise ValueError()
        out=summary(value)
        if out!=value or ((returncode==0)!=(value.get('status')!='BLOCKED')):raise ValueError()
        return out
    except Exception:return {'status':'BLOCKED','reason':'child_output_rejected'}
