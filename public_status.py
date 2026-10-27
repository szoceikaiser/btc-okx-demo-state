"""Strict public output: fixed status/phase, pins and bounded counters only."""
import re
from bounded_http import strict_json
PHASES={'VERIFY','AUTHORIZE','LOAD','ACQUIRE','COLLECT','CLOSED','RELOAD','CONFIRMED','PUBLIC_VERIFY','PUBLIC_FETCH','DEPENDENCIES','CAPSULE_RESTORE','INNER_VERIFY','HOSTED_SELECTOR'}
STATUSES={'BLOCKED','BOOTSTRAPPED_ONLY','CONTROL_ONLY','COMPLETED','DISPATCH_DISABLED','WAIT','CONTROL_CLOSED_RECEIPT_MISSING'}
REASONS={'runtime_blocked','first_demo_close_and_read_authorization_missing','hosted_launch_failed','child_output_rejected','child_failed','child_timeout','public_launch_blocked','control_stopped_no_retry'}
COUNTERS={'collector_calls':1200,'collector_bytes':24*1024*1024,'github_calls':400,'exchange_writes':3,'github_bytes':32*1024*1024,'cipher_bytes':1536036,'native_strategy_passes':0,'control_close_ms':2**63-1,'checkpoint_revision':1003,'checkpoint_publications':3}
PINS={'root_head':40,'root_tree':40,'root_blob':40,'cipher_sha256':64,'root_digest':64,'seed_sha256':64}
CONTROL_PINS={'checkpoint_head':40,'checkpoint_digest':64}
def summary(value):
 out={'status':value.get('status') if value.get('status') in STATUSES else 'BLOCKED'}
 for n,limit in COUNTERS.items():
  v=value.get(n)
  if type(v) is int and 0<=v<=limit:out[n]=v
 if value.get('phase') in PHASES:out['phase']=value['phase']
 pins=PINS if out['status']=='BOOTSTRAPPED_ONLY' else CONTROL_PINS if out['status']=='CONTROL_ONLY' else {}
 for n,size in pins.items():
  v=value.get(n)
  if type(v) is not str or not re.fullmatch('[0-9a-f]{'+str(size)+'}',v):return {'status':'BLOCKED','reason':'runtime_blocked'}
  out[n]=v
 if out['status']=='CONTROL_ONLY' and (value.get('phase')!='CONFIRMED' or value.get('exchange_writes')!=0 or value.get('native_strategy_passes')!=0):return {'status':'BLOCKED','reason':'runtime_blocked'}
 if out['status'] in ('BLOCKED','CONTROL_CLOSED_RECEIPT_MISSING'):
  out['reason']=value.get('reason') if value.get('reason') in REASONS else 'runtime_blocked'
 return out
def child_summary(raw,returncode):
 try:
  if type(raw) is not bytes or len(raw)>2048 or returncode not in (0,20,24):raise ValueError()
  value=strict_json(raw)
  if not isinstance(value,dict) or set(value)-({'status','reason','phase'}|set(COUNTERS)|set(PINS)|set(CONTROL_PINS)):raise ValueError()
  out=summary(value)
  if out!=value or ((returncode==0)!=(value.get('status') not in ('BLOCKED','CONTROL_CLOSED_RECEIPT_MISSING'))):raise ValueError()
  return out
 except Exception:return {'status':'BLOCKED','reason':'child_output_rejected'}
