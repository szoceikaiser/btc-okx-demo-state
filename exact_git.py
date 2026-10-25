"""Exact SHA Git REST reads. All trees and blobs are recomputed, no ref search."""
import base64
from datetime import datetime
import hashlib
import re
from bounded_http import PublicError,strict_json,MAX_JSON

TARGET='szoceikaiser/btc-okx-demo-state'
REPOSITORY_ID=1430986303
def sha(raw):return hashlib.sha256(raw).hexdigest()
def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def identity(s):
    if not isinstance(s,str) or not re.fullmatch('[0-9a-f]{40}',s):raise PublicError('git_identity')
    return s
def tree_id(rows):
    data=[];seen=set()
    for r in rows:
        name=r['path'];mode=r['mode'];kind=r['type'];obj=identity(r['sha'])
        if (not isinstance(name,str) or not name or '/' in name or '\\' in name or '\0' in name
                or name in ('.','..','.git') or name.casefold() in seen
                or (mode,kind) not in (('100644','blob'),('040000','tree'))):raise PublicError('git_tree_entry')
        seen.add(name.casefold());key=name.encode()+ (b'/' if kind=='tree' else b'')
        data.append((key,('40000' if kind=='tree' else mode).encode()+b' '+name.encode()+b'\0'+bytes.fromhex(obj)))
    return oid('tree',b''.join(v for _,v in sorted(data)))

def commit_bytes(c):
    """Supported exact UTC REST commits, including standard gpgsig commits.

    Noncanonical timezones/extra headers fail SHA validation; never guess hashes.
    """
    payload=c.get('verification',{}).get('payload');signature=c.get('verification',{}).get('signature')
    if payload is not None:
        if not isinstance(payload,str) or not isinstance(signature,str):raise PublicError('git_commit_payload')
        header,sep,message=payload.partition('\n\n')
        if not sep:raise PublicError('git_commit_payload')
        raw=(header+'\ngpgsig '+signature.replace('\n','\n ')+'\n\n'+message).encode()
    else:
        def person(p):
            if not isinstance(p,dict):raise PublicError('git_commit_person')
            name,email,date=(p.get(n) for n in ('name','email','date'))
            if (not all(isinstance(x,str) for x in (name,email,date)) or not date.endswith('Z')
                    or any(c in name+email for c in '\r\n\0<>')):raise PublicError('git_commit_person')
            ts=int(datetime.fromisoformat(date.replace('Z','+00:00')).timestamp())
            return name+' <'+email+'> '+str(ts)+' +0000'
        raw=('tree '+identity(c['tree']['sha'])+'\n'+''.join('parent '+identity(p['sha'])+'\n' for p in c['parents'])+
            'author '+person(c['author'])+'\ncommitter '+person(c['committer'])+'\n\n'+c['message']).encode()
    return raw
def verify_commit(c,expected):
    if c.get('sha')!=identity(expected) or oid('commit',commit_bytes(c))!=expected:raise PublicError('git_commit_digest')
    # Reconstructing the raw bytes alone must not allow JSON tree/parents to lie.
    header=commit_bytes(c).split(b'\n\n',1)[0].splitlines()
    if header[0]!=b'tree '+identity(c['tree']['sha']).encode():raise PublicError('git_commit_tree')
    if [line[7:].decode() for line in header if line.startswith(b'parent ')]!=[identity(p['sha']) for p in c['parents']]:raise PublicError('git_commit_parents')
    return identity(c['tree']['sha'])

class ExactGit:
    def __init__(self,wire,token,repository,repository_id,commit):
        if repository!=TARGET or type(repository_id) is not int or repository_id!=REPOSITORY_ID:raise PublicError('public_repository_binding')
        self.wire,self.token,self.commit=wire,token,identity(commit)
        if not isinstance(token,str) or not token or len(token)>4096 or any(c.isspace() for c in token):raise PublicError('token_invalid')
        self.prefix='https://api.github.com/repos/'+TARGET+'/git/';self.cache={};self.calls=0
        self.started=wire.budget.clock()
    def get(self,tail):
        if self.calls>=64 or self.wire.budget.clock()-self.started>60:raise PublicError('fetch_bound')
        self.calls+=1
        return strict_json(self.wire.fetch(self.prefix+tail,{'Authorization':'Bearer '+self.token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'btc-public-bootstrap-v1'}))
    def root(self):
        c=self.get('commits/'+self.commit);self.tree=verify_commit(c,self.commit)
        return self.tree
    def rows(self,obj):
        if obj not in self.cache:
            v=self.get('trees/'+identity(obj));rows=v.get('tree')
            if v.get('sha')!=obj or v.get('truncated') is not False or not isinstance(rows,list) or len(rows)>128 or tree_id(rows)!=obj:raise PublicError('git_tree_digest')
            self.cache[obj]={r['path']:r for r in rows}
        return self.cache[obj]
    def blob(self,path,maximum=MAX_JSON):
        parts=path.split('/')
        if any(p in ('','.','..') for p in parts) or '\\' in path:raise PublicError('git_path')
        obj=self.tree
        for i,p in enumerate(parts):
            row=self.rows(obj).get(p)
            if not row or (row['type'],row['mode'])!=(('blob','100644') if i==len(parts)-1 else ('tree','040000')):raise PublicError('git_member')
            obj=row['sha']
        v=self.get('blobs/'+identity(obj));text=v.get('content')
        if v.get('sha')!=obj or v.get('encoding')!='base64' or not isinstance(text,str) or len(text)>MAX_JSON:raise PublicError('git_blob_encoding')
        try:raw=base64.b64decode(''.join(text.splitlines()),validate=True)
        except Exception:raise PublicError('git_blob_encoding') from None
        if len(raw)>maximum or v.get('size')!=len(raw) or oid('blob',raw)!=obj:raise PublicError('git_blob_digest')
        return raw
