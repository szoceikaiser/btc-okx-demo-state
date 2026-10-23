"""Fixed bounded HTTPS wire; no redirects, retries, proxies or ambient TLS key log."""
import http.client
import json
import queue
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

class PublicError(Exception):pass
class HttpStatus(PublicError):
    def __init__(self,status):self.status=status;super().__init__('https_status_blocked')

MAX_JSON=2200*1024
MAX_CALLS=400
MAX_BYTES=32*1024*1024
MAX_SECONDS=240
HEADER_CAP=16384

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
def strict_json(raw):
    def pairs(rows):
        d={}
        for k,v in rows:
            if k in d:raise PublicError('json_duplicate')
            d[k]=v
        return d
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except Exception:raise PublicError('json_invalid') from None

class Budget:
    def __init__(self,usage=None,clock=time.monotonic):
        self.clock=clock;self.started=clock();self.calls=self.bytes=0
        if usage is not None:
            if (not isinstance(usage,dict) or set(usage)!={'started','calls','bytes'}
                    or type(usage['started']) not in (int,float)
                    or type(usage['calls']) is not int or not 0<=usage['calls']<=MAX_CALLS
                    or type(usage['bytes']) is not int or not 0<=usage['bytes']<=MAX_BYTES):
                raise PublicError('budget_invalid')
            self.started=usage['started'];self.calls=usage['calls'];self.bytes=usage['bytes']
        self.check()
    def check(self):
        if not 0<=self.clock()-self.started<=MAX_SECONDS:raise PublicError('invocation_deadline')
    def charge(self):
        self.check()
        if self.calls>=MAX_CALLS:raise PublicError('invocation_calls')
        self.calls+=1
    def received(self,n):
        self.bytes+=n;self.check()
        if self.bytes>MAX_BYTES:raise PublicError('invocation_bytes')
    def value(self):return dict(started=self.started,calls=self.calls,bytes=self.bytes)

class HeaderReader:
    def __init__(self,fp):self.fp=fp;self.used=0
    def readline(self,n=-1):
        data=self.fp.readline(min(8193,HEADER_CAP-self.used+1));self.used+=len(data)
        if self.used>HEADER_CAP or len(data)>8192:raise PublicError('header_limit')
        return data
    def read(self,n=-1):
        if n<0 or n>HEADER_CAP-self.used:raise PublicError('framing_limit')
        data=self.fp.read(n);self.used+=len(data);return data
    def __getattr__(self,n):return getattr(self.fp,n)

class HTTPResponse(http.client.HTTPResponse):
    def __init__(self,*a,**k):
        super().__init__(*a,**k);self.fp=HeaderReader(self.fp);self.header_reader=self.fp
    def begin(self):super().begin();self.header_bytes=self.fp.used

class Wire:
    def __init__(self,budget,*,factory=http.client.HTTPSConnection):
        self.budget=budget;self.factory=factory
        self.tls=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);self.tls.load_default_certs()
        self.tls.minimum_version=ssl.TLSVersion.TLSv1_2;self.tls.set_alpn_protocols(['http/1.1'])
    def fetch(self,url,headers,*,method='GET',body=None,maximum=MAX_JSON):
        u=urlsplit(url)
        if (u.scheme!='https' or u.netloc not in ('api.github.com','files.pythonhosted.org')
                or u.username or u.password or u.fragment or method not in ('GET','POST','PATCH')
                or u.netloc!='api.github.com' and method!='GET'
                or body is not None and (type(body) is not bytes or len(body)>MAX_JSON)
                or type(maximum) is not int or not 0<maximum<=8*1024*1024):raise PublicError('wire_scope')
        if (len({k.lower() for k in headers})!=len(headers)
                or any('\r' in str(v) or '\n' in str(v) for v in headers.values())
                or any(k.lower() in ('host','content-length','transfer-encoding','connection','accept-encoding') for k in headers)):
            raise PublicError('wire_headers')
        headers=dict(headers,Host=u.hostname,Connection='close',**{'Accept-Encoding':'identity'})
        if body is not None:headers['Content-Length']=str(len(body))
        target=u.path+('?' +u.query if u.query else '')
        request_bytes=len((method+' '+target+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode('ascii'))+len(body or b'')
        self.budget.charge();self.budget.received(request_bytes)
        deadline=min(self.budget.started+MAX_SECONDS,self.budget.clock()+10)
        conn=self.factory(u.hostname,443,timeout=max(.001,deadline-self.budget.clock()),context=self.tls)
        conn.response_class=HTTPResponse
        cancel=threading.Event();connected=None
        def abort():
            cancel.set();sock=connected or getattr(conn,'sock',None)
            if sock:
                try:sock.shutdown(socket.SHUT_RDWR)
                except Exception:pass
            conn.close()
        def bounded(fn):
            left=deadline-self.budget.clock()
            if left<=0:raise PublicError('https_deadline')
            q=queue.Queue(1)
            def work():
                try:q.put((True,fn()))
                except BaseException:q.put((False,None))
            threading.Thread(target=work,daemon=True).start()
            try:ok,value=q.get(timeout=left)
            except queue.Empty:raise PublicError('https_deadline') from None
            if not ok or cancel.is_set() or self.budget.clock()>deadline:raise PublicError('https_outcome_unknown_no_retry')
            return value
        def begin():
            nonlocal connected
            conn.connect();connected=getattr(conn,'sock',None)
            if cancel.is_set():raise PublicError('cancelled_before_send')
            conn.request(method,target,body=body,headers=headers)
            if cancel.is_set():raise PublicError('cancelled_after_send')
            return conn.getresponse()
        try:
            r=bounded(begin);self.budget.received(r.header_bytes)
            if r.status!=(201 if method=='POST' else 200):raise HttpStatus(r.status)
            hs=r.getheaders()
            def vals(k):return [v for n,v in hs if n.lower()==k]
            enc,length,transfer=vals('content-encoding'),vals('content-length'),vals('transfer-encoding')
            if (len(enc)>1 or len(length)>1 or len(transfer)>1 or enc and enc[0].strip().lower()!='identity'
                    or transfer and (transfer[0].strip().lower()!='chunked' or length)):
                raise PublicError('https_framing')
            expected=None
            if length:
                if not length[0].isascii() or not length[0].isdigit() or len(length[0])>12:raise PublicError('https_length')
                expected=int(length[0])
                if expected>maximum:raise PublicError('https_size')
            chunks=[];size=0
            while size<=maximum:
                before=r.header_reader.used
                part=bounded(lambda:r.read1(min(65536,maximum+1-size)))
                self.budget.received(len(part)+r.header_reader.used-before)
                if not part:break
                chunks.append(part);size+=len(part)
            if size>maximum or expected is not None and expected!=size:raise PublicError('https_size_or_eof')
            return b''.join(chunks)
        finally:abort()

def request_size(request):
    """The fake-wire adapter uses the same explicit framing as Wire for accounting."""
    u=urlsplit(request.full_url);hs=dict(request.header_items());hs.update({'Host':u.hostname,'Connection':'close','Accept-Encoding':'identity'})
    if request.data is not None:hs['Content-Length']=str(len(request.data))
    return len((request.get_method()+' '+u.path+('?' +u.query if u.query else '')+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in hs.items())+'\r\n').encode('ascii'))+len(request.data or b'')

class GitTransport:
    """urllib-shaped adapter for the existing provider/checkpoint interfaces.

    Production uses Wire; injected fake transport uses identical request-body
    accounting and bounded response reads. No injection exists in the CLI.
    """
    def __init__(self,budget,delegate=None):
        self.budget=budget;self.delegate=delegate;self.wire=Wire(budget) if delegate is None else None
        self.counts=dict(get=0,post=0,patch=0,bytes=0)
    def open(self,request,timeout):
        from io import BytesIO
        from urllib.error import HTTPError
        u=urlsplit(request.full_url);method=request.get_method()
        if u.scheme!='https' or u.netloc!='api.github.com' or u.fragment or method not in ('GET','POST','PATCH'):
            raise PublicError('github_wire_scope')
        self.counts[method.lower()]+=1;before=self.budget.bytes
        if self.delegate is None:
            try:
                raw=self.wire.fetch(request.full_url,dict(request.header_items()),method=method,body=request.data)
            except HttpStatus as e:
                raise HTTPError(request.full_url,e.status,'blocked',{},BytesIO()) from None
            finally:self.counts['bytes']+=self.budget.bytes-before
            r=BytesIO(raw);r.status=201 if method=='POST' else 200;return r
        self.budget.charge();self.budget.received(request_size(request))
        r=self.delegate.open(request,timeout=min(10,timeout));self.budget.received(getattr(r,'header_bytes',0))
        parent=self
        class Meter:
            def __getattr__(self,k):return getattr(r,k)
            def __enter__(self):return self
            def __exit__(self,*a):r.close()
            def read(self,n=-1):
                if not 0<=n<=MAX_JSON+1:raise PublicError('github_read_bound')
                b=r.read(n);parent.budget.received(len(b));parent.counts['bytes']+=len(b);return b
            def read1(self,n=-1):return self.read(n)
            def close(self):r.close()
        self.counts['bytes']+=self.budget.bytes-before
        return Meter()
