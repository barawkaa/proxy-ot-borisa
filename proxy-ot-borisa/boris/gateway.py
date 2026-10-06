"""Bounded async TCP gateways; HTTP parsing/routing is delegated to sing-box."""
import asyncio
import base64
import collections
import contextlib
import ipaddress
import secrets
import time
import urllib.parse
from .model import client_enabled


def in_cidrs(ip, items):
    try:
        address=ipaddress.ip_address(ip)
        return any(address in ipaddress.ip_network(x,strict=False) for x in items)
    except ValueError:return False


async def socks_open(port,host,dest_port,username='',password=''):
    reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',port),8)
    try:
        writer.write(b'\x05\x01'+(b'\x02' if username else b'\x00'));await writer.drain()
        method=await reader.readexactly(2)
        if method != b'\x05'+(b'\x02' if username else b'\x00'):raise OSError('SOCKS authentication method')
        if username:
            u=username.encode();p=password.encode()
            writer.write(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p);await writer.drain()
            if await reader.readexactly(2)!=b'\x01\x00':raise OSError('SOCKS credentials rejected')
        host=host.encode('idna')
        if len(host)>255:raise ValueError('Hostname too long')
        writer.write(b'\x05\x01\x00\x03'+bytes([len(host)])+host+int(dest_port).to_bytes(2,'big'));await writer.drain()
        head=await reader.readexactly(4)
        if head[:2]!=b'\x05\x00':raise OSError('SOCKS connect failed')
        size={1:4,4:16}.get(head[3])
        if head[3]==3:size=(await reader.readexactly(1))[0]
        if size is None:raise OSError('SOCKS address')
        await reader.readexactly(size+2)
        return reader,writer
    except asyncio.IncompleteReadError:
        writer.close()
        raise OSError('SOCKS connection closed during handshake') from None
    except BaseException:
        writer.close()
        raise


class Gateway:
    def __init__(self,store):
        self.store=store;self.listeners=[];self.ports=None;self.active={};self.tasks={};self.pending=[]
        self.usage_pending=collections.defaultdict(lambda:[0,0]);self.usage_cache=store.usage()
        self.attempts={};self.bans={};self.accepted=0

    def permitted(self,ip):
        c=self.store.config;sec=c['security'];now=time.time()
        if in_cidrs(ip,sec['deny_cidrs']) or self.bans.get(ip,0)>now:return False
        if sec['allow_cidrs'] and not in_cidrs(ip,sec['allow_cidrs']):return False
        if sec['country_enabled'] and not in_cidrs(ip,sec['country_cidrs']) and not in_cidrs(ip,sec['allow_cidrs']):return False
        if sec['autoban_enabled']:
            if len(self.attempts)>4096:self.attempts={k:v for k,v in self.attempts.items() if v and v[-1]>now-60}
            hits=self.attempts.setdefault(ip,collections.deque(maxlen=1000))
            while hits and hits[0]<now-60:hits.popleft()
            hits.append(now)
            count=sum(1 for x in self.active.values() if x['ip']==ip)
            if len(hits)>sec['new_per_minute'] or count>=sec['max_per_ip']:
                self.bans[ip]=now+sec['ban_seconds'];self.store.event('security','Временная блокировка источника из-за превышения лимита подключений');return False
        return True

    def enabled(self,c,protocol):
        usage=self.usage_cache.get(c['id'],{})
        current=sum(self.usage_pending.get(c['id'],[0,0]))
        limit=c.get('monthly_limit_gb',0)*1024**3
        return client_enabled(c) and c.get(protocol,False) and (not limit or usage.get('upload',0)+usage.get('download',0)+current<limit)

    def trusted(self,ip,protocol):
        s=self.store.config['security']
        if s['trusted_enabled']:
            for rule in s['trusted']:
                if protocol in rule.get('protocols',['http','socks']) and in_cidrs(ip,[rule['cidr']]):
                    return next((u for u in self.store.config['clients'] if u['id']==rule['client_id'] and self.enabled(u,protocol)),None)
        return None

    def authenticate(self,username,password,protocol):
        for u in self.store.config['clients']:
            if secrets.compare_digest(u['username'],username) and secrets.compare_digest(u['password'],password) and self.enabled(u,protocol):return u
        return None

    async def apply(self):
        s=self.store.config['settings'];ports=(s['http_port'] if s['http_enabled'] else 0,s['socks_port'] if s['socks_enabled'] else 0)
        if ports==self.ports:return
        old=self.ports
        await self.stop_listeners()
        try:
            for protocol,port in zip(('http','socks'),ports):
                if port:self.listeners.append(await asyncio.start_server(lambda r,w,p=protocol: self.accept(r,w,p),'0.0.0.0',port,limit=65536))
            self.ports=ports
        except OSError:
            await self.stop_listeners()
            if old:
                for protocol,port in zip(('http','socks'),old):
                    if port:self.listeners.append(await asyncio.start_server(lambda r,w,p=protocol:self.accept(r,w,p),'0.0.0.0',port,limit=65536))
                self.ports=old
            raise ValueError('Порт прокси занят; прежние порты восстановлены') from None

    async def accept(self,r,w,protocol):
        peer=w.get_extra_info('peername');ip=peer[0] if peer else ''
        if self.accepted>=self.store.config['settings']['max_connections'] or not self.permitted(ip):w.close();return
        self.accepted+=1;uid=secrets.token_hex(12);self.tasks[uid]=asyncio.current_task();upstream=None
        try:
            async with asyncio.timeout(12):
                user=self.trusted(ip,protocol)
                if protocol=='http':
                    header=await r.readuntil(b'\r\n\r\n')
                    if len(header)>32768:raise ValueError('Header too large')
                    lines=header.decode('latin1').split('\r\n');method,target,version=lines[0].split(' ')
                    headers=[];credential=''
                    for line in lines[1:]:
                        if not line:continue
                        key,sep,value=line.partition(':')
                        if not sep or line[0].isspace():raise ValueError('Malformed header')
                        if key.lower()=='proxy-authorization':credential=value.strip()
                        else:headers.append(line)
                    if credential.lower().startswith('basic '):
                        try:username,password=base64.b64decode(credential[6:],validate=True).decode().split(':',1);user=self.authenticate(username,password,protocol)
                        except (ValueError,UnicodeError):user=None
                    if not user:
                        w.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Boris"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');await w.drain();return
                    # Forward the original absolute request to a mature HTTP proxy.
                    # Connection: close prevents a later unauthenticated HTTP request sharing this tunnel.
                    if method!='CONNECT':
                        headers=[x for x in headers if x.split(':',1)[0].lower() not in ('connection','proxy-connection')]
                        headers.append('Connection: close')
                    token=base64.b64encode((user['username']+':'+user['password']).encode()).decode()
                    headers.append('Proxy-Authorization: Basic '+token)
                    ur,uw=await asyncio.open_connection('127.0.0.1',12080);upstream=uw
                    uw.write(('\r\n'.join([lines[0]]+headers)+'\r\n\r\n').encode('latin1'));await uw.drain()
                    destination=target[:300] if method=='CONNECT' else (urllib.parse.urlsplit(target).hostname or 'HTTP')
                else:
                    head=await r.readexactly(2)
                    if head[0]!=5:raise ValueError('SOCKS version')
                    methods=await r.readexactly(head[1])
                    if user and 0 in methods:w.write(b'\x05\x00')
                    elif 2 in methods:
                        w.write(b'\x05\x02');await w.drain()
                        h=await r.readexactly(2)
                        if h[0]!=1:raise ValueError('Auth version')
                        username=(await r.readexactly(h[1])).decode()
                        password=(await r.readexactly((await r.readexactly(1))[0])).decode()
                        user=self.authenticate(username,password,protocol)
                        w.write(b'\x01'+(b'\x00' if user else b'\x01'));await w.drain()
                        if not user:return
                    else:w.write(b'\x05\xff');await w.drain();return
                    await w.drain();h=await r.readexactly(4)
                    if h[:3]!=b'\x05\x01\x00':
                        w.write(b'\x05\x07\x00\x01'+b'\x00'*6);await w.drain();return
                    if h[3]==1:host=str(ipaddress.ip_address(await r.readexactly(4)))
                    elif h[3]==4:host=str(ipaddress.ip_address(await r.readexactly(16)))
                    elif h[3]==3:host=(await r.readexactly((await r.readexactly(1))[0])).decode('idna')
                    else:raise ValueError('Address type')
                    port=int.from_bytes(await r.readexactly(2),'big');destination=f'{host}:{port}'
                    try:ur,uw=await socks_open(12080,host,port,user['username'],user['password'])
                    except OSError:
                        w.write(b'\x05\x04\x00\x01'+b'\x00'*6);await w.drain();return
                    upstream=uw
                    w.write(b'\x05\x00\x00\x01'+b'\x00'*6);await w.drain()
            rec={'id':uid,'client_id':user['id'],'name':user['name'],'protocol':protocol,'ip':ip,'destination':destination,'started':time.time(),'ended':0,'upload':0,'download':0,'result':'active'}
            self.active[uid]=rec
            async def pump(reader,writer,key):
                while True:
                    if not self.enabled(user,protocol):break
                    data=await asyncio.wait_for(reader.read(65536),self.store.config['settings']['idle_seconds'])
                    if not data:
                        if writer.can_write_eof():writer.write_eof();await writer.drain()
                        break
                    writer.write(data);await writer.drain();rec[key]+=len(data)
                    self.usage_pending[user['id']][0 if key=='upload' else 1]+=len(data)
            a=asyncio.create_task(pump(r,uw,'upload'));b=asyncio.create_task(pump(ur,w,'download'))
            try:await asyncio.gather(a,b)
            finally:
                a.cancel();b.cancel();await asyncio.gather(a,b,return_exceptions=True)
        except (OSError,TimeoutError,ValueError,UnicodeError,asyncio.IncompleteReadError,asyncio.LimitOverrunError):
            if uid in self.active:self.active[uid]['result']='connection_error'
        finally:
            if uid in self.active:
                rec=self.active.pop(uid);rec['ended']=time.time()
                if rec['result']=='active':rec['result']='closed'
                # Bound RAM even if storage is temporarily unavailable.
                self.pending.append(rec);self.pending=self.pending[-1000:]
            self.tasks.pop(uid,None);self.accepted-=1
            w.close()
            if upstream:upstream.close()
            with contextlib.suppress(Exception):await asyncio.wait_for(w.wait_closed(),1)

    def flush(self):
        if self.pending:self.store.sessions(self.pending);self.pending=[]
        if self.usage_pending:
            self.store.add_usage([(uid,*counts) for uid,counts in self.usage_pending.items()]);self.usage_pending.clear()
        self.usage_cache=self.store.usage()
        self.bans={k:v for k,v in self.bans.items() if v>time.time()}

    def disconnect(self,client_id=''):
        for sid,rec in list(self.active.items()):
            if not client_id or rec['client_id']==client_id:
                task=self.tasks.get(sid)
                if task:task.cancel()

    async def stop_listeners(self):
        for s in self.listeners:s.close();await s.wait_closed()
        self.listeners=[];self.ports=None

    async def close(self):
        await self.stop_listeners()
        tasks=list(self.tasks.values())
        for t in tasks:t.cancel()
        await asyncio.gather(*tasks,return_exceptions=True);self.flush()
