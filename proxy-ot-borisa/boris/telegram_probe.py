"""MTProto nonce exchange, authenticated Fake TLS, and bounded real file sampling."""
import asyncio
import contextlib
import hashlib
import hmac
import secrets
import ssl
import struct
import time
from telethon import TelegramClient, functions, utils
from telethon.sessions import StringSession
from telethon.network.connection import ConnectionTcpIntermediate, ConnectionTcpMTProxyRandomizedIntermediate
from .gateway import socks_open


def client_hello(secret):
    raw=bytes.fromhex(secret);incoming=ssl.MemoryBIO();outgoing=ssl.MemoryBIO()
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    conn=ctx.wrap_bio(incoming,outgoing,server_hostname=raw[17:].decode('ascii'))
    with contextlib.suppress(ssl.SSLWantReadError):conn.do_handshake()
    packet=bytearray(outgoing.read());packet[11:43]=bytes(32)
    digest=bytearray(hmac.digest(raw[1:17],packet,'sha256'))
    stamp=int(time.time()).to_bytes(4,'little')
    for i in range(4):digest[28+i]^=stamp[i]
    packet[11:43]=digest
    return bytes(packet)


def identify_hello(packet,clients):
    if len(packet)<43:return None
    signed=packet[11:43];zero=packet[:11]+bytes(32)+packet[43:]
    for user in clients:
        try:raw=bytes.fromhex(user['telegram_secret'])
        except (ValueError,KeyError):continue
        digest=hmac.digest(raw[1:17],zero,'sha256')
        if hmac.compare_digest(signed[:28],digest[:28]):
            stamp=int.from_bytes(bytes(a^b for a,b in zip(signed[28:],digest[28:])),'little')
            if abs(time.time()-stamp)<300:return user
    return None


async def record(reader):
    head=await reader.readexactly(5);size=int.from_bytes(head[3:],'big')
    if size>18432:raise ValueError('Oversized TLS record')
    return head+await reader.readexactly(size)


class TLSReader:
    def __init__(self,reader):self.reader=reader;self.buffer=bytearray()
    async def readexactly(self,size):
        while len(self.buffer)<size:
            data=await record(self.reader)
            if data[0]==23:self.buffer.extend(data[5:])
            elif data[0]!=20:raise ConnectionError('Unexpected TLS record')
        out=bytes(self.buffer[:size]);del self.buffer[:size];return out
    def at_eof(self):return self.reader.at_eof() and not self.buffer


class TLSWriter:
    def __init__(self,writer):self.writer=writer
    def write(self,data):
        for offset in range(0,len(data),16384):
            chunk=data[offset:offset+16384];self.writer.write(b'\x17\x03\x03'+len(chunk).to_bytes(2,'big')+chunk)
    async def drain(self):await self.writer.drain()
    def close(self):self.writer.close()
    async def wait_closed(self):await self.writer.wait_closed()
    def get_extra_info(self,*args):return self.writer.get_extra_info(*args)


async def fake_open(port,secret):
    reader,writer=await asyncio.open_connection('127.0.0.1',port)
    try:
        hello=client_hello(secret);writer.write(hello);await writer.drain()
        reply=b''.join([await record(reader) for _ in range(3)])
        if reply[0]!=22 or len(reply)<43:raise ConnectionError('Fake TLS not accepted')
        expected=hmac.digest(bytes.fromhex(secret)[1:17],hello[11:43]+reply[:11]+bytes(32)+reply[43:],'sha256')
        if not hmac.compare_digest(reply[11:43],expected):raise ConnectionError('Fake TLS authentication failed')
        writer.write(b'\x14\x03\x03\x00\x01\x01');await writer.drain()
        return TLSReader(reader),TLSWriter(writer)
    except BaseException:writer.close();raise


class FakeTLSConnection(ConnectionTcpMTProxyRandomizedIntermediate):
    def __init__(self,*args,proxy=None,**kwargs):
        self.full_secret=proxy[2]
        super().__init__(*args,proxy=proxy,**kwargs)
    async def _connect(self,timeout=None,ssl=None):
        async with asyncio.timeout(timeout or 15):
            self._reader,self._writer=await fake_open(self._port,self.full_secret)
            self._codec=self.packet_codec(self);self._init_conn();await self._writer.drain()


def pq_request():
    nonce=secrets.token_bytes(16);body=b'\xf1\x8e\x7e\xbe'+nonce
    return bytes(8)+struct.pack('<QI',int(time.time()*2**32)&~3,len(body))+body,nonce


def valid_pq(packet,nonce):
    return len(packet)>=56 and packet[:8]==bytes(8) and packet[20:24]==b'\x63\x24\x16\x05' and hmac.compare_digest(packet[24:40],nonce)


async def direct_exchange(open_stream):
    reader,writer=await open_stream()
    try:
        packet,nonce=pq_request();writer.write(b'\xee'*4+len(packet).to_bytes(4,'little')+packet);await writer.drain()
        size=int.from_bytes(await reader.readexactly(4),'little')
        if not 56<=size<=4096:raise ConnectionError('Invalid MTProto frame')
        if not valid_pq(await reader.readexactly(size),nonce):raise ConnectionError('Invalid MTProto nonce')
    finally:writer.close()


class TelegramProbe:
    def __init__(self,store,runtime):
        self.store=store;self.runtime=runtime;self.media_lock=asyncio.Lock();self.cache={};self.cooldown=0
        store.db.execute('CREATE TABLE IF NOT EXISTS telegram_sessions(id TEXT PRIMARY KEY, identity TEXT, session TEXT)');store.db.commit()

    async def protocol(self,tag):
        targets=self.store.config['settings']['telegram_targets'][:5];results=[]
        async def check(target):
            start=time.monotonic()
            try:
                host,port=target.rsplit(':',1)
                async with asyncio.timeout(self.store.config['settings']['check_timeout']):
                    await direct_exchange(lambda:socks_open(12085,host,int(port),tag,self.runtime.password))
                return {'target':target,'status':'protocol_ok','ms':round((time.monotonic()-start)*1000)}
            except (OSError,TimeoutError,ValueError,asyncio.IncompleteReadError):return {'target':target,'status':'unreachable'}
        results=await asyncio.gather(*(check(t) for t in targets))
        passed=sum(r['status']=='protocol_ok' for r in results)
        return {'status':'protocol_ok' if passed==len(results) and passed else 'partial' if passed else 'unreachable','checks':results,
                'detail':'Ответ MTProto проверен; загрузка медиа оценивается отдельно'}

    async def chain(self):
        clients=[u for u in self.store.config['clients'] if u.get('enabled') and u.get('telegram')]
        if not clients:return {'status':'unconfigured'}
        secret=self.store.config['telegram_probe']['internal_secret'];port=self.store.config['settings']['telegram_port']
        from collections import defaultdict
        import logging
        results=[]
        for dc in (2,-2,4,-4,5,-5):
            connection=FakeTLSConnection('',0,dc,loggers=defaultdict(lambda:logging.getLogger('boris.probe')),proxy=('127.0.0.1',port,secret))
            try:
                async with asyncio.timeout(self.store.config['settings']['check_timeout']):
                    await connection.connect();packet,nonce=pq_request();await connection.send(packet)
                    if not valid_pq(await connection.recv(),nonce):raise ConnectionError('Invalid nonce')
                results.append({'dc':dc,'status':'protocol_ok'})
            except (OSError,TimeoutError,ValueError,asyncio.IncompleteReadError):results.append({'dc':dc,'status':'unreachable'})
            finally:await connection.disconnect()
        return {'status':'protocol_ok' if all(x['status']=='protocol_ok' for x in results) else 'partial' if any(x['status']=='protocol_ok' for x in results) else 'unreachable','checks':results,'checked_at':time.time()}

    async def media(self,tag,chain=False,force=False):
        valid={x['id'] for x in self.store.config['servers']}|{'__chain'}
        for row in self.store.db.execute('SELECT id FROM telegram_sessions').fetchall():
            if row[0] not in valid:self.store.db.execute('DELETE FROM telegram_sessions WHERE id=?',row)
        self.store.db.commit()
        self.cache={k:v for k,v in self.cache.items() if k in valid}
        settings=self.store.config['telegram_probe'];key='__chain' if chain else tag
        old=self.cache.get(key,{'status':'unconfigured'})
        if not settings['enabled']:return {'status':'unconfigured','detail':'Контрольный бот не настроен'}
        if time.time()<self.cooldown:return {'status':'limited','detail':'Telegram запросил паузу проверок'}
        if not force and (self.media_lock.locked() or time.time()-old.get('checked_at',0)<settings['interval']):return old
        async with self.media_lock:
            # One bounded MTProto file sample; never consume Bot API updates or publish messages.
            try:
                async with asyncio.timeout(settings['timeout']+20):result=await self._media(tag,chain)
            except TimeoutError:result={'status':'stalled','detail':'Контрольная передача не завершилась'}
            result['checked_at']=time.time();self.cache[key]=result
            return result

    async def _media(self,tag,chain):
        s=self.store.config['telegram_probe'];key='__chain' if chain else tag
        identity=hashlib.sha256((str(s['api_id'])+s['api_hash']+s['bot_token']).encode()).hexdigest()
        stored=self.store.db.execute('SELECT session FROM telegram_sessions WHERE id=? AND identity=?',(key,identity)).fetchone()
        session=StringSession(stored[0] if stored else '')
        runtime=self.runtime
        class RouteConnection(ConnectionTcpIntermediate):
            async def _connect(self,timeout=None,ssl=None):
                async with asyncio.timeout(timeout or 10):
                    self._reader,self._writer=await socks_open(12085,self._ip,self._port,tag,runtime.password)
                    self._codec=self.packet_codec(self);self._init_conn();await self._writer.drain()
        options={'connection':RouteConnection}
        if chain:
            client=next((u for u in self.store.config['clients'] if u.get('enabled') and u.get('telegram')),None)
            if not client:return {'status':'unconfigured'}
            options={'connection':FakeTLSConnection,'proxy':('127.0.0.1',self.store.config['settings']['telegram_port'],self.store.config['telegram_probe']['internal_secret'])}
        client=TelegramClient(session,int(s['api_id']),s['api_hash'],receive_updates=False,auto_reconnect=False,connection_retries=0,request_retries=0,flood_sleep_threshold=0,timeout=10,**options)
        try:
            async with asyncio.timeout(s['timeout']):
                await client.connect()
                if not await client.is_user_authorized():await client.sign_in(bot_token=s['bot_token'])
                self.store.db.execute('INSERT OR REPLACE INTO telegram_sessions VALUES(?,?,?)',(key,identity,session.save()));self.store.db.commit()
                await client(functions.help.GetConfigRequest())
                if not s['file_id']:return {'status':'unconfigured','detail':'Укажите file_id контрольного файла из Telegram'}
                media=utils.resolve_bot_file_id(s['file_id'])
                if media is None:return {'status':'configuration_error','detail':'Не удалось прочитать file_id контрольного файла'}
                # Bot API file IDs map to input locations without requiring chat-history access.
                location=utils.get_input_location(media)
                start=time.monotonic();received=0;limit=s['sample_kb']*1024
                async for chunk in client.iter_download(location[1],dc_id=location[0],request_size=65536,limit=(limit+65535)//65536):
                    received+=len(chunk)
                elapsed=time.monotonic()-start
                if received<65536:return {'status':'configuration_error','detail':'Контрольный файл должен быть не меньше 64 КБ'}
                return {'status':'media_ok','bytes':received,'kbps':round(received/max(elapsed,.001)/1024),'seconds':round(elapsed,2),'dc':location[0],'detail':'Получен фрагмент файла через MTProto; это не проверка всех видео Telegram'}
        except asyncio.CancelledError:raise
        except Exception as exc:
            from telethon.errors import FloodWaitError, RPCError
            if isinstance(exc,FloodWaitError):self.cooldown=time.time()+min(max(exc.seconds,60),86400);return {'status':'limited','detail':'Telegram ограничил частоту; проверки временно отложены'}
            if isinstance(exc,RPCError):return {'status':'configuration_error','detail':'Telegram отклонил контрольный запрос: '+type(exc).__name__}
            return {'status':'stalled','detail':'Передача контрольного файла не завершилась за отведённое время'}
        finally:await client.disconnect()
