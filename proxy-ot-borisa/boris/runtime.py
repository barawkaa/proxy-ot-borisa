"""Validated core replacement, bounded process logs, health-based restart with backoff."""
import asyncio
import json
import os
import secrets
import time
from collections import deque
from pathlib import Path
import aiohttp
from .model import client_enabled
from .routing import core_config
from .storage import atomic_json


class Runtime:
    def __init__(self, store):
        self.store=store
        self.tmp=Path(os.environ.get('BORIS_TMP','/tmp/boris-v5')); self.tmp.mkdir(parents=True,exist_ok=True)
        self.binary=os.environ.get('SINGBOX_BIN','/usr/local/bin/sing-box')
        self.mtg_binary=os.environ.get('MTG_BIN','/usr/local/bin/mtg-multi')
        self.password=secrets.token_urlsafe(24);self.api_secret=secrets.token_urlsafe(24)
        self.process=None; self.mtg=None;self.selected='';self.lock=asyncio.Lock()
        self.last_good=None;self.last_mtg=None;self.error='';self.tg_error='';self.restarts=0
        self.next_restart=0;self.failures=0;self.tg_failures=0;self.tg_next=0
        self.started=0;self.tg_started=0;self.output=deque(maxlen=80);self.readers=set();self.tg_hash=''

    async def api(self,path,method='GET',data=None):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
            async with session.request(method,'http://127.0.0.1:19090'+path,headers={'Authorization':'Bearer '+self.api_secret},json=data) as r:
                r.raise_for_status()
                return await r.json(content_type=None) if r.status!=204 else {}

    async def _read(self, process, name):
        while True:
            line=await process.stdout.readline()
            if not line:break
            # Raw core logs stay only in bounded RAM, and are never exposed/exported.
            self.output.append((name,line[:1000]))

    async def _spawn(self,args):
        proc=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT,limit=65536)
        task=asyncio.create_task(self._read(proc,args[0]));self.readers.add(task);task.add_done_callback(self.readers.discard)
        return proc

    async def _stop(self,proc):
        if proc and proc.returncode is None:
            proc.terminate()
            try:await asyncio.wait_for(proc.wait(),5)
            except TimeoutError:proc.kill();await proc.wait()

    async def check(self,cfg):
        path=self.tmp/'check.json';atomic_json(path,cfg)
        proc=await asyncio.create_subprocess_exec(self.binary,'check','-c',str(path),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
        try:output,_=await asyncio.wait_for(proc.communicate(),10)
        except TimeoutError:
            proc.kill();await proc.wait();raise ValueError('Проверка конфигурации ядром превысила время') from None
        finally:path.unlink(missing_ok=True)
        if proc.returncode:
            # Only field/schema context; raw values may contain secrets.
            text=output.decode(errors='replace')
            import re
            field=re.search(r'unknown field "([\w-]+)"',text)
            raise ValueError('Ядро отклонило конфигурацию'+(': неизвестное поле '+field[1] if field else ' (параметры или сочетание протокола/транспорта)'))

    async def validate_servers(self,servers):
        # Per-node validation prevents one unsupported node taking down all proxies.
        for s in servers:
            cfg={'outbounds':[{**s['outbound'],'tag':'test'}]}
            try:await self.check(cfg);s.pop('error',None)
            except ValueError as e:s['error']=str(e)
        return servers

    async def _ready(self):
        for _ in range(30):
            if self.process.returncode is not None:break
            try:await self.api('/version');return
            except (aiohttp.ClientError,TimeoutError):await asyncio.sleep(.1)
        raise RuntimeError('Ядро не запустилось: проверьте порты и конфигурацию')

    async def apply(self,config):
        async with self.lock:
            cfg=core_config(config,self.password,self.api_secret,self.selected)
            await self.check(cfg)
            if cfg==self.last_good and self.process and self.process.returncode is None:
                await self.apply_mtg(config);return
            old=self.last_good
            await self._stop(self.process)
            path=self.tmp/'core.json';atomic_json(path,cfg)
            try:
                self.process=await self._spawn([self.binary,'run','-c',str(path)])
                await self._ready()
            except Exception:
                await self._stop(self.process)
                if old:
                    atomic_json(path,old)
                    self.process=await self._spawn([self.binary,'run','-c',str(path)])
                    await self._ready()
                self.error='Новая конфигурация не запустилась; выполнен возврат к предыдущей'
                raise RuntimeError(self.error) from None
            self.last_good=cfg;self.started=time.time();self.error='';self.next_restart=0
            chosen=next(x['default'] for x in cfg['outbounds'] if x['tag']=='vpn')
            self.selected='' if chosen=='unavailable' else chosen
            await self.apply_mtg(config)

    async def select(self,tag):
        async with self.lock:
            await self.api('/proxies/vpn','PUT',{'name':tag or 'unavailable'})
            self.selected=tag
            if self.last_good:
                for o in self.last_good['outbounds']:
                    if o.get('tag')=='vpn':o['default']=tag or 'unavailable'

    def mtg_config(self,c):
        s=c['settings'];usage=self.store.usage()
        users=[u for u in c['clients'] if client_enabled(u) and u.get('telegram') and (not u.get('monthly_limit_gb') or sum(usage.get(u['id'],{}).values())<u['monthly_limit_gb']*1024**3)]
        if not s['telegram_enabled'] or not users:return ''
        q=json.dumps
        lines=[f'bind-to = "0.0.0.0:{s["telegram_port"]}"','api-bind-to = "127.0.0.1:19091"','prefer-ip = "prefer-ipv4"','auto-update = false',
               '[network]','dns = "https://1.1.1.1/dns-query"','proxies = ["socks5://127.0.0.1:12084"]',
               '[network.timeout]','tcp = "10s"','http = "10s"','idle = "10m"','handshake = "10s"',
               '[defense.blocklist]','enabled = false','[stats.prometheus]','enabled = false',
               '[throttle]',f'max-connections = {s["max_connections"]}','check-interval = "5s"','[secrets]']
        lines.extend(q(u['username'])+' = '+q(u['telegram_secret']) for u in users)
        return '\n'.join(lines)+'\n'

    async def apply_mtg(self,c,force=False):
        content=self.mtg_config(c)
        if content==self.last_mtg and not force and (not content or self.mtg and self.mtg.returncode is None):return
        await self._stop(self.mtg);self.mtg=None
        if not content:self.last_mtg='';self.tg_error='';return
        path=self.tmp/'mtg.toml';path.write_text(content);path.chmod(0o600)
        try:
            self.mtg=await self._spawn([self.mtg_binary,'run',str(path)])
            await asyncio.sleep(.4)
            if self.mtg.returncode is not None:raise RuntimeError()
            self.last_mtg=content;self.tg_started=time.time();self.tg_error=''
        except (OSError,RuntimeError):
            self.tg_error='MTProxy не запустился. Проверьте порт и секреты клиентов.'
            self.store.event('error',self.tg_error)

    async def stats(self):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
            async with session.get('http://127.0.0.1:19091/stats') as r:
                r.raise_for_status();return await r.json()

    async def watch(self,config):
        now=time.time()
        if now>=self.next_restart:
            try:
                if not self.process or self.process.returncode is not None:raise RuntimeError()
                await self.api('/version')
                if now-self.started>300:self.failures=0
            except (RuntimeError,aiohttp.ClientError,TimeoutError):
                self.failures+=1;self.next_restart=now+min(300,5*2**min(self.failures,6))
                self.store.event('recovery','Ядро недоступно. Автоматическое восстановление.')
                try:
                    await self._stop(self.process);await self.apply(config);self.restarts+=1
                except Exception:
                    self.next_restart=now+min(300,5*2**min(self.failures,6))
                    self.error='Ядро не восстановилось; следующая попытка после паузы'
        if self.mtg_config(config)!=self.last_mtg:
            await self.apply_mtg(config)
        if self.mtg_config(config) and now>=self.tg_next:
            try:
                if not self.mtg or self.mtg.returncode is not None:raise RuntimeError()
                await self.stats()
                if now-self.tg_started>300:self.tg_failures=0
            except (RuntimeError,aiohttp.ClientError,TimeoutError):
                self.tg_failures+=1;self.tg_next=now+min(300,5*2**min(self.tg_failures,6))
                await self.apply_mtg(config,True)

    def status(self):
        return {'core':bool(self.process and self.process.returncode is None),'telegram':bool(self.mtg and self.mtg.returncode is None),
                'error':self.error,'telegram_error':self.tg_error,'restarts':self.restarts,'selected':self.selected}

    async def close(self):
        await self._stop(self.mtg);await self._stop(self.process)
        for task in self.readers:task.cancel()
