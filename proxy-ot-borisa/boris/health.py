"""Measured reachability and hysteresis; no pretend 'ping' from a listening TCP port."""
import asyncio
import statistics
import time
from collections import deque
import aiohttp
from .gateway import socks_open


def rank(result,now=None):
    now=time.time() if now is None else now
    if not result or now-result.get('checked_at',0)>600 or not result.get('foreign_ok'):return (9,999999)
    tier=0 if result.get('russian_ok') else 1
    return (tier,float(result.get('latency_ms') or 99999)+result.get('failure_rate',0)*1000)


class Health:
    def __init__(self,store,runtime):
        self.store=store;self.runtime=runtime;self.results={};self.history={};self.lock=asyncio.Lock()
        self.last_switch=0;self.reason='Ожидание проверки';self.progress={'running':False,'done':0,'total':0}
        self.last_scan=0;self.last_full=0;self.last_current=0;self.after_switch={}

    def candidates(self):
        c=self.store.config;sources={x['id']:x for x in c['sources']}
        return [s for s in c['servers'] if s.get('enabled',True) and not s.get('error') and sources.get(s['source_id'],{}).get('enabled',True)]

    async def url_check(self,tag,url):
        timeout=self.store.config['settings']['check_timeout'];start=time.monotonic()
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout),trust_env=False) as session:
                async with session.get(url,proxy='http://127.0.0.1:12085',proxy_auth=aiohttp.BasicAuth(tag,self.runtime.password),allow_redirects=True,max_redirects=3) as r:
                    await r.content.read(1024)
                    status='ok' if 200<=r.status<400 else 'restricted' if r.status in (401,403,429,451) else 'error'
                    return {'status':status,'http_status':r.status,'ms':round((time.monotonic()-start)*1000),'url':url}
        except (aiohttp.ClientError,TimeoutError):
            return {'status':'unreachable','ms':None,'url':url}

    async def telegram_check(self,tag):
        for target in self.store.config['settings']['telegram_targets'][:3]:
            try:
                host,port=target.rsplit(':',1)
                async with asyncio.timeout(self.store.config['settings']['check_timeout']):
                    _,w=await socks_open(12085,host,int(port),tag,self.runtime.password)
                    w.close();await w.wait_closed()
                    return {'status':'tcp_ok','detail':'Доступен TCP-вход Telegram; клиентская MTProto-сессия этим не подтверждается'}
            except (OSError,TimeoutError,ValueError,asyncio.IncompleteReadError):continue
        return {'status':'unreachable'}

    async def probe(self,server,full=True):
        tag=server['id'];s=self.store.config['settings'];old=self.results.get(tag,{})
        foreign=await asyncio.gather(*(self.url_check(tag,u) for u in s['foreign_urls']))
        lat=[x['ms'] for x in foreign if x['status']=='ok']
        hist=self.history.setdefault(tag,deque(maxlen=1440));hist.append((time.time(),bool(lat)))
        while hist and hist[0][0]<time.time()-86400:hist.popleft()
        res={**old,'foreign':foreign,'foreign_ok':bool(lat),'latency_ms':round(statistics.median(lat)) if lat else None,
             'checked_at':time.time(),'failure_rate':sum(not x[1] for x in hist)/len(hist)}
        if full:
            ru,services,tg=await asyncio.gather(asyncio.gather(*(self.url_check(tag,u) for u in s['russian_urls'])),
                asyncio.gather(*(self.url_check(tag,u) for u in s['service_urls'])),self.telegram_check(tag))
            res.update(russian=ru,russian_ok=all(x['status']=='ok' for x in ru),services=services,telegram=tg,full_at=time.time())
        elif time.time()-res.get('full_at',0)>600:res['russian_ok']=False
        self.results[tag]=res
        return res

    async def scan(self,full=True):
        if self.lock.locked():return
        async with self.lock:
            servers=self.candidates();sem=asyncio.Semaphore(self.store.config['settings']['parallel_checks'])
            self.progress={'running':True,'done':0,'total':len(servers)}
            async def run(s):
                async with sem:
                    try:await self.probe(s,full)
                    finally:self.progress['done']+=1
            try:
                await asyncio.gather(*(run(s) for s in servers))
                self.last_scan=time.time()
                if full:self.last_full=time.time()
                await self.choose()
            finally:self.progress['running']=False

    async def choose(self,failed=False):
        c=self.store.config;s=c['settings'];sources={x['id']:x for x in c['sources']}
        candidates=[x for x in self.candidates() if x.get('auto',True) and sources.get(x['source_id'],{}).get('auto',True)]
        if s['selection']=='manual' and not failed:
            target=s['manual_server']
            if target and any(x['id']==target for x in self.candidates()) and (not s['manual_failover'] or self.results.get(target,{}).get('foreign_ok')):
                if self.runtime.selected!=target:await self.switch(target,'Ручной выбор')
                return
        if s['selection']=='manual' and failed and not s['manual_failover']:
            self.reason='Выбранный вручную сервер недоступен; автоматическая замена отключена';return
        ordered=sorted(candidates,key=lambda x:(rank(self.results.get(x['id'])),x.get('priority',50)))
        ordered=[x for x in ordered if rank(self.results.get(x['id']))[0]<9]
        if not ordered:
            self.reason='Рабочий VPN не найден. Повторная проверка выполняется автоматически.'
            if failed:await self.runtime.select('')
            return
        best=ordered[0]['id'];current=self.runtime.selected
        br=rank(self.results.get(best));cr=rank(self.results.get(current))
        if best==current:return
        if not failed and cr[0]<9:
            if time.time()-self.last_switch<s['switch_hold_seconds']:return
            if br[0]>cr[0] or br[0]==cr[0] and br[1]+s['switch_margin_ms']>=cr[1]:return
        await self.switch(best,'Восстановление после отказа' if failed else 'Выбран лучший проверенный сервер')

    async def switch(self,tag,reason):
        await self.runtime.select(tag)
        self.last_switch=time.time();self.reason=reason
        self.store.event('selection',reason)
        # Test through the real selected selector, not just the candidate outbound.
        url=self.store.config['settings']['foreign_urls'][0]
        self.after_switch=await self.url_check('__selected',url)
        if self.after_switch['status']!='ok':
            self.after_switch=await self.url_check('__selected',self.store.config['settings']['foreign_urls'][-1])
        if self.after_switch['status']!='ok':
            self.reason='Сервер переключён, но итоговая проверка не прошла'
            if tag in self.results:self.results[tag]['foreign_ok']=False
            self.last_current=0

    async def current_check(self):
        if self.lock.locked():return
        async with self.lock:
            self.last_current=time.time()
            current=next((s for s in self.candidates() if s['id']==self.runtime.selected),None)
            if current:
                first=await self.probe(current,False)
                if first['foreign_ok']:return
                second=await self.probe(current,True)
                if second['foreign_ok']:return
            # Confirmed failure: renew candidates now, not on the next scheduled scan.
            sem=asyncio.Semaphore(self.store.config['settings']['parallel_checks'])
            ordered=sorted(self.candidates(),key=lambda x:rank(self.results.get(x['id'])))
            async def run(s):
                async with sem:await self.probe(s,True)
            # Try a small best-known batch first to shorten recovery; then the rest.
            for offset in range(0,len(ordered),6):
                await asyncio.gather(*(run(x) for x in ordered[offset:offset+6] if not current or x['id']!=current['id']))
                if any(rank(self.results.get(x['id']))[0]<9 for x in ordered[offset:offset+6]):break
            await self.choose(failed=True)
