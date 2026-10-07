"""Continuous, bounded checks and explainable selection of confirmed VPN paths."""
import asyncio
import statistics
import time
from collections import deque
import aiohttp
from .gateway import socks_open


def group_status(checks):
    if not checks:return 'unknown'
    states=[x.get('status') for x in checks]
    if all(x=='ok' for x in states):return 'available'
    if any(x=='ok' for x in states):return 'partial'
    if any(x=='restricted' for x in states):return 'restricted'
    return 'unreachable'


def rank(result,now=None):
    now=time.time() if now is None else now
    if not result or now-result.get('checked_at',0)>180 or not result.get('foreign_ok'):return (9,9,999999)
    ru=result.get('russian_status', 'available' if result.get('russian_ok') else 'unreachable')
    if now-result.get('full_at',result.get('checked_at',0))>600:ru='unknown'
    tier=0 if ru=='available' else 1 if ru in ('partial','restricted','unknown') else 2
    # Reliability is a separate visible category, never invented milliseconds.
    reliability=1 if result.get('failure_rate',0)>=.4 else 0
    return (tier,reliability,float(result.get('median_ms',result.get('latency_ms')) or 99999))


class Health:
    def __init__(self,store,runtime):
        self.store=store;self.runtime=runtime;self.results={};self.history={};self.lock=asyncio.Lock()
        self.last_switch=0;self.reason='Ожидание проверки';self.progress={'running':False,'done':0,'total':0}
        self.last_scan=0;self.last_full=0;self.last_current=0;self.after_switch={};self.recovery_lock=asyncio.Lock()
        self.decision_lock=asyncio.Lock();self.probe_locks={};self.inflight=0;self.urgent_waiters=0;self.capacity=asyncio.Condition()
        self.decision={'reason':self.reason,'at':0,'reserve_id':'','order':[]};self.switches=deque(maxlen=20)

    def candidates(self):
        c=self.store.config;sources={x['id']:x for x in c['sources']}
        return [s for s in c['servers'] if s.get('enabled',True) and not s.get('error') and sources.get(s['source_id'],{}).get('enabled',True)]

    def ordered(self):
        c=self.store.config;sources={x['id']:x for x in c['sources']}
        nodes=[x for x in self.candidates() if x.get('auto',True) and sources.get(x['source_id'],{}).get('auto',True) and rank(self.results.get(x['id']))[0]<9]
        if c['settings']['telegram_enabled']:
            nodes=[x for x in nodes if self.results[x['id']].get('telegram',{}).get('status')=='tcp_ok' and time.time()-self.results[x['id']].get('full_at',0)<600]
        return sorted(nodes,key=lambda x:(rank(self.results[x['id']]),x.get('priority',50),x['id']))

    def describe(self,reason):
        nodes=self.ordered();current=self.runtime.selected
        self.reason=reason
        self.decision={'reason':reason,'at':time.time(),'selected_id':current,
            'reserve_id':next((x['id'] for x in nodes if x['id']!=current),''),'order':[x['id'] for x in nodes],
            'last_switch':self.last_switch,'last_scan':self.last_scan,'last_full':self.last_full,
            'next_current':self.last_current+self.store.config['settings']['check_interval'],
            'next_scan':self.last_scan+self.store.config['settings']['scan_interval']}

    async def url_check(self,tag,url):
        timeout=self.store.config['settings']['check_timeout'];start=time.monotonic()
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout),trust_env=False) as session:
                async with session.get(url,proxy='http://127.0.0.1:12085',proxy_auth=aiohttp.BasicAuth(tag,self.runtime.password),allow_redirects=True,max_redirects=3) as r:
                    await r.content.read(1024)
                    status='ok' if 200<=r.status<400 else 'restricted' if r.status in (401,403,429,451) else 'error'
                    return {'status':status,'http_status':r.status,'ms':round((time.monotonic()-start)*1000),'url':url}
        except (aiohttp.ClientError,TimeoutError):return {'status':'unreachable','ms':None,'url':url}

    async def telegram_check(self,tag):
        for target in self.store.config['settings']['telegram_targets'][:3]:
            try:
                host,port=target.rsplit(':',1)
                async with asyncio.timeout(self.store.config['settings']['check_timeout']):
                    _,w=await socks_open(12085,host,int(port),tag,self.runtime.password)
                    w.close();await w.wait_closed()
                    return {'status':'tcp_ok','detail':'TCP доступен; отправка сообщений не проверялась'}
            except (OSError,TimeoutError,ValueError,asyncio.IncompleteReadError):continue
        return {'status':'unreachable'}

    async def probe(self,server,full=True,urgent=False):
        tag=server['id']
        async with self.probe_locks.setdefault(tag,asyncio.Lock()):
            # Shared limit applies to scans, recovery and confirmation together.
            async with self.capacity:
                if urgent:self.urgent_waiters+=1
                try:
                    await self.capacity.wait_for(lambda:self.inflight<self.store.config['settings']['parallel_checks'] and (urgent or not self.urgent_waiters))
                    self.inflight+=1
                finally:
                    if urgent:self.urgent_waiters-=1
                    self.capacity.notify_all()
            try:return await self._probe(server,full)
            finally:
                async with self.capacity:
                    self.inflight-=1;self.capacity.notify_all()

    async def _probe(self,server,full):
        tag=server['id'];s=self.store.config['settings'];old=self.results.get(tag,{})
        foreign=await asyncio.gather(*(self.url_check(tag,u) for u in s['foreign_urls']))
        lat=[x['ms'] for x in foreign if x['status']=='ok' and x.get('ms') is not None]
        latency=round(statistics.median(lat)) if lat else None
        hist=self.history.setdefault(tag,deque(maxlen=10));hist.append((time.time(),latency))
        while hist and hist[0][0]<time.time()-600:hist.popleft()
        recent=[x[1] for x in hist if x[1] is not None]
        res={**old,'foreign':foreign,'foreign_ok':bool(lat),'foreign_status':group_status(foreign),'latency_ms':latency,
             'median_ms':round(statistics.median(recent)) if recent else None,'samples':len(hist),
             'checked_at':time.time(),'failure_rate':sum(x[1] is None for x in hist)/len(hist)}
        if full:
            ru,services,tg=await asyncio.gather(asyncio.gather(*(self.url_check(tag,u) for u in s['russian_urls'])),
                asyncio.gather(*(self.url_check(tag,u) for u in s['service_urls'])),self.telegram_check(tag))
            res.update(russian=ru,russian_ok=all(x['status']=='ok' for x in ru),russian_status=group_status(ru),
                       services=services,service_status=group_status(services),telegram=tg,full_at=time.time())
        elif time.time()-res.get('full_at',0)>600:res.update(russian_ok=False,russian_status='unknown')
        self.results[tag]=res
        return res

    async def scan(self,full=True):
        if self.lock.locked():return
        async with self.lock:
            servers=self.candidates();ids={x['id'] for x in servers}
            for mapping in (self.results,self.history,self.probe_locks):
                for tag in list(mapping):
                    if tag not in ids and not (mapping is self.probe_locks and mapping[tag].locked()):mapping.pop(tag,None)
            self.progress={'running':True,'done':0,'total':len(servers)}
            async def run(node):
                try:await self.probe(node,full or time.time()-self.results.get(node['id'],{}).get('full_at',0)>600)
                finally:self.progress['done']+=1
            try:
                await asyncio.gather(*(run(node) for node in servers))
                self.last_scan=time.time()
                if full:self.last_full=time.time()
                if not self.recovery_lock.locked():await self.choose()
            finally:self.progress['running']=False

    def usable(self,tag):
        r=self.results.get(tag,{})
        return rank(r)[0]<9 and (not self.store.config['settings']['telegram_enabled'] or r.get('telegram',{}).get('status')=='tcp_ok')

    async def choose(self,failed=False):
        async with self.decision_lock:await self._choose(failed)

    async def _choose(self,failed):
        c=self.store.config;s=c['settings'];current=self.runtime.selected
        if s['selection']=='manual':
            target=s['manual_server']
            if not failed and target and any(x['id']==target for x in self.candidates()) and (not s['manual_failover'] or self.usable(target)):
                if current!=target:await self.switch(target,'Возврат к ручному выбору')
                self.describe('Ручной выбор: автоматическая оптимизация задержки отключена');return
            if not s['manual_failover']:
                self.describe('Ручной сервер недоступен; автоматическая замена отключена');return
        nodes=self.ordered()
        if not nodes:
            if failed:await self.runtime.select('')
            self.describe('Нет подтверждённого сервера для включённых сервисов; проверки продолжаются');return
        best=nodes[0];br=rank(self.results[best['id']]);cr=rank(self.results.get(current))
        if best['id']==current:
            self.describe('Текущий сервер лучший по доступности, стабильности и измеренной задержке');return
        improving=not failed and self.usable(current)
        if improving:
            if br[:2]>cr[:2]:self.describe('Сохраняем текущий: у более быстрого кандидата хуже доступность или стабильность');return
            if br[:2]==cr[:2] and not self.enough(cr[2],br[2]):
                self.describe('Сохраняем текущий: выигрыш недостаточен (нужны одновременно '+str(s['switch_margin_percent'])+'% и '+str(s['switch_margin_ms'])+' мс)');return
            recent=[t for t in self.switches if time.time()-t<300]
            if len(recent)>=3 and br[:2]>=cr[:2]:self.describe('Защита от частых переключений: три смены за пять минут');return
            # Compare both paths now, twice for challenger. A large improvement bypasses old hold timer.
            node=next((x for x in self.candidates() if x['id']==current),None)
            if node:await self.probe(node,True,urgent=True)
            confirmations=[]
            for _ in range(2):
                r=await self.probe(best,True,urgent=True);confirmations.append(r.get('latency_ms'))
                if not self.usable(best['id']):self.describe('Кандидат не прошёл повторную проверку; сохраняем текущее соединение');return
            if not any(x['id']==best['id'] for x in self.ordered()):return
            fresh=self.results.get(current,{})
            current_ms=fresh.get('latency_ms');candidate_ms=max(x for x in confirmations if x is not None)
            if self.usable(current) and rank(self.results[best['id']])[:2]>=rank(fresh)[:2]:
                if current_ms is None or not self.enough(current_ms,candidate_ms):
                    self.describe('Преимущество кандидата не подтвердилось двумя измерениями');return
            reason='Подтверждено улучшение доступности или задержки'
        else:reason='Восстановление после отказа' if failed else 'Первый рабочий сервер'
        for node in [best]+[x for x in nodes if x['id']!=best['id']][:2]:
            # Settings could change while confirmation was in flight.
            if not any(x['id']==node['id'] for x in self.ordered()):continue
            if await self.switch(node['id'],reason):return
        await self.runtime.select('');self.describe('Итоговые проверки кандидатов не прошли; поиск продолжается')

    def enough(self,current,candidate):
        s=self.store.config['settings']
        return current-candidate>=s['switch_margin_ms'] and current-candidate>=current*s['switch_margin_percent']/100

    async def switch(self,tag,reason):
        previous=self.runtime.selected
        await self.runtime.select(tag)
        self.last_switch=time.time();self.switches.append(self.last_switch)
        self.after_switch=await self.url_check('__selected',self.store.config['settings']['foreign_urls'][0])
        if self.after_switch['status']!='ok':self.after_switch=await self.url_check('__selected',self.store.config['settings']['foreign_urls'][-1])
        if self.after_switch['status']!='ok':
            if tag in self.results:self.results[tag]['foreign_ok']=False
            self.last_current=0;self.describe('Итоговая проверка после переключения не прошла');return False
        def label(uid):
            node=next((x for x in self.store.config['servers'] if x['id']==uid),None)
            ms=self.results.get(uid,{}).get('latency_ms')
            return (node['name'] if node else 'нет сервера')+(f' ({ms} мс)' if ms is not None else '')
        message=f'{reason}: {label(previous)} → {label(tag)}'
        self.store.event('selection',message);self.describe(message);return True

    async def current_check(self):
        if self.recovery_lock.locked():return
        async with self.recovery_lock:
            self.last_current=time.time()
            current=next((s for s in self.candidates() if s['id']==self.runtime.selected),None)
            if current:
                await self.probe(current,True,urgent=True)
                if self.usable(current['id']):await self.choose();return
                await self.probe(current,True,urgent=True)
                if self.usable(current['id']):await self.choose();return
            ordered=sorted(self.candidates(),key=lambda x:rank(self.results.get(x['id'])))
            for offset in range(0,len(ordered),3):
                await asyncio.gather(*(self.probe(x,True,urgent=True) for x in ordered[offset:offset+3] if not current or x['id']!=current['id']))
                if self.ordered():break
            await self.choose(failed=True)
