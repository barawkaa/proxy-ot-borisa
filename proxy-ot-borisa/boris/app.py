"""HA Ingress API and independent scheduling. All config mutations are serialized."""
import asyncio
import contextlib
import copy
import io
import ipaddress
import json
import os
import re
import secrets
import time
import urllib.parse
from pathlib import Path
import aiohttp
from aiohttp import web
import qrcode
import qrcode.image.svg
from . import VERSION
from .model import validate, client_new, client_enabled
from .storage import Store, atomic_json
from .migration import migrate
from .runtime import Runtime
from .gateway import Gateway
from .health import Health
from .subscriptions import parse_payload, fetch_subscription
from .routing import explain


class Application:
    def __init__(self,root):
        self.store=Store(root);migrate(self.store)
        self.runtime=Runtime(self.store);self.gateway=Gateway(self.store);self.health=Health(self.store,self.runtime)
        self.mutation=asyncio.Lock();self.jobs={};self.background=[];self.stopping=False;self.heartbeat=time.time()
        self.tg_stats={};self.tg_previous={};self.tg_active={};self.boot_error='';self.booted=False;self.current_task=None
        self.source_retry={};self.last_cleanup=0;self.last_rules=0;self.active_job=None;self.last_flush=0;self.next_boot=0;self.core_connections=[]
        self.ui=Path(__file__).resolve().parent.parent/'ui'
        self.web=web.Application(client_max_size=8*1024**2,middlewares=[self.guard])
        self.web.router.add_get('/healthz',self.healthz)
        self.web.router.add_get('/api/state',self.state)
        self.web.router.add_get('/api/history',self.history)
        self.web.router.add_get('/api/backup',self.backup)
        self.web.router.add_get('/api/qr/{uid}',self.qr)
        self.web.router.add_post('/api/{action}',self.command)
        self.web.router.add_get('/',self.index)
        self.web.router.add_static('/static/',self.ui)
        self.web.on_startup.append(self.start)
        self.web.on_cleanup.append(self.close)

    @web.middleware
    async def guard(self,request,handler):
        # Never trust X-Forwarded-For as authentication. HA's actual Ingress peer only.
        peer=request.transport.get_extra_info('peername') if request.transport else None
        allowed={'172.30.32.2','127.0.0.1','::1'}
        if not peer or peer[0] not in allowed:return web.json_response({'error':'Откройте приложение через Home Assistant'},status=403)
        if request.method=='POST' and (request.headers.get('X-Boris-Request')!='1' or request.content_type!='application/json'):
            return web.json_response({'error':'Неверный запрос'},status=403)
        try:response=await handler(request)
        except (ValueError,KeyError,TypeError) as e:
            message=str(e) if isinstance(e,ValueError) else 'Некорректные поля запроса'
            return web.json_response({'error':message[:500]},status=400)
        except web.HTTPException:raise
        except Exception:
            self.store.event('error','Ошибка операции API. Предыдущее состояние сохранено.');return web.json_response({'error':'Операция не выполнена. Проверьте диагностику.'},status=500)
        response.headers['Cache-Control']='no-store';response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'"
        return response

    async def index(self,request):return web.FileResponse(self.ui/'index.html')
    async def healthz(self,request):
        # Supervisor must recover a dead scheduler, not reboot on a provider outage.
        return web.json_response({'alive':not self.stopping,'scheduler':time.time()-self.heartbeat<90},status=200 if time.time()-self.heartbeat<90 else 503)

    async def state(self,request):
        c=self.store.snapshot();s=c['settings']
        for u in c['clients']:
            host=s['public_host'];u['tg_url']='tg://proxy?'+urllib.parse.urlencode({'server':host,'port':s['telegram_port'],'secret':u['telegram_secret']}) if host else ''
            u['tme_url']='https://t.me/proxy?'+u['tg_url'].split('?',1)[1] if host else ''
        return web.json_response({'version':VERSION,'config':c,'runtime':self.runtime.status(),'results':self.health.results,
            'selection_reason':self.health.reason,'checks':self.health.progress,'jobs':list(self.jobs.values()),
            'active':list(self.gateway.active.values()),'telegram_stats':self.tg_stats,'telegram_active':list(self.tg_active.values()),
            'usage':self.store.usage(),'events':self.store.list('events',30),'boot_error':self.boot_error,'booted':self.booted,
            'storage_bytes':(self.store.root/'history-v5.sqlite').stat().st_size})
    async def history(self,request):return web.json_response({'sessions':self.store.list('sessions',request.query.get('limit',200)),'events':self.store.list('events',request.query.get('limit',200))})
    async def backup(self,request):
        return web.json_response({'version':VERSION,'config':self.store.snapshot()},headers={'Content-Disposition':'attachment; filename="proxy-boris-5.0-backup.json"'})
    async def qr(self,request):
        u=next(x for x in self.store.config['clients'] if x['id']==request.match_info['uid']);s=self.store.config['settings']
        if not s['public_host']:raise ValueError('Укажите адрес подключения в настройках прокси')
        link='tg://proxy?'+urllib.parse.urlencode({'server':s['public_host'],'port':s['telegram_port'],'secret':u['telegram_secret']})
        image=qrcode.make(link,image_factory=qrcode.image.svg.SvgPathImage);b=io.BytesIO();image.save(b)
        return web.Response(body=b.getvalue(),content_type='image/svg+xml')

    def job(self,title,func):
        if self.active_job and not self.active_job.done():raise ValueError('Дождитесь завершения текущей операции')
        uid=secrets.token_hex(8);record={'id':uid,'title':title,'state':'running','started':time.time()};self.jobs[uid]=record
        async def run():
            try:record['result']=await func();record['state']='done'
            except asyncio.CancelledError:record['state']='cancelled';raise
            except Exception as e:
                record['state']='error';record['error']=str(e)[:400] if isinstance(e,ValueError) else 'Операция не выполнена; прежние настройки сохранены'
                self.store.event('error',record['error'])
            finally:record['ended']=time.time()
        self.active_job=asyncio.create_task(run())
        while len(self.jobs)>20:self.jobs.pop(next(iter(self.jobs)))
        return {'job_id':uid}

    async def commit(self,c):
        c=validate(c);old=self.store.snapshot()
        await self.runtime.apply(c)
        try:
            self.store.save(c);await self.gateway.apply()
        except Exception:
            self.store.save(old);await self.runtime.apply(old);await self.gateway.apply();raise
        self.store.event('settings','Настройки сохранены')

    async def refresh_source(self,source_id):
        async with self.mutation:
            c=self.store.snapshot();source=next(x for x in c['sources'] if x['id']==source_id)
            self.source_retry[source_id]=time.time()+300
            proxy=('http://__selected:'+self.runtime.password+'@127.0.0.1:12085') if self.runtime.selected else None
            parsed=await fetch_subscription(source['url'],source_id,proxy)
            await self.runtime.validate_servers(parsed['servers'])
            old={s['id']:s for s in c['servers'] if s['source_id']==source_id}
            for node in parsed['servers']:
                if node['id'] in old:
                    for k in ('enabled','auto','priority'):node[k]=old[node['id']].get(k,node[k])
            # An incomplete refresh must never silently delete previous working nodes.
            partial=bool(parsed['errors'] or any(x.get('error') for x in parsed['servers']))
            nodes={x['id']:x for x in parsed['servers']}
            if partial:
                for key,node in old.items():nodes.setdefault(key,node)
            c['servers']=[s for s in c['servers'] if s['source_id']!=source_id]+list(nodes.values())
            source.update(updated_at=time.time(),received=parsed['received'],imported=len(parsed['servers']),errors=parsed['errors'],variants=parsed['variants'],traffic=parsed['traffic'],partial=partial)
            await self.commit(c)
            self.store.event('subscription','Подписка обновлена'+(' частично; прежние серверы сохранены' if partial else ''))
            return {'received':parsed['received'],'imported':len(parsed['servers']),'errors':parsed['errors']}

    async def command(self,request):
        action=request.match_info['action'];b=await request.json()
        if action=='check':return web.json_response(self.job('Проверка серверов',lambda:self.health.scan(True)))
        if action=='refresh':return web.json_response(self.job('Обновление подписки',lambda:self.refresh_source(b['id'])))
        if action=='rules':return web.json_response(self.job('Обновление списков',self.update_rules))
        if action=='diagnostics':return web.json_response(self.job('Проверка приложения',self.diagnostics))
        if action=='restart':return web.json_response(self.job('Восстановление сервисов',self.restart))
        if action=='disconnect':self.gateway.disconnect(b.get('id',''));return web.json_response({'ok':True})
        if action=='cleanup':return web.json_response(self.store.cleanup(bool(b.get('clear'))))
        if action=='route-test':
            u=next((x for x in self.store.config['clients'] if x['id']==b.get('client_id')),None)
            return web.json_response(explain(self.store.config,b['host'],u))
        async with self.mutation:
            c=self.store.snapshot()
            if action=='select':
                tag=b.get('id','');mode='manual' if tag else 'auto'
                if tag and not any(x['id']==tag for x in self.health.candidates()):raise ValueError('Сервер недоступен для выбора')
                if tag:await self.health.switch(tag,'Ручной выбор')
                c['settings'].update(selection=mode,manual_server=tag);self.store.save(c)
                if not tag:await self.health.choose()
                return web.json_response({'ok':True})
            if action=='settings':
                for section in ('settings','routing','security'):
                    if section in b:c[section].update(b[section])
            elif action=='client':
                uid=b.get('id');existing=next((u for u in c['clients'] if u['id']==uid),None)
                if b.get('delete'):
                    c['clients']=[u for u in c['clients'] if u['id']!=uid];c['security']['trusted']=[x for x in c['security']['trusted'] if x['client_id']!=uid];self.gateway.disconnect(uid)
                else:
                    u=existing or client_new(b.get('name','Клиент'),c['settings']['front_domain'])
                    for k in ('name','username','password','telegram_secret','enabled','http','socks','telegram','route_mode','expires_at','blocked_until','monthly_limit_gb','notes'):
                        if k in b:u[k]=b[k]
                    if b.get('rotate'):
                        new=client_new(u['name'],c['settings']['front_domain']);u['password']=new['password'];u['telegram_secret']=new['telegram_secret']
                    if not existing:c['clients'].append(u)
                    else:self.gateway.disconnect(uid)
            elif action=='source':
                uid=b.get('id') or secrets.token_hex(8);existing=next((x for x in c['sources'] if x['id']==uid),None)
                if b.get('delete'):
                    c['sources']=[x for x in c['sources'] if x['id']!=uid];c['servers']=[x for x in c['servers'] if x['source_id']!=uid]
                else:
                    source=existing or {'id':uid,'name':'Подписка','url':'','enabled':True,'auto':True,'interval':3600,'updated_at':0}
                    for k in ('name','url','enabled','auto','interval'):
                        if k in b:source[k]=b[k]
                    if not existing:c['sources'].append(source)
            elif action=='import':
                parsed=parse_payload(b['text']);await self.runtime.validate_servers(parsed['servers'])
                if not parsed['servers']:raise ValueError('Ничего не импортировано: '+json.dumps(parsed['errors'],ensure_ascii=False))
                nodes={s['id']:s for s in c['servers']};nodes.update({s['id']:s for s in parsed['servers']});c['servers']=list(nodes.values())
                await self.commit(c);return web.json_response({'ok':True,'imported':len(parsed['servers']),'errors':parsed['errors']})
            elif action=='server':
                node=next(x for x in c['servers'] if x['id']==b['id'])
                if b.get('delete'):c['servers'].remove(node)
                else:
                    for k in ('enabled','auto','priority','name'):
                        if k in b:node[k]=b[k]
            elif action=='restore':c=b['config'];await self.runtime.validate_servers(c['servers'])
            else:raise ValueError('Неизвестная операция')
            await self.commit(c)
        return web.json_response({'ok':True})

    async def update_rules(self):
        async with self.mutation:
            c=self.store.snapshot();directory=self.store.root/'rules-v5';directory.mkdir(exist_ok=True)
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                for rule in c['routing']['sources']:
                    if not rule.get('enabled'):continue
                    if not re.fullmatch('[A-Za-z0-9_-]{1,80}',rule['id']):raise ValueError('Недопустимый ID списка')
                    async with session.get(rule['url']) as r:
                        r.raise_for_status();body=await r.content.read(8*1024**2+1)
                        if len(body)>8*1024**2:raise ValueError('Список больше 8 МБ')
                    # Content-addressed file: never overwrite last-good before validation.
                    import hashlib
                    digest=hashlib.sha256(body).hexdigest()[:16];path=directory/(rule['id']+'-'+digest+('.srs' if rule['format']=='binary' else '.json'))
                    if rule['format']=='binary':path.write_bytes(body);rule['cache_format']='binary'
                    else:
                        values=[x.strip() for x in body.decode().splitlines() if x.strip() and not x.lstrip().startswith('#')]
                        key=rule.get('kind','domain_suffix')
                        if key not in ('domain_suffix','ip_cidr'):raise ValueError('Неверный тип текстового списка')
                        atomic_json(path,{'version':3,'rules':[{key:values}]});rule['cache_format']='source'
                    rule['cache_path']=str(path);rule['updated_at']=time.time()
                if c['security']['country_enabled']:
                    async with session.get(c['security']['country_url']) as r:
                        r.raise_for_status();raw=await r.content.read(1024**2)
                    c['security']['country_cidrs']=[str(ipaddress.ip_network(x.strip())) for x in raw.decode().splitlines() if x.strip()]
            await self.commit(c)
            keep={x.get('cache_path') for x in c['routing']['sources']}
            for p in directory.iterdir():
                if str(p) not in keep:p.unlink()
            self.last_rules=time.time();return {'ok':True}

    async def diagnostics(self):
        results=[{'name':'Процесс ядра','ok':self.runtime.status()['core']}, {'name':'Планировщик','ok':time.time()-self.heartbeat<90}]
        try:await self.runtime.api('/version');results.append({'name':'Управление ядром','ok':True})
        except Exception:results.append({'name':'Управление ядром','ok':False})
        await self.health.scan(True)
        results.append({'name':'Рабочий VPN','ok':bool(self.runtime.selected),'detail':self.health.reason})
        s=self.store.config['settings']
        for protocol in ('http','socks'):
            if not s[protocol+'_enabled']:continue
            try:
                r,w=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',s[protocol+'_port']),2);w.close();await w.wait_closed()
                results.append({'name':protocol.upper()+' вход','ok':True,'detail':'Порт принимает соединения'})
            except OSError:results.append({'name':protocol.upper()+' вход','ok':False})
        return results

    async def restart(self):
        async with self.mutation:
            await self.runtime._stop(self.runtime.process);await self.runtime.apply(self.store.snapshot());await self.gateway.apply()
        await self.health.current_check();return self.runtime.status()

    async def sample_telegram(self):
        if not self.runtime.status()['telegram']:
            self.tg_stats={};self.tg_previous={}
            records=[]
            for rec in self.tg_active.values():rec['ended']=time.time();rec['result']='service_stopped';records.append(rec)
            if records:self.store.sessions(records)
            self.tg_active={}
            return
        stats=await self.runtime.stats();users=stats.get('users',{});records=[]
        for u in self.store.config['clients']:
            x=users.get(u['username'],{});key=u['id'];counters=(int(x.get('bytes_in',0)),int(x.get('bytes_out',0)))
            prev=self.tg_previous.get(key,(0,0));self.gateway.usage_pending[key][0]+=max(0,counters[0]-prev[0]);self.gateway.usage_pending[key][1]+=max(0,counters[1]-prev[1]);self.tg_previous[key]=counters
            if x.get('connections',0)>0:
                if key not in self.tg_active:self.tg_active[key]={'id':secrets.token_hex(12),'client_id':key,'name':u['name'],'protocol':'telegram','ip':'не предоставлен ядром','destination':'Telegram','started':time.time(),'ended':0,'upload':0,'download':0,'result':'active'}
                rec=self.tg_active[key];rec['upload']+=max(0,counters[0]-prev[0]);rec['download']+=max(0,counters[1]-prev[1])
            elif key in self.tg_active:
                rec=self.tg_active.pop(key);rec['ended']=time.time();rec['result']='closed';records.append(rec)
        if records:self.store.sessions(records)
        self.tg_stats=users

    async def scheduler(self):
        while not self.stopping:
            self.heartbeat=time.time()
            try:
                if not self.booted and time.time()>=self.next_boot and self.background[0].done():
                    self.next_boot=time.time()+60
                    await self.bootstrap()
                if self.booted:
                    if not self.mutation.locked():
                        async with self.mutation:await self.runtime.watch(self.store.snapshot())
                    try:await self.sample_telegram()
                    except (aiohttp.ClientError,TimeoutError):self.tg_stats={}
                    now=time.time();s=self.store.config['settings']
                    if now-self.last_flush>=30:
                        self.gateway.flush();self.store.cleanup();self.last_flush=now
                    if now-self.last_cleanup>=3600:self.store.cleanup();self.last_cleanup=now
                    if now-self.health.last_current>=s['check_interval'] and (not self.current_task or self.current_task.done()):
                        self.current_task=asyncio.create_task(self.check_current())
                    if not self.active_job or self.active_job.done():
                        if now-self.health.last_full>=s['availability_interval']:self.job('Проверка доступности',lambda:self.health.scan(True))
                        elif now-self.health.last_scan>=s['scan_interval']:self.job('Проверка задержки',lambda:self.health.scan(False))
                        else:
                            due=next((x for x in self.store.config['sources'] if x.get('enabled') and now-x.get('updated_at',0)>=max(300,int(x.get('interval',s['subscription_interval']))) and now>=self.source_retry.get(x['id'],0)),None)
                            if due:self.job('Автообновление подписки',lambda uid=due['id']:self.refresh_source(uid))
                            elif any(x.get('enabled') for x in self.store.config['routing']['sources']) and now-self.last_rules>self.store.config['routing']['update_interval']:
                                self.last_rules=now;self.job('Автообновление списков',self.update_rules)
            except asyncio.CancelledError:raise
            except Exception:self.store.event('error','Фоновая проверка не завершилась; будет повторена')
            await asyncio.sleep(10)

    async def check_current(self):
        try:await self.health.current_check()
        except asyncio.CancelledError:raise
        except Exception:self.store.event('error','Проверка текущего подключения не завершилась; будет повторена')

    async def bootstrap(self):
        try:
            c=self.store.snapshot();await self.runtime.validate_servers(c['servers']);await self.commit(c);self.booted=True;self.boot_error=''
            self.job('Первая проверка серверов',lambda:self.health.scan(True))
        except Exception as e:self.boot_error=str(e) if isinstance(e,ValueError) else 'Сервисы не запустились. Проверьте диагностику и порты.'

    async def start(self,app):
        self.background=[asyncio.create_task(self.bootstrap()),asyncio.create_task(self.scheduler())]
    async def close(self,app):
        self.stopping=True
        tasks=self.background+([self.active_job] if self.active_job else [])+([self.current_task] if self.current_task else [])
        for t in tasks:t.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await self.gateway.close();await self.runtime.close();self.store.db.close()


def main():
    os.umask(0o077)
    app=Application(os.environ.get('BORIS_DATA','/data'))
    web.run_app(app.web,host='0.0.0.0',port=int(os.environ.get('BORIS_WEB_PORT','8099')),access_log=None,print=None)
