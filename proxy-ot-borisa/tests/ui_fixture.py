import tempfile,sys
from unittest.mock import AsyncMock
from aiohttp import web
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from boris.app import Application
from boris.subscriptions import parse_payload
app=Application(tempfile.mkdtemp());app.web.on_startup.clear();app.web.on_cleanup.clear();app.runtime.apply=AsyncMock();app.gateway.apply=AsyncMock();app.runtime.select=AsyncMock()
c=app.store.snapshot();c['sources']=[{'id':'testsub','name':'Основная подписка','url':'https://example.com/sub','enabled':True,'auto':True,'interval':3600}]
c['servers']=parse_payload('vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#🇳🇱%20Нидерланды%20⭐','testsub')['servers'];app.store.save(c)
import time
from boris.model import client_new
c=app.store.snapshot();c['clients']=[client_new('Борис'),client_new('Гость')];app.store.save(c)
id=c['servers'][0]['id'];app.runtime.selected=id
app.health.results[id]={'checked_at':time.time(),'full_at':time.time(),'foreign_ok':True,'russian_ok':False,'russian_status':'partial','foreign_status':'available','service_status':'limited','latency_ms':190,'median_ms':210,'samples':6,'failure_rate':0,'telegram':{'status':'protocol_ok'}}
app.health.url_check=AsyncMock(return_value={'status':'ok','ms':190})
app.health.describe('Текущий сервер лучший по доступности, стабильности и измеренной задержке')
app.jobs={'done':{'id':'done','title':'Автообновление подписки','state':'done','background':True,'started':time.time()-20,'ended':time.time()-10}}
app.store.sessions([dict(id=str(i),client_id=u['id'],name=u['name'],protocol='http',ip='192.168.1.'+str(10+i),destination='example.com',started=time.time()-60,ended=time.time(),upload=100,download=200,result='closed') for i,u in enumerate(c['clients'])])
app.store.event('test','Событие для проверки диагностики')
app.jobs.update(running={'id':'running','title':'Тестовая текущая задача','state':'running','background':True,'started':time.time()},error={'id':'error','title':'Тестовая ошибка задачи','state':'error','error':'Проверка не выполнена','started':time.time()-30,'ended':time.time()-10})
app.gateway.active={u['id']:dict(id=u['id'],client_id=u['id'],name=u['name'],protocol='http',ip='192.168.1.10',destination='example-guest' if u['name']=='Гость' else 'example-boris',started=time.time()-20,ended=0,upload=10,download=20,result='active') for u in c['clients']}
app.gateway.access.observe('203.0.113.25')
web.run_app(app.web,host='127.0.0.1',port=18099,access_log=None)
