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
web.run_app(app.web,host='127.0.0.1',port=18099,access_log=None)
