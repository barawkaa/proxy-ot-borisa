import tempfile
import unittest
from unittest.mock import AsyncMock
from aiohttp.test_utils import TestServer,TestClient
from boris.app import Application

class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.app=Application(self.tmp.name)
        self.app.web.on_startup.clear();self.app.web.on_cleanup.clear()
        self.app.runtime.apply=AsyncMock();self.app.gateway.apply=AsyncMock()
        self.client=TestClient(TestServer(self.app.web));await self.client.start_server()
    async def asyncTearDown(self):
        await self.client.close();self.app.store.db.close();self.tmp.cleanup()
    async def post(self,path,data,header=True):return await self.client.post('/api/'+path,json=data,headers={'X-Boris-Request':'1'} if header else {})
    async def test_state_and_csrf(self):
        r=await self.client.get('/api/state');self.assertEqual(r.status,200);s=await r.json();self.assertEqual(s['version'],'5.4')
        r=await self.post('client',{'name':'No'},False);self.assertEqual(r.status,403)
    async def test_client_create_secrets_and_delete(self):
        r=await self.post('client',{'name':'Борис'});self.assertEqual(r.status,200)
        c=self.app.store.config['clients'][-1];self.assertEqual(c['name'],'Борис');self.assertTrue(c['telegram_secret'].startswith('ee'))
        r=await self.post('client',{'id':c['id'],'delete':True});self.assertEqual(r.status,200);self.assertNotIn(c['id'],[x['id'] for x in self.app.store.config['clients']])
    async def test_rejected_config_not_persisted(self):
        original=self.app.store.snapshot();r=await self.post('settings',{'settings':{'http_port':2080}});self.assertEqual(r.status,400);self.assertEqual(self.app.store.config,original)
    async def test_source_isolated_deletion(self):
        for name in ['one','two']:
            r=await self.post('source',{'name':name,'url':'https://example.com/'+name});self.assertEqual(r.status,200)
        one,two=self.app.store.config['sources'];await self.post('source',{'id':one['id'],'delete':True});self.assertEqual(self.app.store.config['sources'],[two])
    async def test_qr_no_external_service(self):
        await self.post('settings',{'settings':{'public_host':'example.com'}});uid=self.app.store.config['clients'][0]['id']
        r=await self.client.get('/api/qr/'+uid);self.assertEqual(r.status,200);self.assertIn('<svg',await r.text())
    async def test_backup_removed_and_report_redacted(self):
        r=await self.client.get('/api/backup');self.assertIn(r.status,(404,405))
        r=await self.post('restore',{'config':self.app.store.snapshot()});self.assertEqual(r.status,400)
        c=self.app.store.config;secret=c['clients'][0]['telegram_secret']
        r=await self.client.get('/api/report');self.assertEqual(r.status,200);text=await r.text()
        self.assertNotIn(secret,text);self.assertNotIn(c['clients'][0]['password'],text)
        self.assertIn('decision',text);self.assertIn('results',text)

    async def test_history_filters_before_limit(self):
        rows=[]
        for i in range(205):
            rows.append(dict(id=str(i),client_id='a' if i<3 else 'b',name='A' if i<3 else 'B',protocol='http',ip='127.0.0.1',destination='example.com',started=i,ended=i+1,upload=0,download=0,result='closed'))
        self.app.store.sessions(rows)
        r=await self.client.get('/api/history?client_id=a&limit=2');data=await r.json()
        self.assertEqual(len(data['sessions']),2);self.assertTrue(all(x['client_id']=='a' for x in data['sessions']))
        self.assertEqual(len(data['clients']),2)


if __name__=='__main__':unittest.main()

class TransferTests(unittest.IsolatedAsyncioTestCase):
    async def test_subscription_chunked_body_is_complete(self):
        import asyncio
        from aiohttp import web
        from boris.subscriptions import fetch_subscription
        payload='vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#First\nvless://22222222-2222-4222-8222-222222222222@example.net:443?security=tls#Second'
        async def fragmented(request):
            response=web.StreamResponse();await response.prepare(request)
            for chunk in [payload[:40],payload[40:100],payload[100:]]:
                await response.write(chunk.encode());await asyncio.sleep(.01)
            await response.write_eof();return response
        app=web.Application();app.router.add_get('/sub',fragmented)
        async with TestServer(app) as server:
            result=await fetch_subscription(str(server.make_url('/sub')),'test')
            self.assertEqual(len(result['servers']),2)
    async def test_oversized_stream_rejected(self):
        from boris.subscriptions import read_limited
        class Stream:
            async def iter_chunked(self,n):
                yield b'123';yield b'456'
        with self.assertRaises(ValueError):await read_limited(Stream(),5)
