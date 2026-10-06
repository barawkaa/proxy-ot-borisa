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
        r=await self.client.get('/api/state');self.assertEqual(r.status,200);s=await r.json();self.assertEqual(s['version'],'5.0')
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
    async def test_backup(self):
        r=await self.client.get('/api/backup');self.assertEqual(r.status,200);self.assertIn('attachment',r.headers['Content-Disposition']);self.assertEqual((await r.json())['config']['schema'],5)

if __name__=='__main__':unittest.main()
