import re
from unittest.mock import AsyncMock
import unittest
import test_api
from boris.subscriptions import parse_payload


class Release52(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=test_api.ApiTests.asyncSetUp
    asyncTearDown=test_api.ApiTests.asyncTearDown
    post=test_api.ApiTests.post

    async def test_assets_are_complete_and_versioned(self):
        html=await (await self.client.get('/')).text()
        urls=re.findall(r'(?:src|href)="(assets/[^"]+)"',html)
        self.assertEqual(len(urls),3)
        self.assertNotIn('/static/',html)
        self.assertNotIn('__BUILD__',html)
        self.assertIn('width="56" height="56"',html)
        for url in urls:
            response=await self.client.get('/'+url)
            self.assertEqual(response.status,200)
            self.assertEqual(await response.read(),(self.app.ui/url.rsplit('/',1)[1]).read_bytes())
        self.assertEqual((await self.client.get('/assets/wrong/app.js')).status,404)
        self.assertEqual((await self.client.get('/static/app.js')).status,404)

    async def prepare_selection(self):
        c=self.app.store.snapshot()
        c['servers']=parse_payload('socks5://example.com:1080#old\nsocks5://example.net:1080#new')['servers']
        self.app.store.save(c)
        old,new=[x['id'] for x in c['servers']]
        self.app.runtime.selected=old
        async def select(tag):self.app.runtime.selected=tag
        self.app.runtime.select=AsyncMock(side_effect=select)
        return old,new

    async def test_manual_failure_restores_previous_without_saving_mode(self):
        old,new=await self.prepare_selection()
        original=self.app.store.snapshot()
        self.app.health.usable=lambda tag:tag==old
        self.app.health.url_check=AsyncMock(side_effect=[{'status':'unreachable'},{'status':'unreachable'},{'status':'ok'}])
        response=await self.post('select',{'id':new})
        self.assertEqual(response.status,400)
        self.assertIn('восстановлено',(await response.json())['error'])
        self.assertEqual(self.app.runtime.selected,old)
        self.assertEqual(self.app.store.config,original)

    async def test_manual_failure_without_reserve_closes_route(self):
        old,new=await self.prepare_selection()
        original=self.app.store.snapshot()
        self.app.health.usable=lambda tag:False
        self.app.health.url_check=AsyncMock(return_value={'status':'unreachable'})
        response=await self.post('select',{'id':new})
        self.assertEqual(response.status,400)
        self.assertEqual(self.app.runtime.selected,'')
        self.assertEqual(self.app.store.config,original)

    async def test_failed_rollback_also_closes_route(self):
        old,new=await self.prepare_selection()
        self.app.health.usable=lambda tag:tag==old
        self.app.health.url_check=AsyncMock(return_value={'status':'unreachable'})
        self.assertEqual((await self.post('select',{'id':new})).status,400)
        self.assertEqual(self.app.runtime.selected,'')

    async def test_confirmed_manual_selection_saves_mode(self):
        old,new=await self.prepare_selection()
        self.app.health.url_check=AsyncMock(return_value={'status':'ok'})
        response=await self.post('select',{'id':new})
        self.assertEqual(response.status,200)
        self.assertEqual(self.app.runtime.selected,new)
        self.assertEqual(self.app.store.config['settings']['manual_server'],new)
        self.assertEqual(self.app.store.config['settings']['selection'],'manual')
