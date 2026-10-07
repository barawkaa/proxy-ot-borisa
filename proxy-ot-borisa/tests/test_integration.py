"""Real sing-box integration, enabled in CI; never silently skipped there."""
import asyncio
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
import aiohttp
from aiohttp import web
from boris.model import defaults,client_new
from boris.storage import Store,atomic_json
from boris.runtime import Runtime
from boris.gateway import Gateway,socks_open
from boris.subscriptions import normalize

@unittest.skipUnless(os.environ.get('CORE_INTEGRATION')=='1','Set CORE_INTEGRATION=1 on a Linux host with network capabilities')
class RealCoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();os.environ['BORIS_TMP']=self.tmp.name+'/runtime';self.store=Store(self.tmp.name)
        self.c=defaults();self.user=client_new('Test');self.c['clients']=[self.user]
        self.c['servers']=[normalize('Local reference',{'type':'socks','server':'127.0.0.1','server_port':18088},'manual')]
        self.store.save(self.c);self.runtime=Runtime(self.store);self.gateway=Gateway(self.store)
        reference={'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':18088}],'outbounds':[{'type':'direct','tag':'direct'}]}
        p=Path(self.tmp.name)/'reference.json';atomic_json(p,reference)
        self.reference=await asyncio.create_subprocess_exec(self.runtime.binary,'run','-c',str(p),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        await asyncio.sleep(.3)
        await self.runtime.apply(self.c);await self.runtime.select(self.c['servers'][0]['id']);await self.gateway.apply()
        async def ok(request):return web.Response(text='BORIS_INTEGRATION_OK')
        app=web.Application();app.router.add_get('/ok',ok)
        self.runner=web.AppRunner(app);await self.runner.setup();await web.TCPSite(self.runner,'127.0.0.1',18111).start()
        async def echo(r,w):
            try:
                while data:=await r.read(65536):w.write(data);await w.drain()
            finally:w.close()
        self.echo=await asyncio.start_server(echo,'127.0.0.1',18112)
    async def asyncTearDown(self):
        await self.gateway.close();await self.runtime.close();await self.runner.cleanup();self.echo.close();await self.echo.wait_closed()
        self.reference.terminate();await self.reference.wait();self.store.db.close();self.tmp.cleanup()
    async def test_http_authentication_and_tunnel(self):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get('http://127.0.0.1:18111/ok',proxy='http://127.0.0.1:2081') as r:self.assertEqual(r.status,407)
            async with session.get('http://127.0.0.1:18111/ok',proxy='http://127.0.0.1:2081',proxy_auth=aiohttp.BasicAuth(self.user['username'],self.user['password'])) as r:self.assertEqual(await r.text(),'BORIS_INTEGRATION_OK')
        # CONNECT must relay arbitrary bytes, not just browser GET requests.
        r,w=await asyncio.open_connection('127.0.0.1',2081)
        token=base64.b64encode((self.user['username']+':'+self.user['password']).encode()).decode()
        w.write(f'CONNECT 127.0.0.1:18112 HTTP/1.1\r\nHost: 127.0.0.1:18112\r\nProxy-Authorization: Basic {token}\r\n\r\n'.encode());await w.drain()
        self.assertIn(b'200',await asyncio.wait_for(r.readuntil(b'\r\n\r\n'),5))
        payload=os.urandom(128*1024);w.write(payload);await w.drain();self.assertEqual(await asyncio.wait_for(r.readexactly(len(payload)),5),payload);w.close();await w.wait_closed()
    async def test_socks_auth_and_history(self):
        r,w=await socks_open(2080,'127.0.0.1',18112,self.user['username'],self.user['password']);w.write(b'hello');await w.drain();self.assertEqual(await r.readexactly(5),b'hello');w.close();await w.wait_closed();await asyncio.sleep(.1);self.gateway.flush()
        records=self.store.list('sessions');self.assertTrue(any(x['client_id']==self.user['id'] and x['upload']==5 for x in records))
        with self.assertRaises(OSError):await socks_open(2080,'127.0.0.1',18112,self.user['username'],'wrong')
    async def test_trusted_http(self):
        c=self.store.snapshot();c['security'].update(trusted_enabled=True,trusted=[{'cidr':'127.0.0.1/32','client_id':self.user['id'],'protocols':['http']}]);self.store.save(c)
        async with aiohttp.ClientSession() as session:
            async with session.get('http://127.0.0.1:18111/ok',proxy='http://127.0.0.1:2081') as r:self.assertEqual(await r.text(),'BORIS_INTEGRATION_OK')
    async def test_watchdog_restores_and_retains_selection(self):
        old_pid=self.runtime.process.pid;tag=self.runtime.selected;self.runtime.process.kill();await self.runtime.process.wait();await self.runtime.watch(self.c)
        self.assertNotEqual(self.runtime.process.pid,old_pid);self.assertEqual(self.runtime.selected,tag);self.assertEqual((await self.runtime.api('/proxies/vpn'))['now'],tag)
    async def test_rejected_config_does_not_stop_working_process(self):
        old_pid=self.runtime.process.pid;bad=self.store.snapshot();bad['servers'][0]['outbound']['unknown_field']=True
        with self.assertRaises(ValueError):await self.runtime.apply(bad)
        self.assertEqual(self.runtime.process.pid,old_pid);self.assertIsNone(self.runtime.process.returncode)
    async def test_fail_closed(self):
        await self.runtime.select('')
        with self.assertRaises(OSError):await socks_open(2080,'127.0.0.1',18112,self.user['username'],self.user['password'])
    async def test_probe_and_switch_preserve_existing_stream(self):
        from boris.health import Health
        import copy
        other=copy.deepcopy(self.c['servers'][0]);other['id']='second_path';other['name']='Second';self.c['servers'].append(other)
        await self.runtime.apply(self.c)
        first=self.c['servers'][0]['id'];await self.runtime.select(first)
        r,w=await socks_open(2080,'127.0.0.1',18112,self.user['username'],self.user['password'])
        h=Health(self.store,self.runtime)
        check=await h.url_check(other['id'],'http://127.0.0.1:18111/ok')
        self.assertEqual(check['status'],'ok');self.assertEqual(self.runtime.selected,first)
        await self.runtime.select(other['id'])
        w.write(b'after-switch');await w.drain();self.assertEqual(await asyncio.wait_for(r.readexactly(12),3),b'after-switch')
        w.close();await w.wait_closed()

    async def test_mtg_config_and_stats(self):
        self.c['settings']['telegram_enabled']=True;await self.runtime.apply_mtg(self.c)
        for _ in range(50):
            try:
                stats=await self.runtime.stats();self.assertIn('users',stats);break
            except (aiohttp.ClientError,TimeoutError):await asyncio.sleep(.2)
        else:self.fail('MTProxy stats API did not start')
        self.assertIsNone(self.runtime.mtg.returncode)


    async def test_mtg_authenticated_front_gateway(self):
        from boris.telegram_probe import fake_open
        self.c['settings']['telegram_enabled']=True;self.store.save(self.c)
        await self.runtime.apply_mtg(self.c);await self.gateway.apply()
        async with asyncio.timeout(10):
            r,w=await fake_open(self.c['settings']['telegram_port'],self.user['telegram_secret'])
        self.assertTrue(any(x.get('client_id')==self.user['id'] for x in self.gateway.tg_connections.values()))
        self.gateway.disconnect(self.user['id'])
        await asyncio.wait_for(r.reader.read(),3);w.close();await w.wait_closed()
        bad=client_new()['telegram_secret']
        with self.assertRaises((OSError,asyncio.IncompleteReadError)):
            async with asyncio.timeout(5):await fake_open(self.c['settings']['telegram_port'],bad)

    async def test_ip_proxy_approval_and_private_destination_denied(self):
        self.c['access']['enabled']=True;self.store.save(self.c)
        await self.runtime.apply(self.c);await self.gateway.apply()
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get('http://127.0.0.1:18111/ok',proxy='http://127.0.0.1:2084') as r:self.assertEqual(r.status,403)
            self.gateway.access.update('127.0.0.1',{'status':'approved'})
            try:
                async with session.get('http://127.0.0.1:18111/ok',proxy='http://127.0.0.1:2084') as r:self.assertNotEqual(r.status,200)
            except (aiohttp.ClientError,TimeoutError):pass

if __name__=='__main__':unittest.main()
