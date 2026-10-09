"""Cross-profile, migration, HA discovery, authorization and delivery regressions."""
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
from aiohttp import web
from aiohttp.test_utils import TestServer,TestClient
from boris.app import Application
from boris.model import defaults,PROFILES,client_new,validate
from boris.routing import core_config
from boris.storage import Store
from boris.health import Health
from boris.homeassistant import HomeAssistant,install_companion
from boris.notifications import Notifications
from boris.gateway import Gateway
from boris.runtime import Runtime


class Model54(unittest.TestCase):
    def test_service_requests_use_enabled_proxy_when_http_is_off(self):
        with tempfile.TemporaryDirectory() as root:
            store=Store(root);runtime=Runtime(store)
            runtime.selections.update(http='old',socks='working')
            store.config['settings']['http_enabled']=False
            self.assertEqual(runtime.control_username(),'__selected_socks')
            store.config['settings']['socks_enabled']=False
            self.assertEqual(runtime.control_username(),'')
            store.db.close()

    def test_migrate_all_profiles_without_losing_manual_choice_or_bot(self):
        with tempfile.TemporaryDirectory() as root:
            c=defaults();del c['profiles'];del c['notifications']['mode']
            c['settings'].update(selection='manual',manual_server='original',manual_failover=False)
            c['notifications']['token']='secret-retained'
            Path(root,'config-v5.json').write_text(json.dumps(c))
            store=Store(root)
            for v in store.config['profiles'].values():self.assertEqual((v['selection'],v['manual_server'],v['manual_failover']),('manual','original',False))
            self.assertEqual(store.config['notifications']['mode'],'direct');store.db.close()

    def test_distinct_routes_ports_and_no_anonymous_core(self):
        c=defaults();c['clients']=[client_new()];c['access']['enabled']=True
        cfg=core_config(c,'pw','api')
        tags={x['tag'] for x in cfg['outbounds']}
        self.assertTrue({'vpn','vpn_socks','vpn_telegram','vpn_http_ip'}<=tags)
        for key,port in [('http',12080),('socks',12081),('http_ip',12082)]:
            inbound=next(x for x in cfg['inbounds'] if x['tag']=='clients_'+key)
            self.assertEqual(inbound['listen_port'],port);self.assertTrue(inbound['users'])
            rules=[x for x in cfg['route']['rules'] if x.get('inbound')==['clients_'+key] and x.get('outbound') and (key!='http_ip' or x.get('auth_user')==['__access_all_vpn'])]
            self.assertTrue(rules);self.assertTrue(all(x['outbound']==('vpn' if key=='http' else 'vpn_'+key) for x in rules))
        c['access']['port']=c['settings']['socks_port']
        with self.assertRaises(ValueError):validate(c)

    def test_installation_refuses_unowned_directory_and_only_manages_own_files(self):
        with tempfile.TemporaryDirectory() as root:
            dest=Path(root,'custom_components','boris_proxy');dest.mkdir(parents=True);(dest/'mine').write_text('keep')
            with self.assertRaises(ValueError):install_companion(defaults(),root)
            self.assertEqual((dest/'mine').read_text(),'keep')
            (dest/'.managed-by-proxy-boris').touch();Path(root,'configuration.yaml').write_text('keep-ha')
            install_companion(defaults(),root)
            self.assertFalse((dest/'mine').exists());self.assertTrue((dest/'select.py').exists())
            self.assertEqual(Path(root,'configuration.yaml').read_text(),'keep-ha')
            self.assertEqual(Path(root,'boris_proxy_link.json').stat().st_mode & 0o777,0o600)


class Independent54(unittest.IsolatedAsyncioTestCase):
    async def test_telegram_failure_does_not_change_http_and_socks(self):
        with tempfile.TemporaryDirectory() as root:
            store=Store(root);c=defaults();c['settings']['telegram_enabled']=True
            c['servers']=[{'id':x,'name':x,'source_id':'manual','enabled':True,'auto':True} for x in ('fast','media')];store.save(c)
            runtime=type('Runtime',(),{'selected':'fast','selections':{p:'fast' for p in PROFILES},'password':'pw'})()
            async def select(tag,profile='http'):
                runtime.selections[profile]=tag
                if profile=='http':runtime.selected=tag
            runtime.select=AsyncMock(side_effect=select)
            h=Health(store,runtime)
            now=time.time();base={'foreign_ok':True,'checked_at':now,'full_at':now,'russian_status':'available','failure_rate':0}
            h.results={'fast':{**base,'median_ms':30,'latency_ms':30,'telegram':{'status':'unreachable'}},'media':{**base,'median_ms':200,'latency_ms':200,'telegram':{'status':'protocol_ok'}}}
            h.url_check=AsyncMock(return_value={'status':'ok','ms':200});h.telegram.chain=AsyncMock(return_value={'status':'protocol_ok'});h.telegram.media=AsyncMock(return_value={'status':'unconfigured'})
            await h.choose()
            self.assertEqual(runtime.selections['http'],'fast');self.assertEqual(runtime.selections['socks'],'fast');self.assertEqual(runtime.selections['telegram'],'media')
            runtime.select.assert_awaited_once_with('media','telegram');store.db.close()

    async def test_failed_nodes_backoff_without_stopping_current_checks(self):
        with tempfile.TemporaryDirectory() as root:
            store=Store(root);h=Health(store,None);h.url_check=AsyncMock(return_value={'status':'unreachable'})
            node={'id':'bad'}
            await h.probe(node,False);first=h.next_probe['bad']
            await h.probe(node,False);self.assertGreater(h.next_probe['bad']-first,59)
            h.url_check=AsyncMock(return_value={'status':'ok','ms':10});await h.probe(node,False)
            self.assertEqual(h.next_probe['bad'],0);store.db.close()


class Api54(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.app=Application(self.tmp.name)
        self.app.web.on_startup.clear();self.app.web.on_cleanup.clear()
        self.app.runtime.apply=AsyncMock();self.app.gateway.apply=AsyncMock()
        self.client=TestClient(TestServer(self.app.web));await self.client.start_server()
    async def asyncTearDown(self):
        await self.client.close();self.app.store.db.close();self.tmp.cleanup()
    async def test_ha_endpoint_never_trusts_localhost_without_pairing(self):
        response=await self.client.get('/api/ha/state');self.assertEqual(response.status,403)
        self.app.store.config['ha']['enabled']=True
        response=await self.client.get('/api/ha/state');self.assertEqual(response.status,403)
        token=self.app.store.config['ha']['token'];headers={'Authorization':'Bearer '+token}
        response=await self.client.get('/api/ha/state',headers=headers);self.assertEqual(response.status,200)
        body=await response.text();self.assertNotIn(token,body);self.assertNotIn('telegram_secret',body);self.assertNotIn('password',body)
        response=await self.client.post('/api/ha/command',headers=headers,json={'action':'enabled','profile':'http_ip','enabled':True});self.assertEqual(response.status,200)
        self.assertTrue(self.app.store.config['access']['enabled'])
        response=await self.client.post('/api/ha/command',headers=headers,json={'action':'client','name':'attack'});self.assertEqual(response.status,400)
        self.app.store.config['ha']['enabled']=False
        response=await self.client.get('/api/ha/state',headers=headers);self.assertEqual(response.status,403)
    async def test_all_four_ports_in_status(self):
        data=await (await self.client.get('/api/state')).json()
        self.assertEqual(data['services']['http_ip']['port'],2084)
        self.assertEqual(set(data['profiles']),set(PROFILES));self.assertNotIn('token',data['config']['ha'])
    async def test_profiles_validated_without_overwriting_siblings(self):
        old=copy.deepcopy(self.app.store.config['profiles']['socks'])
        r=await self.client.post('/api/settings',headers={'X-Boris-Request':'1'},json={'profiles':{'http':{'require_russian':True}}});self.assertEqual(r.status,200)
        self.assertEqual(self.app.store.config['profiles']['socks'],old)
        r=await self.client.post('/api/settings',headers={'X-Boris-Request':'1'},json={'profiles':{'bad':{}}});self.assertEqual(r.status,400)
    async def test_ip_grant_default_expiry_and_explicit_permanent(self):
        a=self.app.gateway.access;a.observe('203.0.113.1');r=a.update('203.0.113.1',{'status':'approved'})
        self.assertGreater(r['expires'],time.time());self.assertLess(r['expires'],time.time()+169*3600)
        r=a.update('203.0.113.1',{'status':'approved','expires':0});self.assertEqual(r['expires'],0)

    async def test_ip_route_settings_and_explanation_agree(self):
        headers={'X-Boris-Request':'1'}
        r=await self.client.post('/api/settings',headers=headers,json={'profiles':{'http_ip':{'route_mode':'direct'}}})
        self.assertEqual(r.status,200);self.assertEqual(self.app.store.config['access']['route_mode'],'direct')
        r=await self.client.post('/api/route-test',headers=headers,json={'profile':'http_ip','host':'example.com'})
        self.assertEqual((await r.json())['route'],'direct')
        r=await self.client.post('/api/settings',headers=headers,json={'access':{'route_mode':'all_vpn'}})
        self.assertEqual(r.status,200);self.assertEqual(self.app.store.config['profiles']['http_ip']['route_mode'],'all_vpn')
        self.assertEqual(self.app.store.config['profiles']['http']['route_mode'],'default')


class HA54(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls=[]
        async def ws_handler(request):
            ws=web.WebSocketResponse();await ws.prepare(request);await ws.send_json({'type':'auth_required'})
            auth=await ws.receive_json();self.assertEqual(auth['access_token'],'internal')
            await ws.send_json({'type':'auth_ok'})
            async for msg in ws:
                q=msg.json()
                result=[{'entity_id':'notify.boris','platform':'telegram_bot','config_entry_id':'bot','original_name':'Борис'},{'entity_id':'notify.other','platform':'mobile_app'}] if q['type']=='config/entity_registry/list' else [{'entry_id':'bot','domain':'telegram_bot','title':'HA bot'}]
                await ws.send_json({'id':q['id'],'type':'result','success':True,'result':result})
            return ws
        async def states(request):return web.json_response([{'entity_id':'notify.boris','state':'unknown','attributes':{'friendly_name':'Борис'}}])
        async def service(request):
            self.assertEqual(request.headers['Authorization'],'Bearer internal');self.calls.append((request.path,await request.json()));return web.json_response([])
        app=web.Application();app.router.add_get('/ws',ws_handler);app.router.add_get('/states',states);app.router.add_post('/services/{domain}/{service}',service)
        self.server=TestServer(app);await self.server.start_server();self.ha=HomeAssistant();self.ha.base=str(self.server.make_url('')).rstrip('/');self.ha.ws_url=str(self.server.make_url('/ws')).replace('http:','ws:');self.ha.token='internal'
    async def asyncTearDown(self):await self.server.close()
    async def test_discovery_and_combined_selected_and_manual_recipients(self):
        recipients=await self.ha.recipients();self.assertEqual(len(recipients['targets']),1)
        n=defaults()['notifications'];n.update(ha_targets=['notify.boris'],ha_entry_id='bot',ha_chat_ids=['-100123'])
        await self.ha.send(n,'Запрос доступа')
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0],('/services/telegram_bot/send_message',{'entity_id':['notify.boris'],'message':'Запрос доступа','parse_mode':'plain_text','chat_id':[-100123],'config_entry_id':'bot'}))
    async def test_no_bot_token_required_in_ha_mode_and_no_updates_consumed(self):
        with tempfile.TemporaryDirectory() as root:
            store=Store(root);c=defaults();c['notifications'].update(enabled=True,ha_targets=['notify.boris']);store.save(validate(c))
            runtime=type('Runtime',(),{'status':lambda self:{}})();n=Notifications(store,Gateway(store),runtime);n.ha=self.ha;n.call=AsyncMock()
            await n.test();self.assertEqual(len(self.calls),1);n.call.assert_not_awaited();store.db.close()
    async def test_removed_target_rejected_without_partial_send(self):
        n=defaults()['notifications'];n['ha_targets']=['notify.boris','notify.removed']
        with self.assertRaises(ValueError):await self.ha.send(n,'test')
        self.assertEqual(self.calls,[])

    async def test_missing_manual_bot_rejected_before_sending_to_selected_users(self):
        n=defaults()['notifications'];n.update(ha_targets=['notify.boris'],ha_entry_id='removed',ha_chat_ids=['123'])
        with self.assertRaises(ValueError):await self.ha.send(n,'test')
        self.assertEqual(self.calls,[])
