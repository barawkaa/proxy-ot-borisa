import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
from boris.model import defaults,client_new,validate
from boris.subscriptions import parse_payload
from boris.storage import Store
from boris.migration import migrate
from boris.routing import core_config,explain
from boris.health import Health,rank
from boris.gateway import Gateway

UID='11111111-1111-4111-8111-111111111111'
def vless(name='🇳🇱 Нидерланды ⭐',host='example.com',q=''):
    from urllib.parse import quote
    return f'vless://{UID}@{host}:443?security=tls&sni=example.com{q}#{quote(name)}'

class ImportTests(unittest.TestCase):
    def test_unicode_name_and_full_identity(self):
        a=parse_payload(vless())['servers'][0];b=parse_payload(vless(q='&type=ws&path=%2Fws'))['servers'][0]
        self.assertEqual(a['name'],'🇳🇱 Нидерланды ⭐');self.assertNotEqual(a['id'],b['id']);self.assertNotEqual(a['id'],parse_payload(vless(),'another')['servers'][0]['id'])
    def test_base64(self):
        import base64
        self.assertEqual(len(parse_payload(base64.b64encode(vless().encode()).decode())['servers']),1)
    def test_xray_array(self):
        x=[{'remarks':'🇬🇧 Великобритания','outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'example.com','port':443,'users':[{'id':UID,'flow':'xtls-rprx-vision'}]}]},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':'example.com','publicKey':'abc','shortId':'ff','fingerprint':'chrome'}}}]}]
        r=parse_payload(json.dumps(x));self.assertEqual(len(r['servers']),1);self.assertEqual(r['servers'][0]['name'],'🇬🇧 Великобритания');self.assertIn('reality',r['servers'][0]['outbound']['tls'])
    def test_clash_mixed_and_transport(self):
        data='''proxies:
  - name: Германия
    type: vless
    server: example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    network: ws
    ws-opts:
      path: /hello
      headers:
        Host: test.com
  - name: Trojan
    type: trojan
    server: example.com
    port: 443
    password: testing
'''
        r=parse_payload(data);self.assertEqual(len(r['servers']),2);self.assertEqual(r['servers'][0]['outbound']['transport']['headers']['Host'],'test.com')
    def test_errors_are_not_silenced_or_secret(self):
        r=parse_payload(vless()+'\n'+vless(name='bad',q='&type=xhttp'));self.assertEqual(len(r['errors']),1);self.assertEqual(r['received'],2);self.assertNotIn(UID,json.dumps(r['errors']))
    def test_ss(self):
        import base64
        auth=base64.b64encode(b'aes-128-gcm:test').decode().rstrip('=');r=parse_payload('ss://'+auth+'@example.com:8388#SS');self.assertEqual(r['servers'][0]['outbound']['password'],'test')
    def test_no_dedup_by_host(self):
        r=parse_payload(vless(q='&type=ws&path=%2Fone')+'\n'+vless(q='&type=ws&path=%2Ftwo'));self.assertEqual(len(r['servers']),2)
    def test_duplicate_connection(self):
        r=parse_payload(vless()+'\n'+vless());self.assertEqual(len(r['servers']),1);self.assertEqual(r['duplicates'],1)
    def test_detour_rejected(self):
        r=parse_payload(json.dumps([{'type':'trojan','server':'x','server_port':443,'password':'x','detour':'other'}]));self.assertEqual(len(r['servers']),0);self.assertEqual(len(r['errors']),1)

class ConfigTests(unittest.TestCase):
    def setUp(self):self.c=defaults();self.c['clients']=[client_new('Борис')]
    def test_valid(self):validate(self.c)
    def test_port_conflict(self):
        self.c['settings']['http_port']=self.c['settings']['socks_port']
        with self.assertRaises(ValueError):validate(self.c)
    def test_credentials_unique(self):
        self.c['clients'].append(copy.deepcopy(self.c['clients'][0]))
        with self.assertRaises(ValueError):validate(self.c)
    def test_direct_exceptions_first(self):
        self.c['routing'].update(mode='selected',vpn_domains=['example.com'],direct_domains=['safe.example.com'])
        self.assertEqual(explain(self.c,'safe.example.com')['route'],'direct');self.assertEqual(explain(self.c,'sub.example.com')['route'],'vpn');self.assertEqual(explain(self.c,'other.com')['route'],'direct')
    def test_per_client_mode(self):
        u=self.c['clients'][0];u['route_mode']='direct';self.assertEqual(explain(self.c,'anything.com',u)['route'],'direct')
    def test_fail_closed_and_isolated_probe(self):
        self.c['servers']=parse_payload(vless())['servers'];cfg=core_config(self.c,'password','secret');vpn=next(x for x in cfg['outbounds'] if x['tag']=='vpn')
        self.assertEqual(vpn['default'],'unavailable');self.assertNotIn('direct',vpn['outbounds']);self.assertFalse(vpn['interrupt_exist_connections'])
        probe=next(x for x in cfg['route']['rules'] if x.get('auth_user')==[self.c['servers'][0]['id']]);self.assertEqual(probe['inbound'],['probes'])

class StorageTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.store=Store(self.tmp.name)
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def test_atomic_previous_and_cleanup(self):
        c=defaults();self.store.save(c);c['settings']['history_days']=2;self.store.save(c);self.assertEqual(json.loads((Path(self.tmp.name)/'config-v5.previous.json').read_text())['settings']['history_days'],7)
        self.store.event('test','same');self.store.event('test','same');self.assertEqual(self.store.list('events')[0]['count'],2);self.store.cleanup(True);self.assertFalse(self.store.list('events'))
    def test_migration_preserves_source_and_secrets(self):
        user=client_new('Борис');root=Path(self.tmp.name);old=[{**user,'http_enabled':True,'socks_enabled':True,'telegram_enabled':True}]
        (root/'proxy_users.json').write_text(json.dumps(old));original=(root/'proxy_users.json').read_bytes();migrate(self.store);migrate(self.store)
        self.assertEqual(self.store.config['clients'][0]['telegram_secret'],user['telegram_secret']);self.assertEqual((root/'proxy_users.json').read_bytes(),original)

class SelectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(self.tmp.name);self.c=defaults();self.c['servers']=parse_payload(vless(host='a.com')+'\n'+vless(host='b.com'))['servers'];self.store.save(self.c)
        self.runtime=type('Runtime',(),{'selected':'','select':AsyncMock(),'password':'p'})();self.health=Health(self.store,self.runtime);self.health.url_check=AsyncMock(return_value={'status':'ok'})
    async def asyncTearDown(self):self.store.db.close();self.tmp.cleanup()
    async def test_reserve_lower_ping_not_preferred(self):
        a,b=[x['id'] for x in self.c['servers']];self.health.results={a:{'checked_at':time.time(),'foreign_ok':True,'russian_ok':False,'latency_ms':20},b:{'checked_at':time.time(),'foreign_ok':True,'russian_ok':True,'latency_ms':200}}
        await self.health.choose();self.runtime.select.assert_awaited_with(b);self.health.results[b]['foreign_ok']=False;await self.health.choose(True);self.runtime.select.assert_awaited_with(a)
    async def test_hysteresis(self):
        a,b=[x['id'] for x in self.c['servers']];self.runtime.selected=a;self.health.results={a:{'checked_at':time.time(),'foreign_ok':True,'russian_ok':True,'latency_ms':100},b:{'checked_at':time.time(),'foreign_ok':True,'russian_ok':True,'latency_ms':90}}
        await self.health.choose();self.runtime.select.assert_not_awaited()
    async def test_stale_results(self):self.assertEqual(rank({'foreign_ok':True,'checked_at':time.time()-601})[0],9)
    async def test_manual_does_not_return_to_dead_server(self):
        a,b=[x['id'] for x in self.c['servers']];self.c['settings'].update(selection='manual',manual_server=a);self.store.save(self.c);self.health.results={a:{'foreign_ok':False,'checked_at':time.time()},b:{'foreign_ok':True,'checked_at':time.time(),'latency_ms':40}}
        await self.health.choose();self.runtime.select.assert_awaited_with(b)

class AccessTests(unittest.TestCase):
    def test_trusted_is_bound_to_client_and_protocol(self):
        with tempfile.TemporaryDirectory() as d:
            s=Store(d);c=defaults();u=client_new();c['clients']=[u];c['security'].update(trusted_enabled=True,trusted=[{'cidr':'192.168.1.2/32','client_id':u['id'],'protocols':['http']}]);s.save(c);g=Gateway(s)
            self.assertEqual(g.trusted('192.168.1.2','http')['id'],u['id']);self.assertIsNone(g.trusted('192.168.1.3','http'));self.assertIsNone(g.trusted('192.168.1.2','socks'));self.assertIsNone(g.authenticate(u['username'],'wrong','http'));s.db.close()

if __name__=='__main__':unittest.main()

class MoreRegressionTests(unittest.TestCase):
    def test_native_profile_array_name(self):
        profile=[{'remarks':'🇫🇷 Франция','outbounds':[{'type':'trojan','tag':'proxy','server':'example.com','server_port':443,'password':'p'},{'type':'direct','tag':'direct'}]}]
        r=parse_payload(json.dumps(profile));self.assertEqual(len(r['servers']),1);self.assertEqual(r['servers'][0]['name'],'🇫🇷 Франция')
    def test_history_cap(self):
        with tempfile.TemporaryDirectory() as d:
            store=Store(d);c=defaults();c['settings']['event_records']=3;store.save(c)
            for i in range(8):store.event('test',str(i))
            self.assertEqual(len(store.list('events')),3);store.db.close()
