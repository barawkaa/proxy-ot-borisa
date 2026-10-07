import asyncio
import copy
import hashlib
import hmac
import tempfile
import time
import unittest
from unittest.mock import AsyncMock,patch
from boris.storage import Store
from boris.gateway import Gateway
from boris.model import defaults,client_new,validate
from boris.access import Access
from boris.notifications import Notifications
from boris.telegram_probe import client_hello,identify_hello,direct_exchange,pq_request,valid_pq
from boris.routing import core_config
from boris.health import Health,group_status


class Access53(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.store=Store(self.tmp.name);self.access=Access(self.store)
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def test_pending_approval_pause_revoke_expiry_persist(self):
        row=self.access.observe('203.0.113.2');self.assertEqual(row['status'],'pending');self.assertIsNone(self.access.user(row['ip']))
        self.access.update(row['ip'],{'status':'approved'});self.assertIsNotNone(self.access.user(row['ip']))
        self.access.update(row['ip'],{'status':'paused'});self.assertIsNone(self.access.user(row['ip']))
        self.access.update(row['ip'],{'status':'approved','expires':time.time()+10})
        self.assertEqual(Access(self.store).get(row['ip'])['status'],'approved')
        with patch('boris.access.time.time',return_value=time.time()+20):self.assertIsNone(self.access.user(row['ip']))
        self.access.update(row['ip'],{'status':'blocked','expires':0});self.assertIsNone(self.access.user(row['ip']))
    def test_explicit_lan_only_and_cidr_revocation(self):
        self.store.config['access']['lan_cidrs']=['192.168.1.0/24']
        self.assertIsNotNone(self.access.user('192.168.1.20'));self.assertIsNone(self.access.user('10.0.0.20'))
        self.store.config['access']['lan_cidrs']=[];self.assertIsNone(self.access.user('192.168.1.20'))
    def test_invitation_is_bound_and_does_not_grant(self):
        token,_=self.access.invite('Guest');self.assertTrue(self.access.redeem(token,'203.0.113.5'))
        self.assertEqual(self.access.get('203.0.113.5')['invited'],1)
        self.assertIsNone(self.access.user('203.0.113.5'));self.assertEqual(self.access.get('203.0.113.5')['invited'],2)
        self.assertFalse(self.access.redeem(token,'203.0.113.6'))
        self.assertNotIn(token,str(self.store.db.execute('SELECT * FROM invitations').fetchall()))
    def test_bounds_and_stale_callback(self):
        self.store.config['access']['pending_limit']=10
        for n in range(20):self.access.observe('203.0.113.'+str(n+1))
        self.assertEqual(len(self.access.rows()),10)
        row=self.access.rows()[0];self.access.update(row['ip'],{'status':'blocked'})
        with self.assertRaises(ValueError):self.access.update(row['ip'],{'status':'approved'},row['revision'])
    def test_config_upgrade_preserves_personal_data(self):
        c=defaults();c.pop('access');c.pop('notifications');c.pop('telegram_probe');c['security'].pop('auth_failures');c['settings'].pop('http_auth');c['clients']=[client_new('Boris')]
        secret=c['clients'][0]['telegram_secret'];self.store.save(c)
        other=Store(self.tmp.name)
        try:self.assertEqual(validate(other.config)['clients'][0]['telegram_secret'],secret)
        finally:other.db.close()
    def test_access_internal_routes_and_no_open_anonymous_core(self):
        c=defaults();c['access']['enabled']=True;cfg=core_config(c,'private','secret')
        users=cfg['inbounds'][0]['users'];self.assertEqual(len(users),5);self.assertTrue(all(u['password'] for u in users))
        self.assertTrue(any(r.get('ip_is_private') and r['action']=='reject' for r in cfg['route']['rules']))
    def test_bad_ports_and_lan_range_rejected(self):
        for cidr in ['0.0.0.0/0','127.0.0.0/8','8.8.8.0/24']:
            c=defaults();c['access']['lan_cidrs']=[cidr]
            with self.assertRaises(ValueError):validate(c)
        c=defaults();c['access']['port']=12086
        with self.assertRaises(ValueError):validate(c)
    def test_secret_client_hello_verified_not_only_tls(self):
        user=client_new();packet=client_hello(user['telegram_secret'])
        self.assertEqual(identify_hello(packet,[user]),user)
        forged=bytearray(packet);forged[15]^=1
        self.assertIsNone(identify_hello(bytes(forged),[user]))
        with patch('boris.telegram_probe.time.time',return_value=time.time()+600):self.assertIsNone(identify_hello(packet,[user]))


class Gateway53(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(self.tmp.name);self.gateway=Gateway(self.store)
        self.store.config['access']['enabled']=True;self.hits=0
        async def upstream(r,w):
            self.hits+=1
            try:
                await r.readuntil(b'\r\n\r\n');w.write(b'HTTP/1.1 200 Connection established\r\n\r\n');await w.drain()
                while data:=await r.read(1024):w.write(data);await w.drain()
            except (OSError,asyncio.IncompleteReadError):pass
            finally:w.close()
        self.up=await asyncio.start_server(upstream,'127.0.0.1',12080)
        self.listener=await asyncio.start_server(lambda r,w:self.gateway.accept(r,w,'http_ip'),'127.0.0.1',0)
        self.port=self.listener.sockets[0].getsockname()[1]
    async def asyncTearDown(self):
        self.listener.close();await self.listener.wait_closed();await self.gateway.close();self.up.close();await self.up.wait_closed();self.store.db.close();self.tmp.cleanup()
    async def request(self,packet=b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n'):
        r,w=await asyncio.open_connection('127.0.0.1',self.port);w.write(packet);await w.drain();return r,w
    async def test_unknown_denied_before_outbound_then_approve_transfer_revoke(self):
        r,w=await self.request();self.assertIn(b'403',await r.read());w.close();await w.wait_closed();self.assertEqual(self.hits,0)
        row=self.gateway.access.get('127.0.0.1');self.assertEqual(row['status'],'pending')
        self.gateway.access.update('127.0.0.1',{'status':'approved'})
        r,w=await self.request();self.assertIn(b'200',await r.readuntil(b'\r\n\r\n'))
        w.write(b'hello');await w.drain();self.assertEqual(await r.readexactly(5),b'hello')
        self.gateway.access.update('127.0.0.1',{'status':'blocked'});self.gateway.disconnect_ip('127.0.0.1')
        self.assertEqual(await asyncio.wait_for(r.read(),2),b'');w.close();await w.wait_closed()
        await asyncio.sleep(.01);self.gateway.flush();self.assertEqual(self.store.list('sessions')[0]['client_id'],row['id'])
    async def test_scanner_does_not_create_pending(self):
        for packet in [b'GET / HTTP/1.1\r\nHost: foo\r\n\r\n',b'SSH-2.0-test\r\n\r\n',b'CONNECT invalid HTTP/1.1\r\n\r\n']:
            r,w=await self.request(packet);await r.read();w.close();await w.wait_closed()
        self.assertEqual(self.gateway.access.rows(),[]);self.assertEqual(self.hits,0)
    async def test_failed_auth_is_bounded_and_bans(self):
        for _ in range(10):self.gateway.auth_failed('203.0.113.9')
        self.assertFalse(self.gateway.permitted('203.0.113.9'));self.assertTrue(self.gateway.security_state())
        self.gateway.attempts={str(i):[time.time()] for i in range(4096)}
        self.assertFalse(self.gateway.permitted('203.0.113.10'));self.assertEqual(len(self.gateway.attempts),4096)
    async def test_trusted_mode_rejects_password_even_valid(self):
        user=client_new();self.store.config['clients']=[user];self.store.config['settings']['http_auth']='trusted'
        self.assertIsNone(self.gateway.authenticate(user['username'],user['password'],'http'))
    async def test_bot_shared_mode_never_gets_updates_and_deduplicates(self):
        n=self.store.config['notifications'];n.update(enabled=True,chat_id='1',owner_id='2')
        notification=Notifications(self.store,self.gateway,type('Runtime',(),{'selected':''})());notification.call=AsyncMock(return_value={})
        token,_=self.gateway.access.invite('Guest');self.gateway.access.redeem(token,'203.0.113.4')
        await notification.tick();notification.call.assert_not_awaited()
        self.gateway.access.user('203.0.113.4');await notification.tick()
        self.assertEqual(notification.call.await_args.args[0],'sendMessage');notification.next_send=0
        await notification.tick();self.assertEqual(notification.call.await_count,1)
    async def test_bot_requires_owner_and_current_request(self):
        n=self.store.config['notifications'];n.update(chat_id='1',owner_id='2')
        notify=Notifications(self.store,self.gateway,type('Runtime',(),{})());notify.call=AsyncMock()
        row=self.gateway.access.observe('203.0.113.8')
        item={'id':'cb','from':{'id':3},'message':{'chat':{'id':1},'message_id':1},'data':'allow:'+row['id']+':'+row['revision']}
        await notify.callback(item);self.assertEqual(self.gateway.access.get(row['ip'])['status'],'pending')
        item['from']['id']=2;await notify.callback(item);self.assertEqual(self.gateway.access.get(row['ip'])['status'],'approved')
        self.gateway.access.update(row['ip'],{'status':'blocked'});await notify.callback(item);self.assertEqual(self.gateway.access.get(row['ip'])['status'],'blocked')


class Telegram53(unittest.IsolatedAsyncioTestCase):
    async def test_protocol_requires_nonce_response_not_tcp(self):
        async def server(r,w):
            try:
                await r.readexactly(4);size=int.from_bytes(await r.readexactly(4),'little');packet=await r.readexactly(size)
                payload=bytes(8)+bytes(8)+(40).to_bytes(4,'little')+b'\x63\x24\x16\x05'+packet[24:40]+bytes(20)
                w.write(len(payload).to_bytes(4,'little')+payload);await w.drain()
            finally:w.close()
        listener=await asyncio.start_server(server,'127.0.0.1',0);port=listener.sockets[0].getsockname()[1]
        try:await direct_exchange(lambda:asyncio.open_connection('127.0.0.1',port))
        finally:listener.close();await listener.wait_closed()
        packet,nonce=pq_request();self.assertFalse(valid_pq(packet,nonce))
    async def test_challenge_not_unreachable_and_media_priority(self):
        self.assertEqual(group_status([{'status':'limited'}]),'limited')
        with tempfile.TemporaryDirectory() as path:
            store=Store(path);runtime=type('Runtime',(),{'selected':''})();h=Health(store,runtime);store.config['settings']['telegram_enabled']=True
            r={'foreign_ok':True,'checked_at':time.time(),'full_at':time.time(),'russian_status':'available','latency_ms':50,'telegram':{'status':'protocol_ok','media':{'status':'unconfigured'}}}
            h.results['a']=r;h.results['b']=copy.deepcopy(r);h.results['b']['latency_ms']=200
            h.results['b']['telegram']['media']={'status':'media_ok','checked_at':time.time()}
            self.assertLess(h.node_rank('b'),h.node_rank('a'));store.db.close()
