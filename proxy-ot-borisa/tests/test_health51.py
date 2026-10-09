import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
from boris.health import Health,rank,group_status
from boris.model import defaults
from boris.storage import Store

class Selection51(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name)
        c=defaults();c['servers']=[{'id':x,'name':x.upper(),'source_id':'manual','outbound':{'type':'trojan'},'enabled':True,'auto':True} for x in ('a','b','c')];self.store.save(c)
        self.runtime=type('Runtime',(),{'selected':'a','password':'test'})()
        async def select(tag):self.runtime.selected=tag
        self.runtime.select=AsyncMock(side_effect=select)
        self.h=Health(self.store,self.runtime);self.h.url_check=AsyncMock(return_value={'status':'ok','ms':200})
        self.h.telegram.chain=AsyncMock(return_value={'status':'protocol_ok'})
        self.h.telegram.media=AsyncMock(return_value={'status':'unconfigured'})
        self.h.results={x:self.result(860 if x=='a' else 250 if x=='b' else 300) for x in ('a','b','c')}
        async def probe(node,full=True,urgent=False):
            self.h.results[node['id']]['checked_at']=time.time()
            return self.h.results[node['id']]
        self.h.probe=AsyncMock(side_effect=probe)
    def result(self,ms,ru='available'):
        return dict(checked_at=time.time(),full_at=time.time(),foreign_ok=True,russian_ok=ru=='available',russian_status=ru,latency_ms=ms,median_ms=ms,failure_rate=0,telegram={'status':'protocol_ok'})
    async def asyncTearDown(self):self.store.db.close();self.temp.cleanup()
    async def test_big_improvement_does_not_wait_five_minutes(self):
        self.h.last_switch=time.time();await self.h.profiles['http'].choose()
        self.assertEqual(self.runtime.selected,'b');self.assertEqual(self.h.probe.await_count,3)
        event=self.store.list('events')[0]['message'];self.assertIn('860',event);self.assertIn('250',event)
    async def test_recent_slowdown_not_hidden_by_old_median(self):
        self.h.results['a']['median_ms']=100
        await self.h.profiles['http'].choose();self.assertEqual(self.runtime.selected,'b')
    async def test_candidate_loses_universal_access_during_confirmation(self):
        original=self.h.probe.side_effect
        async def probe(node,*args,**kwargs):
            if node['id']=='b':self.h.results['b'].update(russian_ok=False,russian_status='unreachable')
            return await original(node,*args,**kwargs)
        self.h.probe.side_effect=probe;await self.h.profiles['http'].choose();self.runtime.select.assert_not_awaited()
    async def test_small_difference_keeps_current(self):
        self.h.results['a']=self.result(270);await self.h.profiles['http'].choose();self.runtime.select.assert_not_awaited()
    async def test_spike_candidate_rejected(self):
        original=self.h.probe.side_effect;count=0
        async def probe(node,*args,**kwargs):
            nonlocal count
            if node['id']=='b':
                count+=1
                if count==2:self.h.results['b']['latency_ms']=850
            return await original(node,*args,**kwargs)
        self.h.probe.side_effect=probe;await self.h.profiles['http'].choose();self.runtime.select.assert_not_awaited()
    async def test_failed_confirmation_keeps_current(self):
        async def probe(node,*args,**kwargs):
            if node['id']=='b':self.h.results['b']['foreign_ok']=False
            return self.h.results[node['id']]
        self.h.probe.side_effect=probe;await self.h.profiles['http'].choose();self.runtime.select.assert_not_awaited()
    async def test_reserve_does_not_displace_universal(self):
        self.h.results['b']=self.result(20,'unreachable');self.h.results['c']=self.result(30,'restricted')
        await self.h.profiles['http'].choose();self.runtime.select.assert_not_awaited()
    async def test_telegram_requirement_respected(self):
        self.h.profiles['http'].profile='telegram';self.runtime.selections={'telegram':'a'};self.runtime.select=AsyncMock(side_effect=lambda tag,profile: self.runtime.selections.update({profile:tag}));self.h.results['b']['telegram']={'status':'unreachable'}
        await self.h.profiles['http'].choose();self.assertEqual(self.runtime.selections['telegram'],'c')
    async def test_failure_bypasses_switch_limiter(self):
        self.h.switches.extend([time.time()]*3);self.h.results['a']['foreign_ok']=False
        await self.h.profiles['http'].choose(True);self.assertEqual(self.runtime.selected,'b')
    async def test_final_route_failure_tries_next(self):
        self.h.results['a']['foreign_ok']=False
        self.h.url_check=AsyncMock(side_effect=[{'status':'unreachable'},{'status':'unreachable'},{'status':'ok'}])
        await self.h.profiles['http'].choose(True);self.assertEqual(self.runtime.selected,'c');self.assertFalse(self.h.results['b']['foreign_ok'])
    async def test_healthy_current_still_optimizes(self):
        await self.h.profiles['http'].current_check();self.assertEqual(self.runtime.selected,'b')
    async def test_manual_not_optimized(self):
        self.store.config['profiles']['http'].update(selection='manual',manual_server='a')
        await self.h.profiles['http'].current_check();self.runtime.select.assert_not_awaited()
    async def test_disabled_source_excluded(self):
        self.store.config['sources']=[{'id':'off','enabled':True,'auto':False}]
        self.store.config['servers'][1]['source_id']='off';await self.h.profiles['http'].choose();self.assertEqual(self.runtime.selected,'c')
    async def test_services_no_hidden_latency_penalty(self):
        self.h.results['b']['services']=[{'status':'restricted'}];await self.h.profiles['http'].choose();self.assertEqual(self.runtime.selected,'b')
    async def test_no_confirmed_telegram_fail_closed(self):
        self.h.profiles['http'].profile='telegram';self.runtime.selections={'telegram':'a'};self.runtime.select=AsyncMock(side_effect=lambda tag,profile: self.runtime.selections.update({profile:tag}))
        for r in self.h.results.values():r['telegram']={'status':'unreachable'}
        await self.h.profiles['http'].choose(True);self.assertEqual(self.runtime.selections['telegram'],'')

class Measurements51(unittest.IsolatedAsyncioTestCase):
    async def test_rolling_median_and_failure_window(self):
        with tempfile.TemporaryDirectory() as root:
            store=Store(root);h=Health(store,type('Runtime',(),{'password':'p'})())
            h.url_check=AsyncMock(side_effect=[{'status':'ok','ms':x} for x in (100,100,120,120,900,900)])
            for _ in range(3):r=await h.probe({'id':'a'},False)
            self.assertEqual(r['latency_ms'],900);self.assertEqual(r['median_ms'],120);self.assertEqual(r['samples'],3);store.db.close()
    async def test_shared_parallelism_limit(self):
        with tempfile.TemporaryDirectory() as root:
            store=Store(root);store.config['settings']['parallel_checks']=2
            h=Health(store,None);running=0;peak=0
            async def probe(node,full):
                nonlocal running,peak
                running+=1;peak=max(peak,running);await asyncio.sleep(.02);running-=1
            h._probe=probe
            await asyncio.gather(*(h.probe({'id':str(i)},False,urgent=i==5) for i in range(8)))
            self.assertLessEqual(peak,2);self.assertEqual(h.inflight,0);store.db.close()
    def test_partial_and_restricted_are_distinct(self):
        self.assertEqual(group_status([{'status':'ok'},{'status':'restricted'}]),'partial')
        self.assertEqual(group_status([{'status':'restricted'}]),'restricted')
        self.assertEqual(group_status([{'status':'unreachable'}]),'unreachable')
    def test_old_full_check_no_universal_priority(self):
        r=dict(checked_at=time.time(),full_at=time.time()-601,foreign_ok=True,russian_status='available',latency_ms=100)
        self.assertEqual(rank(r)[0],1)
    def test_upgrade_defaults_and_personal_credentials(self):
        with tempfile.TemporaryDirectory() as root:
            c=defaults();c['settings'].pop('switch_margin_percent');c['settings']['scan_interval']=180;c['settings']['switch_hold_seconds']=300
            c['clients']=[{'id':'u','password':'private','telegram_secret':'private-secret'}]
            path=Path(root)/'config-v5.json';path.write_text(json.dumps(c));original=path.read_bytes()
            store=Store(root)
            self.assertEqual(store.config['settings']['scan_interval'],60);self.assertEqual(store.config['settings']['switch_margin_percent'],25)
            self.assertEqual(store.config['settings']['switch_hold_seconds'],300);self.assertEqual(store.config['clients'],c['clients']);self.assertEqual(path.read_bytes(),original);store.db.close()
