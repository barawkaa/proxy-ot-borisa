"""Runs on actual Home Assistant 2026.9.4 (Python 3.14), no pytest shim."""
import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from aiohttp import web
from homeassistant.core import HomeAssistant
from homeassistant import loader, config_entries
from homeassistant.bootstrap import async_load_base_functionality
from homeassistant.setup import async_setup_component


async def main():
    with tempfile.TemporaryDirectory() as root:
        target=Path(root,'custom_components','boris_proxy');target.parent.mkdir()
        shutil.copytree(Path(__file__).resolve().parents[1]/'ha_integration'/'boris_proxy',target)
        Path(root,'boris_proxy_link.json').write_text(json.dumps({'url':'http://127.0.0.1:8099','token':'test-private-token'}))
        profiles={k:dict(enabled=True,running=True,available=True,selected_name='Netherlands',selected_id='nl',reserve_name='Sweden',latency_ms=80,checked_at=1,last_switch=1,reason='Stable',port=p,selection='auto',manual_server='') for k,p in [('http',2081),('socks',2080),('telegram',2083),('http_ip',2084)]}
        state={'version':'5.4','core':True,'started':1,'checking':False,'clients':1,'profiles':profiles,'servers':[{'id':'nl','name':'Netherlands'},{'id':'se','name':'Sweden'}]}
        calls=[]
        async def status(request):
            assert request.headers['Authorization']=='Bearer test-private-token'
            return web.json_response(state)
        async def command(request):
            b=await request.json();calls.append(b)
            if b['action']=='enabled':profiles[b['profile']]['enabled']=b['enabled']
            if b['action']=='select':profiles[b['profile']].update(selection='manual' if b['id'] else 'auto',manual_server=b['id'])
            return web.json_response({'ok':True})
        app=web.Application();app.router.add_get('/api/ha/state',status);app.router.add_post('/api/ha/command',command)
        runner=web.AppRunner(app);await runner.setup();await web.TCPSite(runner,'127.0.0.1',8099).start()
        hass=HomeAssistant(root)
        try:
            loader.async_setup(hass)
            hass.config_entries=config_entries.ConfigEntries(hass,{})
            assert await async_load_base_functionality(hass)
            assert await async_setup_component(hass,'network',{})
            assert await async_setup_component(hass,'homeassistant',{})
            result=await hass.config_entries.flow.async_init('boris_proxy',context={'source':'user'})
            assert result['type']=='form',result
            result=await hass.config_entries.flow.async_configure(result['flow_id'],{})
            assert result['type']=='create_entry',result
            await hass.async_block_till_done()
            assert hass.states.get('sensor.boris_proxy_status').state=='Работает'
            assert hass.states.get('sensor.boris_proxy_http_ip').attributes['port']==2084
            assert hass.states.get('sensor.boris_proxy_http').attributes['reserve_name']=='Sweden'
            await hass.services.async_call('switch','turn_off',{'entity_id':'switch.boris_proxy_socks'},blocking=True)
            assert not profiles['socks']['enabled'];assert profiles['http']['enabled']
            await hass.services.async_call('select','select_option',{'entity_id':'select.boris_proxy_http','option':'Sweden [se]'},blocking=True)
            assert profiles['http']['manual_server']=='se'
            await hass.services.async_call('button','press',{'entity_id':'button.boris_proxy_check'},blocking=True)
            assert calls[-1]['action']=='check'
            assert 'test-private-token' not in str(hass.states.async_all())
            entry=result['result'];assert await hass.config_entries.async_unload(entry.entry_id)
            print('HA 2026.9.4: setup, entities, independent switches, select, check button, unload PASS')
        finally:
            await hass.async_stop();await runner.cleanup()


asyncio.run(main())
