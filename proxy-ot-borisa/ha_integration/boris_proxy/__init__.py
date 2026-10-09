"""Local companion for Proxy от Бориса; no credentials in entity states."""
from datetime import timedelta
import logging
import aiohttp
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.exceptions import HomeAssistantError

DOMAIN='boris_proxy'
PLATFORMS=['sensor','switch','select','button']
LABELS={'http':'HTTP','socks':'SOCKS5','telegram':'Telegram','http_ip':'HTTP по IP'}


class Coordinator(DataUpdateCoordinator):
    def __init__(self,hass,entry):
        super().__init__(hass,logging.getLogger(__name__),name=DOMAIN,update_interval=timedelta(seconds=30),always_update=False)
        self.entry=entry;self.session=async_get_clientsession(hass)

    async def call(self,path,body=None):
        try:
            async with self.session.request('GET' if body is None else 'POST',self.entry.data['url']+'/api/ha/'+path,
                headers={'Authorization':'Bearer '+self.entry.data['token']},json=body,timeout=aiohttp.ClientTimeout(total=15)) as response:
                result=await response.json()
                if response.status>=400:raise HomeAssistantError(result.get('error','Приложение недоступно'))
                return result
        except (aiohttp.ClientError,TimeoutError) as exc:raise HomeAssistantError('Нет связи с Proxy от Бориса') from exc

    async def _async_update_data(self):
        try:return await self.call('state')
        except HomeAssistantError as exc:raise UpdateFailed(str(exc)) from exc

    async def command(self,body):
        result=await self.call('command',body)
        await self.async_request_refresh()
        return result


async def async_setup_entry(hass,entry):
    coordinator=Coordinator(hass,entry)
    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN,{})[entry.entry_id]=coordinator
    await hass.config_entries.async_forward_entry_setups(entry,PLATFORMS)
    return True


async def async_unload_entry(hass,entry):
    if await hass.config_entries.async_unload_platforms(entry,PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)
        return True
    return False
