"""No token entry: pairing is created explicitly by the add-on installer."""
import json
from pathlib import Path
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import aiohttp
from . import DOMAIN


class Flow(config_entries.ConfigFlow,domain=DOMAIN):
    VERSION=1
    async def async_step_user(self,user_input=None):
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        errors={}
        if user_input is not None:
            try:
                def read():return json.loads(Path(self.hass.config.path('boris_proxy_link.json')).read_text())
                data=await self.hass.async_add_executor_job(read)
                # Pairing file is local, managed by the installed add-on.
                if data.get('url')!='http://127.0.0.1:8099' or not data.get('token'):raise ValueError()
                session=async_get_clientsession(self.hass)
                async with session.get(data['url']+'/api/ha/state',headers={'Authorization':'Bearer '+data['token']},timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status!=200:raise ValueError()
                return self.async_create_entry(title='Proxy от Бориса',data=data)
            except (OSError,ValueError,KeyError,aiohttp.ClientError,TimeoutError):errors['base']='cannot_connect'
        return self.async_show_form(step_id='user',data_schema=vol.Schema({}),errors=errors)
