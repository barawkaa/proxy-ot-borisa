from homeassistant.components.select import SelectEntity
from homeassistant.exceptions import HomeAssistantError
from . import DOMAIN, LABELS
from .entity import BorisEntity


class Server(BorisEntity,SelectEntity):
    _attr_icon='mdi:server-network'
    def __init__(self,c,key):
        super().__init__(c,key,'сервер');self.entity_id=f'select.boris_proxy_{key}'
    def choices(self):
        return {'Автоматически':'',**{x['name']+' ['+x['id']+']':x['id'] for x in self.coordinator.data['servers']}}
    @property
    def options(self):return list(self.choices())
    @property
    def current_option(self):
        key=self.proxy.get('manual_server') if self.proxy['selection']=='manual' else ''
        return next((label for label,uid in self.choices().items() if uid==key),'Автоматически')
    async def async_select_option(self,option):
        choices=self.choices()
        if option not in choices:raise HomeAssistantError('Сервер больше недоступен')
        await self.coordinator.command({'action':'select','profile':self.profile,'id':choices[option]})


async def async_setup_entry(hass,entry,async_add_entities):
    c=hass.data[DOMAIN][entry.entry_id];async_add_entities([Server(c,key) for key in LABELS])
