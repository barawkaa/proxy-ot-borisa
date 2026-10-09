from homeassistant.components.switch import SwitchEntity
from . import DOMAIN, LABELS
from .entity import BorisEntity


class Enabled(BorisEntity,SwitchEntity):
    _attr_icon='mdi:power'
    def __init__(self,c,key):
        super().__init__(c,key,'включён');self.entity_id=f'switch.boris_proxy_{key}'
    @property
    def is_on(self):return self.proxy['enabled']
    async def async_turn_on(self,**kwargs):await self.coordinator.command({'action':'enabled','profile':self.profile,'enabled':True})
    async def async_turn_off(self,**kwargs):await self.coordinator.command({'action':'enabled','profile':self.profile,'enabled':False})


async def async_setup_entry(hass,entry,async_add_entities):
    c=hass.data[DOMAIN][entry.entry_id];async_add_entities([Enabled(c,key) for key in LABELS])
