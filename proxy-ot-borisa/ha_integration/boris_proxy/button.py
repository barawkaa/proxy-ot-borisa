from homeassistant.components.button import ButtonEntity
from . import DOMAIN
from .entity import BorisEntity


class Check(BorisEntity,ButtonEntity):
    _attr_icon='mdi:connection'
    def __init__(self,c):
        super().__init__(c,'all','проверить и выбрать');self.entity_id='button.boris_proxy_check'
    async def async_press(self):await self.coordinator.command({'action':'check'})


async def async_setup_entry(hass,entry,async_add_entities):
    async_add_entities([Check(hass.data[DOMAIN][entry.entry_id])])
