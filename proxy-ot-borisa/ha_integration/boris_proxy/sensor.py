from homeassistant.components.sensor import SensorEntity
from . import DOMAIN, LABELS
from .entity import BorisEntity


class Status(BorisEntity,SensorEntity):
    _attr_icon='mdi:shield-link-variant'
    def __init__(self,coordinator,profile):
        super().__init__(coordinator,profile,'статус')
        self.entity_id=f'sensor.boris_proxy_{profile}'
    @property
    def native_value(self):
        p=self.proxy
        return 'Выключен' if not p['enabled'] else p['selected_name'] if p['available'] else 'Нет подтверждённого доступа'


class Summary(BorisEntity,SensorEntity):
    _attr_icon='mdi:shield-check'
    def __init__(self,coordinator):
        super().__init__(coordinator,'all','состояние');self.entity_id='sensor.boris_proxy_status'
    @property
    def native_value(self):
        data=self.coordinator.data;enabled=[x for x in data['profiles'].values() if x['enabled']]
        if not data['core']:return 'Требуется внимание'
        if not enabled:return 'Прокси выключены'
        return 'Работает' if all(x['available'] for x in enabled) else 'Проверяем доступ'
    @property
    def extra_state_attributes(self):
        d=self.coordinator.data
        return {'clients':d['clients'],'started':d['started'],'checking':d['checking']}


async def async_setup_entry(hass,entry,async_add_entities):
    c=hass.data[DOMAIN][entry.entry_id]
    async_add_entities([Summary(c)]+[Status(c,key) for key in LABELS])
