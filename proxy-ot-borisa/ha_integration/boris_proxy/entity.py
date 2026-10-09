from homeassistant.helpers.update_coordinator import CoordinatorEntity
from . import DOMAIN, LABELS


class BorisEntity(CoordinatorEntity):
    _attr_has_entity_name=True
    # Live diagnostics remain visible without copying every ping into Recorder.
    _unrecorded_attributes=frozenset({'latency_ms','checked_at','reason','clients','checking'})
    def __init__(self,coordinator,profile,suffix):
        super().__init__(coordinator)
        self.profile=profile
        self._attr_unique_id=f'{DOMAIN}_{profile}_{suffix}'
        self._attr_name=(LABELS.get(profile,'')+' '+suffix).strip()
        self._attr_device_info={'identifiers':{(DOMAIN,DOMAIN)},'name':'Proxy от Бориса','manufacturer':'Proxy от Бориса','model':'Home Assistant OS','sw_version':coordinator.data['version']}
    @property
    def proxy(self):return self.coordinator.data['profiles'].get(self.profile,{})
    @property
    def extra_state_attributes(self):
        p=self.proxy
        return {k:p.get(k) for k in ('selected_name','reserve_name','last_switch','reason','latency_ms','checked_at','foreign','russian','services','telegram','media','port','running','available')}
