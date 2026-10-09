"""HA service discovery and explicit installation of the local companion."""
import asyncio
import os
import shutil
from pathlib import Path
import aiohttp
from .storage import atomic_json


class HomeAssistant:
    def __init__(self):
        self.base=os.environ.get('BORIS_HA_URL','http://supervisor/core/api')
        self.ws_url=os.environ.get('BORIS_HA_WS','ws://supervisor/core/websocket')
        self.token=os.environ.get('SUPERVISOR_TOKEN','')

    async def request(self,path,body=None):
        if not self.token:raise ValueError('Связь с Home Assistant доступна в установленном приложении HA OS')
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20),trust_env=False) as session:
                async with session.request('GET' if body is None else 'POST',self.base+path,json=body,headers={'Authorization':'Bearer '+self.token}) as response:
                    if response.status>=400:raise ValueError('Home Assistant не выполнил действие. Проверьте интеграцию Telegram и её прокси (ошибка 407 требует исправления авторизации).')
                    return await response.json()
        except (aiohttp.ClientError,TimeoutError):raise ValueError('Нет связи с Home Assistant. Запрос будет повторён.') from None

    async def registries(self):
        if not self.token:raise ValueError('Подключение доступно только в Home Assistant OS')
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15),trust_env=False) as session:
            async with session.ws_connect(self.ws_url,timeout=10) as ws:
                await ws.receive_json(timeout=10)
                await ws.send_json({'type':'auth','access_token':self.token})
                if (await ws.receive_json(timeout=10)).get('type')!='auth_ok':raise ValueError('Home Assistant отклонил внутреннее подключение')
                results=[]
                for uid,kind in enumerate(('config/entity_registry/list','config_entries/get'),1):
                    await ws.send_json({'id':uid,'type':kind})
                    reply=await ws.receive_json(timeout=10)
                    if not reply.get('success'):raise ValueError('Не удалось прочитать получателей Home Assistant')
                    results.append(reply['result'])
                return results

    async def recipients(self):
        try:(entities,entries),states=await asyncio.gather(self.registries(),self.request('/states'))
        except (aiohttp.ClientError,TimeoutError):raise ValueError('Не удалось получить получателей из Home Assistant') from None
        states={x['entity_id']:x for x in states}
        bots=[{'id':x['entry_id'],'name':x['title'],'state':x.get('state','unknown')} for x in entries if x['domain']=='telegram_bot']
        targets=[]
        for x in entities:
            if x.get('platform')!='telegram_bot' or not x['entity_id'].startswith('notify.') or x.get('disabled_by'):continue
            state=states.get(x['entity_id'],{})
            targets.append({'id':x['entity_id'],'name':x.get('name') or state.get('attributes',{}).get('friendly_name') or x.get('original_name') or x['entity_id'],
                'bot_id':x.get('config_entry_id'),'available':bool(state) and state.get('state')!='unavailable'})
        return {'targets':targets,'bots':bots}

    async def send(self,config,text):
        if not config['ha_targets'] and not config['ha_chat_ids']:raise ValueError('Выберите получателей Telegram или укажите ID чата')
        known=await self.recipients();ids={x['id'] for x in known['targets']}
        if any(x not in ids for x in config['ha_targets']):raise ValueError('Получатель Telegram удалён или выключен в Home Assistant. Выберите его заново.')
        if config['ha_chat_ids'] and config['ha_entry_id'] not in {x['id'] for x in known['bots']}:raise ValueError('Выбранный бот не найден в Home Assistant')
        if config['ha_targets']:
            await self.request('/services/notify/send_message',{'entity_id':config['ha_targets'],'message':text})
        if config['ha_chat_ids']:
            await self.request('/services/telegram_bot/send_message',{'config_entry_id':config['ha_entry_id'],'target':[int(x) for x in config['ha_chat_ids']],'message':text,'parse_mode':'plain_text'})


def install_companion(config,root=None,source=None):
    """Explicit button only. Touch only our managed directory; never restart HA."""
    root=Path(root or os.environ.get('BORIS_HA_CONFIG','/homeassistant'))
    source=Path(source or Path(__file__).resolve().parent.parent/'ha_integration'/'boris_proxy')
    if not root.is_dir():raise ValueError('Каталог конфигурации Home Assistant не подключён')
    parent=root/'custom_components';parent.mkdir(exist_ok=True)
    dest=parent/'boris_proxy';stage=parent/'.boris_proxy-stage';old=parent/'.boris_proxy-previous'
    if dest.is_symlink() or parent.is_symlink():raise ValueError('Отказ: каталог интеграции является ссылкой')
    if dest.exists() and not (dest/'.managed-by-proxy-boris').exists():raise ValueError('Каталог boris_proxy уже существует и не управляется приложением; файлы сохранены')
    if stage.exists():shutil.rmtree(stage)
    shutil.copytree(source,stage);(stage/'.managed-by-proxy-boris').write_text('managed\n')
    if old.exists():shutil.rmtree(old)
    if dest.exists():dest.rename(old)
    try:
        stage.rename(dest)
        atomic_json(root/'boris_proxy_link.json',{'url':'http://127.0.0.1:8099','token':config['ha']['token']})
    except Exception:
        if dest.exists():shutil.rmtree(dest)
        if old.exists():old.rename(dest)
        raise
    if old.exists():shutil.rmtree(old)
    return {'summary':'Интеграция установлена. Перезапустите Home Assistant в удобное время, затем добавьте интеграцию «Proxy от Бориса». Приложение само HA не перезапускает.'}
