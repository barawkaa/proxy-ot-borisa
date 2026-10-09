"""Owner-only approval notifications. Shared HA bots are send-only by default."""
import asyncio
import time
import aiohttp
from .homeassistant import HomeAssistant


class Notifications:
    def __init__(self,store,gateway,runtime):
        self.ha=HomeAssistant();self.last_runtime_error='';self.store=store;self.gateway=gateway;self.runtime=runtime;self.next_send=0;self.error='';self.last_ok=0;self.offset=0;self.identity='';self.callback_ready=False

    async def call(self,method,body):
        n=self.store.config['notifications']
        proxy='http://127.0.0.1:12085' if self.runtime.selected else None
        auth=aiohttp.BasicAuth('__selected',self.runtime.password) if proxy else None
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),trust_env=False) as session:
            async with session.post('https://api.telegram.org/bot'+n['token']+'/'+method,json=body,proxy=proxy,proxy_auth=auth) as response:
                data=await response.json()
                if not response.ok or not data.get('ok'):raise ValueError('Бот не принял запрос. Проверьте токен, чат и права бота.')
                return data['result']

    async def callback(self,item):
        self.gateway.access.cleanup()
        n=self.store.config['notifications'];message=item.get('message',{})
        if str(item.get('from',{}).get('id'))!=str(n['owner_id']) or str(message.get('chat',{}).get('id'))!=str(n['chat_id']):return
        parts=item.get('data','').split(':')
        if len(parts)!=3 or parts[0] not in ('allow','deny'):return
        uid,revision=parts[1:];row=next((x for x in self.gateway.access.rows() if x['id']==uid),None)
        text='Запрос уже обработан или истёк'
        if row and row['status']=='pending' and row['revision']==revision and time.time()-row['first_seen']<self.store.config['access']['pending_hours']*3600:
            self.gateway.access.update(row['ip'],{'status':'approved' if parts[0]=='allow' else 'blocked'},revision)
            self.gateway.disconnect_ip(row['ip']);text='Доступ разрешён' if parts[0]=='allow' else 'Доступ запрещён'
        await self.call('answerCallbackQuery',{'callback_query_id':item['id'],'text':text})
        await self.call('editMessageReplyMarkup',{'chat_id':n['chat_id'],'message_id':message['message_id'],'reply_markup':{'inline_keyboard':[]}})

    async def tick(self):
        n=self.store.config['notifications']
        if not n['enabled']:return
        self.gateway.access.cleanup()
        if self.identity!=n['token']:
            self.identity=n['token'];self.offset=0;self.callback_ready=False
        try:
            if n.get('mode','direct')=='direct' and n['poll_callbacks']:
                # Explicit option for a dedicated bot only. Never delete an HA webhook.
                if not self.callback_ready:
                    info=await self.call('getWebhookInfo',{})
                    if info.get('url'):raise ValueError('У бота уже настроен webhook. Отключите приём кнопок здесь, чтобы сохранить интеграцию Home Assistant.')
                    self.callback_ready=True
                updates=await self.call('getUpdates',{'offset':self.offset,'timeout':0,'limit':20,'allowed_updates':['callback_query']})
                for item in updates:
                    self.offset=item['update_id']+1
                    if 'callback_query' in item:await self.callback(item['callback_query'])
            if time.time()<self.next_send:return
            rows=[r for r in self.gateway.access.rows() if r['status']=='pending' and not r['notified'] and (r['invited']==2 or not self.store.config['access']['notify_invited_only'])]
            if not rows:
                error=self.runtime.status().get('error') or self.runtime.status().get('telegram_error') or ''
                if error!=self.last_runtime_error:
                    if error or self.last_runtime_error:
                        await self.send({'chat_id':n['chat_id'],'text':'Proxy от Бориса: '+(error or 'Работа сервисов восстановлена.')})
                        self.next_send=time.time()+60;self.last_ok=time.time()
                    self.last_runtime_error=error
                return
            # Global budget: one message per minute, regardless of source-IP churn.
            batch=rows[:10];buttons=[]
            lines=['Запрос доступа к HTTP-прокси:']
            for r in batch:
                lines.append(r['name']+' · '+r['ip'])
                if n.get('mode','direct')=='direct' and n['poll_callbacks']:
                    buttons.append([{'text':'Разрешить '+r['ip'],'callback_data':'allow:'+r['id']+':'+r['revision']},{'text':'Запретить','callback_data':'deny:'+r['id']+':'+r['revision']}])
            if n['app_url']:buttons.append([{'text':'Открыть приложение','url':n['app_url']}])
            if n.get('mode','direct')=='ha' or not n['poll_callbacks']:lines.append('Одобрите адрес в приложении → Доступ по IP.')
            body={'chat_id':n['chat_id'],'text':'\n'.join(lines),'disable_web_page_preview':True}
            if buttons:body['reply_markup']={'inline_keyboard':buttons}
            await self.send(body)
            self.store.db.executemany('UPDATE ip_access SET notified=1 WHERE ip=? AND revision=?',[(r['ip'],r['revision']) for r in batch]);self.store.db.commit()
            self.last_ok=time.time();self.next_send=time.time()+60;self.error=''
        except asyncio.CancelledError:raise
        except Exception as exc:
            self.error=str(exc) if isinstance(exc,ValueError) else 'Telegram недоступен. Уведомление будет повторено; запрос сохранён.'
            self.next_send=time.time()+60;self.store.event('notifications',self.error)

    async def send(self,body):
        n=self.store.config['notifications']
        if n.get('mode','direct')=='ha':
            text=body['text']+('\n'+n['app_url'] if n['app_url'] else '')
            await self.ha.send(n,text)
        else:await self.call('sendMessage',body)

    async def test(self):
        await self.send({'chat_id':self.store.config['notifications']['chat_id'],'text':'Proxy от Бориса: уведомления подключены. Доступы управляются в приложении.'})
        self.last_ok=time.time();self.error=''
        return {'summary':'Тестовое уведомление отправлено выбранным получателям'}
