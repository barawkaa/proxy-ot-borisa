"""Read-only v4 migration; original files are kept for rollback."""
import json
import secrets
import time
from .model import defaults,client_new
from .subscriptions import parse_payload
from .storage import atomic_json


def migrate(store):
    if store.path.exists():return []
    def read(name,default):
        p=store.root/name
        try:return json.loads(p.read_text()) if p.exists() else default
        except (ValueError,OSError):return default
    c=defaults();warnings=[]
    options=read('options.json',{});options.update(read('runtime_options.json',{}));options.update(read('runtime_ports.json',{}))
    s=c['settings'];old=read('settings.json',{});tg=read('telegram_proxy.json',{})
    for src,dst in [('http_proxy_port','http_port'),('socks_proxy_port','socks_port'),('telegram_proxy_port','telegram_port')]:
        if src in options:s[dst]=options[src]
    for k in ('http_enabled','socks_enabled'):
        if k in old:s[k]=old[k]
    s['telegram_enabled']=bool(tg.get('enabled',options.get('telegram_proxy_enabled',False)))
    s['public_host']=tg.get('public_host','');s['front_domain']=tg.get('front_domain') or options.get('telegram_front_domain','www.google.com')
    sources=read('server_sources.json',{})
    for x in sources.get('sources',[]) if isinstance(sources,dict) else sources:
        if x.get('url'):c['sources'].append({'id':x.get('id') or secrets.token_hex(8),'name':x.get('name','Подписка'),'url':x['url'],'enabled':x.get('enabled',True),'auto':x.get('use_in_auto',True),'interval':3600,'updated_at':0})
    raw=read('servers.json',[])
    if isinstance(raw,dict):raw=raw.get('servers',[])
    known={x['id'] for x in c['sources']}
    for item in raw:
        source=item.get('source_id','manual')
        if source not in known:source='manual'
        parsed=parse_payload(json.dumps([item]),source)
        if parsed['servers']:
            node=parsed['servers'][0];node.update(enabled=item.get('enabled',True),auto=item.get('use_in_auto',True),priority=item.get('priority',50))
            if node['id'] not in {x['id'] for x in c['servers']}:c['servers'].append(node)
        else:warnings.append('Старый сервер не перенесён: '+parsed['errors'][0]['reason'])
    for u in read('proxy_users.json',[]):
        user=client_new(u.get('name','Клиент'),s['front_domain'])
        for k in ('id','name','username','password','telegram_secret','enabled','expires_at','blocked_until','notes','created_at'):
            if u.get(k) is not None:user[k]=u[k]
        for k in ('http','socks','telegram'):user[k]=u.get(k+'_enabled',True)
        policy=u.get('traffic_policy') or {};user['monthly_limit_gb']=policy.get('monthly_limit_gb',0) if policy.get('enabled') else 0
        c['clients'].append(user)
    if not c['clients']:
        user=client_new('Основной клиент',s['front_domain'])
        if options.get('proxy_username'):user['username']=options['proxy_username']
        if options.get('proxy_password') and options['proxy_password']!='ChangeThisProxyPassword':user['password']=options['proxy_password']
        if tg.get('secret'):user['telegram_secret']=tg['secret']
        user['telegram']=s['telegram_enabled'];c['clients'].append(user)
    r=read('routing.json',{});nr=c['routing']
    nr['mode']={'all_proxy':'all_vpn','blocked_plus_manual':'selected','manual_only':'selected','all_direct':'direct'}.get(r.get('mode'),'all_vpn')
    for src,dst in [('manual_include_domains','vpn_domains'),('manual_exclude_domains','direct_domains'),('manual_include_ips','vpn_ips'),('manual_exclude_ips','direct_ips')]:nr[dst]=r.get(src,[])
    nr['presets']=[k for k,v in (r.get('presets') or {}).items() if v]
    for x in r.get('sources',[]):nr['sources'].append({'id':x.get('tag') or secrets.token_hex(8),'name':x.get('name','Список'),'url':x.get('url',''),'format':'binary' if x.get('format')=='remote_srs' else 'text','kind':x.get('kind','domain_suffix'),'enabled':x.get('enabled',False) and r.get('mode')!='manual_only','updated_at':0})
    sec=read('security.json',{})
    c['security'].update(deny_cidrs=sec.get('custom_denied_cidrs',[]),allow_cidrs=sec.get('custom_allowed_cidrs',[]),country_enabled=sec.get('country_filter_enabled',False),autoban_enabled=sec.get('autoban_enabled',True),max_per_ip=sec.get('autoban_max_connections_per_ip',120),new_per_minute=sec.get('autoban_max_new_connections_per_minute',240),ban_seconds=sec.get('autoban_duration_seconds',3600),trusted_enabled=sec.get('trusted_auth_bypass_enabled',False))
    for net in sec.get('trusted_auth_bypass_cidrs',[]):c['security']['trusted'].append({'cidr':net,'client_id':c['clients'][0]['id'],'protocols':['http','socks']})
    for x in read('blocked_ips.json',[]):
        if x.get('cidr') and (not x.get('expires_at') or x['expires_at']>time.time()):c['security']['deny_cidrs'].append(x['cidr'])
    for name in ('security.json','client_limits.json','manual_traffic.json','trusted_clients.json','traffic.json'):
        value=read(name,None)
        if value is not None:c['legacy'][name]=value
    c['migration']={'from':'4.x' if raw or old else 'new','warnings':warnings,'at':time.time()}
    if c['migration']['from']=='4.x':atomic_json(store.root/'migration-v5-report.json',c['migration'])
    store.save(c);return warnings
