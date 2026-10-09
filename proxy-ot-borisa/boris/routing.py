"""One rule generator is shared by runtime and route explanation."""
import ipaddress
from .model import PRESETS, client_enabled, PROFILES, CORE_PORTS, selector_tag


def route_rules(config, user=None, profile=None):
    r=config['routing']; mode=(user or {}).get('route_mode','default')
    if mode=='default' and profile:mode=config['profiles'][profile]['route_mode']
    if mode=='default':mode=r['mode']
    prefix={'auth_user':[user['username']]} if user else {}
    if profile:prefix['inbound']=['clients_'+profile]
    vpn=selector_tag(profile) if profile else 'vpn'
    rules=[]
    def add(field,values,out):
        if values:rules.append({**prefix,field:values,'action':'route','outbound':vpn if out=='vpn' else out})
    if mode=='direct': return [{**prefix,'action':'route','outbound':'direct'}]
    if mode=='all_vpn':return [{**prefix,'action':'route','outbound':vpn}]
    add('domain_suffix',r['direct_domains'],'direct');add('ip_cidr',r['direct_ips'],'direct')
    includes=list(r['vpn_domains'])
    for p in r['presets']:includes.extend(PRESETS.get(p,[]))
    add('domain_suffix',sorted(set(includes)),'vpn');add('ip_cidr',r['vpn_ips'],'vpn')
    add('rule_set',[x['id'] for x in r['sources'] if x.get('enabled') and x.get('cache_path')],'vpn')
    rules.append({**prefix,'action':'route','outbound':vpn if mode=='except' else 'direct'})
    return rules


def explain(config, host, user=None, profile=None):
    host=host.strip().lower().strip('.')
    try:ip=ipaddress.ip_address(host)
    except ValueError:ip=None
    if profile=='telegram':return {'route':'vpn_telegram','reason':'Telegram всегда использует выбранный сервер MTProxy'}
    for r in route_rules(config,user,profile):
        if 'domain_suffix' in r:
            hits=[x for x in r['domain_suffix'] if host==x or host.endswith('.'+x)]
            if hits:return {'route':r['outbound'],'reason':'Домен из списка: '+hits[0]}
        elif 'ip_cidr' in r:
            if ip and any(ip in ipaddress.ip_network(x,strict=False) for x in r['ip_cidr']):return {'route':r['outbound'],'reason':'IP из списка'}
        elif 'rule_set' in r:
            # Binary rule sets and DNS-resolved addresses cannot be guessed in Python.
            return {'route':'runtime','reason':'Решение зависит от загруженного списка и DNS. Фактический маршрут виден в активных подключениях.'}
        else:return {'route':r['outbound'],'reason':'Правило по умолчанию для клиента'}


def core_config(config, internal_password, api_secret, selected='', log_path=None):
    sources={s['id']:s for s in config['sources']}
    servers=[s for s in config['servers'] if s.get('enabled',True) and not s.get('error') and sources.get(s['source_id'],{}).get('enabled',True)]
    clients=[c for c in config['clients'] if client_enabled(c)]
    profiles=[]
    if config['access']['enabled']:
        profiles=[{'username':'__access_'+mode,'password':config['access']['internal_password'],'route_mode':mode} for mode in ('default','all_vpn','selected','except','direct')]
        clients+=profiles
    outbounds=[{**s['outbound'],'tag':s['id']} for s in servers]
    tags=[s['id'] for s in servers]
    # No working VPN is fail-closed. Never silently fall back to home IP.
    selected = selected if isinstance(selected,dict) else {key:selected for key in PROFILES}
    outbounds.extend([{'type':'direct','tag':'direct'},{'type':'block','tag':'unavailable'}])
    for profile in PROFILES:
        outbounds.append({'type':'selector','tag':selector_tag(profile),'outbounds':['unavailable']+tags,
            'default':selected.get(profile) if selected.get(profile) in tags else 'unavailable','interrupt_exist_connections':False})
    inbounds=[]
    for profile,port in CORE_PORTS.items():
        users=profiles if profile=='http_ip' else [u for u in clients if u.get(profile)]
        inbounds.append({'type':'mixed','tag':'clients_'+profile,'listen':'127.0.0.1','listen_port':port,
            'users':[{'username':u['username'],'password':u['password']} for u in users] or [{'username':'__disabled','password':internal_password}]})
    inbounds.extend([{'type':'mixed','tag':'probes','listen':'127.0.0.1','listen_port':12085,
        'users':[{'username':tag,'password':internal_password} for tag in tags]+[{'username':'__selected'+('' if key=='http' else '_'+key),'password':internal_password} for key in PROFILES]},
        {'type':'socks','tag':'telegram','listen':'127.0.0.1','listen_port':12084}])
    rules=[{'inbound':['telegram'],'action':'route','outbound':selector_tag('telegram')}]
    for profile in PROFILES:
        rules.append({'inbound':['probes'],'auth_user':['__selected'+('' if profile=='http' else '_'+profile)],'action':'route','outbound':selector_tag(profile)})
    for tag in tags:rules.append({'inbound':['probes'],'auth_user':[tag],'action':'route','outbound':tag})
    if profiles:
        rules.extend([{'inbound':['clients_http_ip'],'action':'resolve'}, {'inbound':['clients_http_ip'],'ip_is_private':True,'action':'reject'}])
    for profile in CORE_PORTS:
        for user in (profiles if profile=='http_ip' else [u for u in clients if u.get(profile)]):
            rules.extend(route_rules(config,user,profile))
    rules.append({'action':'reject'})
    sets=[]
    for x in config['routing']['sources']:
        if x.get('enabled') and x.get('cache_path'):
            sets.append({'type':'local','tag':x['id'],'format':x.get('cache_format','source'),'path':x['cache_path']})
    return {'log':{'level':'warn','timestamp':True,**({'output':str(log_path)} if log_path else {})},
            'dns':{'servers':[{'type':'local','tag':'local'}]},
            'inbounds':inbounds,'outbounds':outbounds,
            'route':{'rules':rules,'rule_set':sets,'default_domain_resolver':'local'},
            'experimental':{'clash_api':{'external_controller':'127.0.0.1:19090','secret':api_secret}}}
