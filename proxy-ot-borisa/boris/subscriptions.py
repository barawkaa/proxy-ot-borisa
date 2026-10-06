"""Loss-aware import: names are presentation, IDs derive from full connection settings."""
import base64
import copy
import hashlib
import json
import re
import urllib.parse as url
import uuid
import aiohttp
import yaml

SUPPORTED = {'vless','vmess','trojan','shadowsocks','hysteria2','tuic','socks','http'}
SERVICE_TYPES = {'selector','urltest','direct','block','dns'}
MAX_BYTES = 4*1024*1024


async def read_limited(stream, limit):
    chunks=[];size=0
    async for chunk in stream.iter_chunked(65536):
        size+=len(chunk)
        if size>limit:raise ValueError('Ответ превышает допустимый размер')
        chunks.append(chunk)
    return b''.join(chunks)


def unbase(text):
    return base64.urlsafe_b64decode(text.strip() + '=' * (-len(text.strip())%4)).decode('utf-8-sig')


def tls_options(q, default=False):
    if q.get('security','tls' if default else '') not in ('tls','reality'):
        return None
    tls = {'enabled':True, 'server_name':q.get('sni') or q.get('peer') or '', 'insecure':str(q.get('allowInsecure',q.get('insecure','0'))).lower() in ('1','true')}
    if q.get('alpn'):
        tls['alpn'] = q['alpn'].split(',')
    if q.get('fp'):
        fp = q['fp'].lower()
        if fp not in {'chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'}:
            raise ValueError('Неподдерживаемый TLS fingerprint: ' + fp[:40])
        tls['utls'] = {'enabled':True, 'fingerprint':fp}
    if q.get('security') == 'reality':
        if not q.get('pbk'):
            raise ValueError('У Reality отсутствует публичный ключ')
        tls['reality'] = {'enabled':True,'public_key':q['pbk'],'short_id':q.get('sid','')}
        tls.setdefault('utls',{'enabled':True,'fingerprint':'chrome'})
    return tls


def transport(q):
    kind = q.get('type') or q.get('net') or 'tcp'
    if kind in ('tcp','raw'):
        if q.get('headerType','none') != 'none':
            raise ValueError('TCP HTTP camouflage не поддерживается выбранным ядром')
        return None
    if kind not in ('ws','grpc','http','httpupgrade'):
        raise ValueError('Транспорт ' + kind + ' не поддерживается sing-box 1.12')
    result = {'type':kind}
    if kind == 'grpc':
        result['service_name'] = q.get('serviceName') or q.get('path','')
    else:
        result['path'] = q.get('path','/')
        if q.get('host'):
            if kind == 'ws': result['headers'] = {'Host':q['host']}
            elif kind == 'http': result['host'] = q['host'].split(',')
            else: result['host'] = q['host']
    return result


def parse_uri(line):
    p = url.urlsplit(line)
    typ = {'ss':'shadowsocks','hy2':'hysteria2','socks5':'socks','https':'http'}.get(p.scheme,p.scheme)
    q = dict(url.parse_qsl(p.query))
    name = url.unquote(p.fragment) or typ
    if typ == 'vmess':
        j = json.loads(unbase(line.split('://',1)[1].split('#',1)[0]))
        o = {'type':typ,'server':j['add'],'server_port':int(j['port']),'uuid':j['id'],'security':j.get('scy','auto'),'alter_id':int(j.get('aid',0))}
        q = {**j,'security':j.get('tls',''),'type':j.get('net','tcp')}
        name = j.get('ps') or name
    elif typ == 'shadowsocks':
        raw = line.split('://',1)[1].split('#',1)[0].split('?',1)[0]
        if '@' not in raw:
            raw = unbase(raw)
        info = url.urlsplit('ss://' + raw)
        cred = url.unquote(info.netloc.rsplit('@',1)[0])
        if ':' not in cred:
            cred = unbase(cred)
        method,password = cred.split(':',1)
        if q.get('plugin'):
            raise ValueError('Shadowsocks plugin требует отдельной поддержки')
        return name, {'type':typ,'server':info.hostname,'server_port':info.port,'method':method,'password':password}
    else:
        if typ not in SUPPORTED:
            raise ValueError('Протокол не поддерживается: ' + typ)
        o = {'type':typ,'server':p.hostname,'server_port':p.port or (1080 if typ=='socks' else 443)}
        user = url.unquote(p.username or '')
        if typ in ('vless','tuic'):
            o['uuid'] = user
            if typ == 'vless' and q.get('flow'): o['flow'] = q['flow']
        if typ in ('trojan','hysteria2'): o['password'] = user + (':' + url.unquote(p.password) if p.password else '')
        if typ in ('socks','http','tuic'):
            if typ != 'tuic': o['username'] = user
            o['password'] = url.unquote(p.password or '')
        if typ == 'hysteria2' and q.get('obfs'):
            o['obfs'] = {'type':q['obfs'],'password':q.get('obfs-password','')}
        if typ == 'tuic': o['congestion_control'] = q.get('congestion_control','cubic')
        if p.scheme == 'https': q['security'] = 'tls'
    tls = tls_options(q, typ in ('trojan','hysteria2','tuic'))
    if tls: o['tls'] = tls
    if typ in ('vless','vmess','trojan'):
        tr = transport(q)
        if tr: o['transport'] = tr
    return name,o


def parse_clash(j):
    typ = {'ss':'shadowsocks','socks5':'socks'}.get(j.get('type'),j.get('type'))
    o = {'type':typ,'server':j.get('server'),'server_port':int(j.get('port',443))}
    for key in ('uuid','password','username','flow','congestion-control'):
        if key in j: o[key.replace('-','_')] = j[key]
    if typ == 'shadowsocks':
        o['method'] = j.get('cipher')
        if j.get('plugin'): raise ValueError('Shadowsocks plugin не поддерживается')
    if typ == 'vmess': o.update(security=j.get('cipher','auto'),alter_id=int(j.get('alterId',0)))
    q = {'security':'tls' if j.get('tls') or typ in ('trojan','hysteria2','tuic') else '',
         'sni':j.get('servername') or j.get('sni',''), 'fp':j.get('client-fingerprint',''),
         'allowInsecure':str(j.get('skip-cert-verify',False))}
    if j.get('alpn'): q['alpn'] = ','.join(j['alpn'])
    if j.get('reality-opts'):
        r = j['reality-opts']; q.update(security='reality',pbk=r.get('public-key',''),sid=str(r.get('short-id','')))
    tls = tls_options(q)
    if tls: o['tls'] = tls
    network = j.get('network','tcp')
    opt = j.get(network+'-opts') or {}
    if network in ('ws','http','grpc','httpupgrade'):
        q = {'type':network, 'path':opt.get('path','/'), 'serviceName':opt.get('grpc-service-name',''), 'host':(opt.get('headers') or {}).get('Host','')}
        if isinstance(q['path'],list): q['path'] = q['path'][0]
        o['transport'] = transport(q)
    elif network not in ('tcp','raw'): raise ValueError('Неподдерживаемый транспорт ' + network)
    if typ == 'hysteria2' and j.get('obfs'): o['obfs'] = {'type':j['obfs'],'password':j.get('obfs-password','')}
    return j.get('name') or typ,o


def parse_xray(j):
    outs = [x for x in j.get('outbounds',[]) if x.get('protocol') not in ('freedom','blackhole','dns')]
    if len(outs) != 1: raise ValueError('Xray: цепочки нескольких outbounds требуют отдельной поддержки')
    x = outs[0]; typ = x.get('protocol'); st = x.get('settings',{})
    stream = x.get('streamSettings') or {}
    if x.get('proxySettings') or stream.get('sockopt',{}).get('dialerProxy'):
        raise ValueError('Xray: цепочка прокси не может быть импортирована как отдельный сервер')
    if typ in ('vless','vmess'):
        entries = st.get('vnext',[])
        if len(entries)!=1 or len(entries[0].get('users',[]))!=1: raise ValueError('Xray: неоднозначная конфигурация')
        endpoint=entries[0]; u=endpoint['users'][0]
        o={'type':typ,'server':endpoint['address'],'server_port':endpoint['port'],'uuid':u['id']}
        if u.get('flow'): o['flow']=u['flow']
        if typ=='vmess': o.update(security=u.get('security','auto'),alter_id=int(u.get('alterId',0)))
    elif typ in ('trojan','shadowsocks','socks','http'):
        entries=st.get('servers',[])
        if len(entries)!=1: raise ValueError('Xray: неоднозначная конфигурация')
        e=entries[0]; o={'type':typ,'server':e['address'],'server_port':e['port']}
        for k in ('password','method'): 
            if k in e:o[k]=e[k]
        if e.get('users'):o.update(username=e['users'][0].get('user',''),password=e['users'][0].get('pass',''))
    else: raise ValueError('Xray: протокол не поддерживается')
    sec=stream.get('security',''); t=stream.get(sec+'Settings') or {}
    q={'security':sec,'sni':t.get('serverName',''),'fp':t.get('fingerprint',''),'pbk':t.get('publicKey') or t.get('password',''),'sid':t.get('shortId',''),'allowInsecure':str(t.get('allowInsecure',False))}
    if t.get('alpn'):q['alpn']=','.join(t['alpn'])
    tls=tls_options(q)
    if tls:o['tls']=tls
    net=stream.get('network','tcp'); opt=stream.get(net+'Settings') or {}
    tr=transport({'type':net,'path':opt.get('path','/'),'host':(opt.get('headers') or {}).get('Host') or opt.get('host',''),'serviceName':opt.get('serviceName',''),'headerType':(opt.get('header') or {}).get('type','none')})
    if tr:o['transport']=tr
    return j.get('remarks') or j.get('name') or x.get('tag') or typ,o


def normalize(name, o, source_id):
    o = copy.deepcopy(o)
    typ = o.get('type')
    if typ not in SUPPORTED: raise ValueError('Протокол не поддерживается: ' + str(typ))
    if not o.get('server'): raise ValueError('Не указан адрес сервера')
    o['server_port'] = int(o['server_port'])
    if not 1<=o['server_port']<=65535: raise ValueError('Неверный порт')
    if typ in ('vless','vmess','tuic'): uuid.UUID(o.get('uuid',''))
    if o.get('detour'): raise ValueError('Связанный outbound нельзя терять при импорте')
    o.pop('tag',None)
    identity = hashlib.sha256((source_id+json.dumps(o,sort_keys=True)).encode()).hexdigest()[:24]
    return {'id':identity,'source_id':source_id,'name':str(name or typ)[:200],'outbound':o,'enabled':True,'auto':True,'priority':50}


def parse_payload(text, source_id='manual'):
    if len(text.encode())>MAX_BYTES: raise ValueError('Подписка больше 4 МБ')
    text=text.lstrip('\ufeff').strip()
    try:
        data=json.loads(text)
    except ValueError:
        data=None
    candidates=[]; kind='links'
    if isinstance(data,dict) and 'proxies' in data: candidates=data['proxies']; kind='clash'
    elif isinstance(data,dict) and 'outbounds' in data:
        if any('protocol' in x for x in data['outbounds']): candidates=[data]; kind='xray'
        else: candidates=data['outbounds']; kind='native'
    elif isinstance(data,dict) and 'servers' in data: candidates=data['servers'];kind='native'
    elif isinstance(data,list): candidates=data;kind='mixed'
    elif text.startswith('proxies:') or '\nproxies:' in text:
        data=yaml.safe_load(text); candidates=data.get('proxies',[]);kind='clash'
    else:
        if '://' not in text:
            try:text=unbase(text)
            except Exception: pass
        candidates=[line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if len(candidates)>500:raise ValueError('В одном источнике допускается не более 500 подключений')
    servers=[]; errors=[]; seen=set(); total=0
    for idx,item in enumerate(candidates):
        if isinstance(item,dict) and item.get('type') in SERVICE_TYPES: continue
        total+=1
        try:
            if isinstance(item,str): name,o=parse_uri(item)
            elif kind=='clash':name,o=parse_clash(item)
            elif kind=='xray' or 'outbounds' in item and any('protocol' in x for x in item['outbounds']):name,o=parse_xray(item)
            elif 'outbounds' in item:
                remote=[x for x in item['outbounds'] if x.get('type') not in SERVICE_TYPES]
                if len(remote)!=1:raise ValueError('Неподдерживаемая составная конфигурация sing-box')
                o=copy.deepcopy(remote[0]);name=item.get('remarks') or item.get('name') or o.get('tag','Сервер')
            else:
                o=copy.deepcopy(item);name=o.pop('name',None) or o.get('tag','Сервер')
                # v4 UI metadata is not a core field.
                for key in ('priority','enabled','use_in_auto','source_id','source_name','source_type','source_url','note','last_ping','last_ping_at','imported_at','created_at','updated_at','manual'):
                    o.pop(key,None)
            srv=normalize(name,o,source_id)
            if srv['id'] not in seen:servers.append(srv);seen.add(srv['id'])
        except Exception as e:
            # Never include raw connection data or credentials.
            safe=str(e) if isinstance(e,ValueError) and str(e).startswith(('Протокол','Транспорт','Неподдерж','Xray:','Shadowsocks','У Reality','Связанный','TCP ','Не указан','Неверный')) else 'Не удалось разобрать параметры подключения'
            errors.append({'row':idx+1,'reason':safe})
    return {'servers':servers,'errors':errors,'received':total,'duplicates':total-len(servers)-len(errors),'format':kind}


async def fetch_subscription(address, source_id, proxy=None):
    if url.urlsplit(address).scheme not in ('https','http'):
        raise ValueError('Нужна HTTP/HTTPS-ссылка подписки')
    results=[]
    uas=['Happ/1.0','v2rayN/7.0','ClashMetaForAndroid/2.11','sing-box/1.12.12']
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20),trust_env=False) as session:
        for ua in uas:
            for via in [None]+([proxy] if proxy else []):
                try:
                    async with session.get(address,headers={'User-Agent':ua},proxy=via) as r:
                        r.raise_for_status()
                        body=await read_limited(r.content,MAX_BYTES)
                        parsed=parse_payload(body.decode('utf-8-sig'),source_id)
                        parsed['user_agent']=ua
                        parsed['traffic']={k:int(v) for k,v in re.findall(r'(upload|download|total|expire)=(\d+)',r.headers.get('subscription-userinfo',''))}
                        results.append(parsed)
                        if parsed['servers']:break
                except (aiohttp.ClientError,TimeoutError,ValueError,UnicodeError):continue
    if not results or not any(x['servers'] for x in results):raise ValueError('Подписка недоступна или не содержит поддерживаемых подключений; прежние серверы сохранены')
    best=max(results,key=lambda x:(len(x['servers']),-len(x['errors'])))
    best['variants']=[{'user_agent':x['user_agent'],'servers':len(x['servers']),'errors':len(x['errors'])} for x in results]
    return best
