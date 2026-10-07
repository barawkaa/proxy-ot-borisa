"""Configuration model. Secrets never belong in event or session records."""
import copy
import ipaddress
import re
import secrets
import time

MODES = ('all_vpn', 'selected', 'except', 'direct')
PRESETS = {
    'youtube': ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'youtubei.googleapis.com'],
    'openai': ['chatgpt.com', 'openai.com', 'oaistatic.com', 'oaiusercontent.com', 'auth0.com', 'workos.com', 'challenges.cloudflare.com'],
    'discord': ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media'],
    'instagram_meta': ['instagram.com', 'cdninstagram.com', 'facebook.com', 'fbcdn.net', 'threads.net'],
    'telegram': ['telegram.org', 't.me', 'tdesktop.com'],
    'tiktok': ['tiktok.com', 'tiktokcdn.com', 'byteoversea.com'],
    'spotify': ['spotify.com', 'scdn.co', 'spotifycdn.com'],
}

def defaults():
    return {
        'schema': 5, 'sources': [], 'servers': [], 'clients': [],
        'settings': {
            'selection': 'auto', 'manual_server': '', 'http_enabled': True, 'socks_enabled': True,
            'http_port': 2081, 'socks_port': 2080, 'telegram_port': 2083,
            'telegram_enabled': False, 'public_host': '', 'front_domain': 'www.google.com',
            'check_interval': 60, 'scan_interval': 60, 'availability_interval': 300,
            'subscription_interval': 3600, 'parallel_checks': 3, 'check_timeout': 8,
            'switch_margin_ms': 80, 'switch_margin_percent': 25,
            'switch_hold_seconds': 300,  # Retained solely for reading these data with release 5.0.
            'manual_failover': True, 'history_days': 7, 'history_records': 10000,
            'event_records': 5000, 'history_mb': 50, 'debug_until': 0,
            'max_connections': 512, 'idle_seconds': 600,
            'foreign_urls': ['https://www.gstatic.com/generate_204', 'https://www.cloudflare.com/cdn-cgi/trace'],
            'russian_urls': ['https://ya.ru/', 'https://www.ozon.ru/'],
            'service_urls': ['https://chatgpt.com/'],
            'telegram_targets': ['149.154.167.51:443', '149.154.175.100:443'],
        },
        'routing': {'mode': 'all_vpn', 'vpn_domains': [], 'direct_domains': [], 'vpn_ips': [],
                    'direct_ips': [], 'presets': [], 'sources': [], 'update_interval': 86400},
        'security': {'trusted_enabled': False, 'trusted': [], 'deny_cidrs': [], 'allow_cidrs': [],
                     'country_enabled': False, 'country_cidrs': [], 'country_url': 'https://www.ipdeny.com/ipblocks/data/countries/ru.zone',
                     'autoban_enabled': True, 'max_per_ip': 120, 'new_per_minute': 240, 'ban_seconds': 3600},
        'legacy': {},
    }

def client_new(name='Клиент', front='www.google.com'):
    uid = secrets.token_hex(6)
    return {'id': uid, 'name': name, 'username': 'client_' + uid[:8], 'password': secrets.token_urlsafe(18),
            'telegram_secret': 'ee' + secrets.token_hex(16) + front.encode('idna').hex(),
            'enabled': True, 'http': True, 'socks': True, 'telegram': True, 'route_mode': 'default',
            'expires_at': 0, 'blocked_until': 0, 'monthly_limit_gb': 0, 'notes': '', 'created_at': time.time()}

def client_enabled(c):
    now = time.time()
    return c.get('enabled', True) and (not c.get('expires_at') or c['expires_at'] > now) and (not c.get('blocked_until') or c['blocked_until'] < now)

def domain(value):
    value = str(value).lower().strip().removeprefix('*.').strip('.')
    if not value or any(x in value for x in '/: @\r\n'):
        raise ValueError('Нужен домен без протокола и пути')
    return value.encode('idna').decode()

def validate(config):
    c = copy.deepcopy(config)
    if c.get('schema') != 5:
        raise ValueError('Неверный формат конфигурации')
    s = c['settings']
    ranges = {'http_port': (1,65535), 'socks_port': (1,65535), 'telegram_port': (1,65535),
              'check_interval': (15,3600), 'scan_interval': (60,86400), 'availability_interval': (60,86400),
              'subscription_interval': (300,604800), 'parallel_checks': (1,8), 'check_timeout': (2,30),
              'history_days': (1,30), 'history_records': (100,50000), 'event_records': (100,10000),
              'history_mb': (5,100), 'max_connections': (16,2048), 'idle_seconds': (30,3600),
              'switch_margin_ms': (0,2000), 'switch_margin_percent': (0,90)}
    for key,(lo,hi) in ranges.items():
        s[key] = int(s[key])
        if not lo <= s[key] <= hi:
            raise ValueError(f'{key}: допустимо {lo}–{hi}')
    ports = [s[k] for k in ('http_port','socks_port','telegram_port')]
    if len(set(ports)) != 3 or set(ports) & {8099, 19090, 19091, 12080, 12084, 12085}:
        raise ValueError('Порты должны отличаться друг от друга и от внутренних портов приложения')
    if s['selection'] not in ('auto','manual'):
        raise ValueError('Неизвестный режим выбора сервера')
    for key in ('foreign_urls','russian_urls','service_urls'):
        if not 1 <= len(s[key]) <= 5 or any(not u.startswith('https://') or '\n' in u for u in s[key]):
            raise ValueError(f'{key}: от 1 до 5 HTTPS-адресов')
    if len(c['servers']) > 500 or len(c['clients']) > 200 or len(c['sources']) > 50:
        raise ValueError('Превышен предел: 500 серверов, 200 клиентов или 50 подписок')
    for collection in ('servers','clients','sources'):
        ids = [x['id'] for x in c[collection]]
        if len(ids) != len(set(ids)) or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', x) for x in ids):
            raise ValueError('Повторяющийся или недопустимый идентификатор')
    names = set()
    for u in c['clients']:
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', u['username']) or u['username'] in names:
            raise ValueError('Логин должен быть уникальным: латиница, цифры, точка, дефис')
        names.add(u['username'])
        if not 1 <= len(u['password'].encode()) <= 255:
            raise ValueError('Пароль: от 1 до 255 байт')
        try:
            raw = bytes.fromhex(u['telegram_secret'])
            if raw[:1] != b'\xee' or len(raw) <= 17:
                raise ValueError()
            raw[17:].decode('ascii')
        except (ValueError, UnicodeError):
            raise ValueError('Неверный секрет MTProxy Fake TLS') from None
        if u.get('route_mode','default') not in (*MODES,'default'):
            raise ValueError('Неизвестный режим маршрутизации клиента')
    r = c['routing']
    if r['mode'] not in MODES:
        raise ValueError('Неизвестный режим маршрутизации')
    for key in ('vpn_domains','direct_domains'):
        r[key] = sorted(set(domain(x) for x in r[key]))
    for items in (r['vpn_ips'], r['direct_ips'], c['security']['deny_cidrs'], c['security']['allow_cidrs'], c['security']['country_cidrs']):
        for item in items:
            ipaddress.ip_network(item, strict=False)
    for entry in c['security']['trusted']:
        ipaddress.ip_network(entry['cidr'], strict=False)
        if entry['client_id'] not in {x['id'] for x in c['clients']}:
            raise ValueError('У доверенного адреса должен быть существующий клиент')
    for source in c['sources']:
        from urllib.parse import urlsplit
        if urlsplit(source['url']).scheme not in ('http','https'):
            raise ValueError('Подписка: нужна HTTP/HTTPS-ссылка')
        if not 300 <= int(source.get('interval',3600)) <= 604800:
            raise ValueError('Обновление подписки: от 5 минут до 7 дней')
    for rule in r['sources']:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',rule['id']):
            raise ValueError('Неверный ID списка')
        if rule.get('format') not in ('binary','text'):
            raise ValueError('Формат списка: binary или text')
        if rule.get('cache_path') and not str(rule['cache_path']).endswith(('.json','.srs')):
            raise ValueError('Неверный файл списка')
    sec=c['security']
    for key,lo,hi in [('max_per_ip',1,2048),('new_per_minute',1,1000),('ban_seconds',60,86400)]:
        sec[key]=int(sec[key])
        if not lo<=sec[key]<=hi:raise ValueError('Неверный предел защиты: '+key)
    for u in c['clients']:
        u['monthly_limit_gb']=float(u.get('monthly_limit_gb',0))
        if not 0<=u['monthly_limit_gb']<=100000:raise ValueError('Недопустимый лимит трафика')
        for key in ('expires_at','blocked_until'):
            u[key]=float(u.get(key) or 0)
    return c
