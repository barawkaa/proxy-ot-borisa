#!/usr/bin/env python3
import base64
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import secrets
import time
import traceback
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

APP_NAME = "Proxy от Бориса"
APP_VERSION = "1.6.0"
DATA_DIR = Path("/data")
UI_DIR = Path("/app/ui")
TMP_DIR = Path("/tmp/boris-proxy")
DEFAULT_SERVERS_FILE = Path("/defaults/servers.example.json")
OPTIONS_FILE = Path("/data/options.json")
SINGBOX_BIN = "/usr/local/bin/sing-box"
SINGBOX_CONFIG = TMP_DIR / "sing-box.json"
BACKEND_PORT = 8099
MTG_BIN = "/usr/local/bin/mtg"
MTG_CONFIG = TMP_DIR / "mtg.toml"
MTG_UPSTREAM_SOCKS_PORT = 2084
CLASH_API = "http://127.0.0.1:9090"
SESSION_BREAK_SECONDS = 60
RECENT_CLIENT_SECONDS = 300

DATA_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

lock = threading.RLock()
singbox_process = None
mtg_process = None
last_error = ""
last_mtg_error = ""


def log(stage, result, message):
    print(f"[{time.strftime('%H:%M:%S')}] INFO: [STAGE={stage}] [RESULT={result}] {message}", flush=True)


def read_json(path, default):
    try:
        if not Path(path).exists():
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)


def load_options():
    options = read_json(OPTIONS_FILE, {})
    defaults = {
        "secret": "ChangeThisSecret_2026",
        "http_proxy_port": 2081,
        "socks_proxy_port": 2080,
        "socks_auth_enabled": True,
        "http_auth_enabled": False,
        "proxy_username": "user",
        "proxy_password": "ChangeThisProxyPassword",
        "urltest_interval": "2m",
        "urltest_tolerance": 50,
        "log_level": "info",
        "servers_json": "[]",
        "telegram_proxy_enabled": False,
        "telegram_proxy_port": 2083,
        "telegram_front_domain": "www.google.com",
    }
    merged = {**defaults, **options}
    for key in ["http_proxy_port", "socks_proxy_port", "telegram_proxy_port", "urltest_tolerance"]:
        try:
            merged[key] = int(merged[key])
        except Exception:
            merged[key] = defaults[key]
    return merged


def data_path(name):
    return DATA_DIR / name


def load_settings():
    return read_json(data_path("settings.json"), {
        "http_enabled": True,
        "socks_enabled": True,
        "subscription_url": "",
        "traffic_limit_bytes": 0,
        "traffic_used_offset_bytes": 0,
        "created_at": time.time(),
        "updated_at": time.time(),
    })


def save_settings(settings):
    settings["updated_at"] = time.time()
    write_json(data_path("settings.json"), settings)


def make_mtproto_secret(hostname):
    host = (hostname or "www.google.com").strip() or "www.google.com"
    return "ee" + secrets.token_hex(16) + host.encode("utf-8").hex()


def load_telegram_settings():
    options = load_options()
    defaults = {
        "enabled": bool(options.get("telegram_proxy_enabled", False)),
        "port": int(options.get("telegram_proxy_port", 2083)),
        "front_domain": str(options.get("telegram_front_domain", "www.google.com") or "www.google.com"),
        "secret": "",
        "public_host": "",
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    data = read_json(data_path("telegram_proxy.json"), {})
    result = {**defaults, **data}
    try:
        result["port"] = int(result.get("port") or defaults["port"])
    except Exception:
        result["port"] = defaults["port"]
    if not result.get("secret"):
        result["secret"] = make_mtproto_secret(result.get("front_domain"))
        save_telegram_settings(result)
    return result


def save_telegram_settings(data):
    data["updated_at"] = time.time()
    write_json(data_path("telegram_proxy.json"), data)


def toml_quote(value):
    return json.dumps(str(value), ensure_ascii=False)


def mtproxy_urls(public_host=None):
    tg = load_telegram_settings()
    host = (public_host or tg.get("public_host") or "").strip()
    port = int(tg.get("port") or load_options().get("telegram_proxy_port", 2083))
    secret_value = tg.get("secret") or ""
    if not host:
        return {"tg_url": "", "tme_url": ""}
    q = urllib.parse.urlencode({"server": host, "port": str(port), "secret": secret_value})
    return {"tg_url": "tg://proxy?" + q, "tme_url": "https://t.me/proxy?" + q}


def write_mtg_config():
    tg = load_telegram_settings()
    secret_value = tg.get("secret") or make_mtproto_secret(tg.get("front_domain"))
    if not tg.get("secret"):
        tg["secret"] = secret_value
        save_telegram_settings(tg)
    port = int(tg.get("port") or load_options().get("telegram_proxy_port", 2083))
    upstream = f"socks5://127.0.0.1:{MTG_UPSTREAM_SOCKS_PORT}"
    lines = [
        f"secret = {toml_quote(secret_value)}",
        f"bind-to = {toml_quote('0.0.0.0:' + str(port))}",
        'prefer-ip = "prefer-ipv4"',
        'auto-update = false',
        '',
        '[network]',
        'dns = "https://1.1.1.1/dns-query"',
        f"proxies = [{toml_quote(upstream)}]",
        '',
        '[network.timeout]',
        'tcp = "10s"',
        'http = "10s"',
        'idle = "10m"',
        'handshake = "10s"',
        '',
        '[defense.blocklist]',
        'enabled = false',
        '',
        '[stats.prometheus]',
        'enabled = false',
        '',
    ]
    MTG_CONFIG.write_text("\n".join(lines), encoding="utf-8")
    return MTG_CONFIG


def stop_mtg():
    global mtg_process
    if mtg_process and mtg_process.poll() is None:
        log("MTG", "STOP", "Stopping Telegram MTProto proxy")
        mtg_process.terminate()
        try:
            mtg_process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            mtg_process.kill()
            mtg_process.wait(timeout=5)
    mtg_process = None


def start_mtg():
    global mtg_process, last_mtg_error
    tg = load_telegram_settings()
    if not tg.get("enabled", False):
        stop_mtg()
        last_mtg_error = ""
        return False
    if not os.path.exists(MTG_BIN):
        last_mtg_error = "mtg binary not found"
        log("MTG", "ERROR", last_mtg_error)
        return False
    write_mtg_config()
    stop_mtg()
    log("MTG", "START", f"Starting MTProto proxy on 0.0.0.0:{tg.get('port')} via SOCKS5 127.0.0.1:{MTG_UPSTREAM_SOCKS_PORT}")
    mtg_process = subprocess.Popen([MTG_BIN, "run", str(MTG_CONFIG)], stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(0.8)
    if mtg_process.poll() is not None:
        last_mtg_error = f"mtg exited with code {mtg_process.returncode}"
        log("MTG", "ERROR", last_mtg_error)
        return False
    last_mtg_error = ""
    return True


def restart_mtg():
    with lock:
        stop_mtg()
        return start_mtg()


def mtg_status():
    tg = load_telegram_settings()
    running = bool(mtg_process and mtg_process.poll() is None)
    return {
        "enabled": bool(tg.get("enabled", False)),
        "running": running,
        "port": int(tg.get("port") or load_options().get("telegram_proxy_port", 2083)),
        "front_domain": tg.get("front_domain") or "www.google.com",
        "public_host": tg.get("public_host") or "",
        "secret": tg.get("secret") or "",
        "last_error": last_mtg_error,
        "upstream": f"socks5://127.0.0.1:{MTG_UPSTREAM_SOCKS_PORT}",
        **mtproxy_urls(),
    }


def load_servers():
    path = data_path("servers.json")
    if not path.exists():
        options = load_options()
        raw = str(options.get("servers_json", "[]")).strip()
        servers = []
        if raw and raw != "[]":
            try:
                servers = parse_servers_payload(raw)["servers"]
                log("SERVERS_INIT", "OK", f"Imported {len(servers)} servers from add-on configuration")
            except Exception as e:
                log("SERVERS_INIT", "ERROR", f"Failed to import servers_json: {e}")
        if not servers and DEFAULT_SERVERS_FILE.exists():
            servers = read_json(DEFAULT_SERVERS_FILE, [])
            log("SERVERS_INIT", "OK", f"Loaded {len(servers)} servers from defaults")
        write_json(path, servers)
    return read_json(path, [])


def save_servers(servers):
    backup_path = data_path(f"servers.backup.{int(time.time())}.json")
    current = read_json(data_path("servers.json"), None)
    if current is not None:
        write_json(backup_path, current)
    write_json(data_path("servers.json"), servers)


def load_blocked():
    return read_json(data_path("blocked_ips.json"), [])


def save_blocked(items):
    write_json(data_path("blocked_ips.json"), items)


def load_trusted():
    return read_json(data_path("trusted_clients.json"), {})


def save_trusted(items):
    write_json(data_path("trusted_clients.json"), items)


def load_clients():
    return read_json(data_path("clients.json"), {})


def save_clients(items):
    write_json(data_path("clients.json"), items)


def load_traffic():
    return read_json(data_path("traffic.json"), {
        "limit_bytes": 0,
        "used_bytes": 0,
        "connection_bytes": {},
        "updated_at": time.time(),
    })


def save_traffic(items):
    items["updated_at"] = time.time()
    write_json(data_path("traffic.json"), items)


def safe_tag(value, fallback="SERVER"):
    value = urllib.parse.unquote(str(value or "")).strip()
    value = re.sub(r"[^A-Za-z0-9_.@()\-]+", "-", value)
    value = value.strip("-._")
    return value or fallback


def normalize_ip_cidr(ip):
    ip = str(ip).strip()
    if not ip:
        raise ValueError("IP пустой")
    if "/" in ip:
        net = ipaddress.ip_network(ip, strict=False)
        return str(net)
    addr = ipaddress.ip_address(ip)
    return f"{addr}/32" if addr.version == 4 else f"{addr}/128"


def extract_ip_from_cidr(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return str(net.network_address)
    except Exception:
        return cidr.split("/")[0]


def parse_vless_uri(uri, index=0):
    uri = uri.strip()
    if not uri.lower().startswith("vless://"):
        raise ValueError("Поддерживаются только vless:// ссылки")
    parsed = urllib.parse.urlparse(uri)
    uuid = parsed.username or ""
    server = parsed.hostname or ""
    port = parsed.port or 443
    query = urllib.parse.parse_qs(parsed.query)
    q = {k: v[-1] for k, v in query.items() if v}
    tag = safe_tag(parsed.fragment or q.get("remarks") or q.get("name") or f"VLESS-{index}", f"VLESS-{index}")
    outbound = {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": int(port),
        "uuid": uuid,
        "packet_encoding": q.get("packetEncoding") or q.get("packet_encoding") or "xudp",
    }
    flow = q.get("flow")
    if flow:
        outbound["flow"] = flow
    security = (q.get("security") or "").lower()
    sni = q.get("sni") or q.get("serverName") or q.get("peer") or server
    fp = q.get("fp") or q.get("fingerprint") or "chrome"
    pbk = q.get("pbk") or q.get("publicKey") or q.get("public_key")
    sid = q.get("sid") or q.get("shortId") or q.get("short_id") or ""
    if security in ["tls", "reality"] or pbk:
        tls = {
            "enabled": True,
            "server_name": sni,
            "utls": {"enabled": True, "fingerprint": fp},
        }
        if security == "reality" or pbk:
            tls["reality"] = {"enabled": True, "public_key": pbk or "", "short_id": sid}
        outbound["tls"] = tls
    transport_type = (q.get("type") or q.get("transport") or "tcp").lower()
    if transport_type == "ws":
        transport = {"type": "ws"}
        if q.get("path"):
            transport["path"] = q.get("path")
        host = q.get("host")
        if host:
            transport["headers"] = {"Host": host}
        outbound["transport"] = transport
    elif transport_type == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName") or q.get("service_name") or ""}
    return outbound


def try_decode_base64(text):
    stripped = re.sub(r"\s+", "", text.strip())
    if not stripped:
        return text
    padding = "=" * (-len(stripped) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder((stripped + padding).encode()).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return text


def parse_servers_payload(text):
    text = (text or "").strip()
    errors = []
    if not text:
        return {"servers": [], "errors": ["Пустые данные"]}
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            servers = parsed
        elif isinstance(parsed, dict) and isinstance(parsed.get("outbounds"), list):
            servers = [x for x in parsed["outbounds"] if isinstance(x, dict) and x.get("type") not in ["selector", "urltest", "direct", "block"]]
        elif isinstance(parsed, dict) and isinstance(parsed.get("servers"), list):
            servers = parsed["servers"]
        else:
            raise ValueError("JSON должен быть массивом серверов или объектом с outbounds/servers")
        return validate_servers(servers)
    except Exception as e:
        errors.append(f"JSON: {e}")
    candidate = text if "vless://" in text.lower() else try_decode_base64(text)
    links = re.findall(r"vless://[^\s\r\n]+", candidate, flags=re.IGNORECASE)
    servers = []
    for i, link in enumerate(links):
        try:
            servers.append(parse_vless_uri(link, i))
        except Exception as e:
            errors.append(f"{link[:60]}...: {e}")
    if servers:
        validated = validate_servers(servers)
        validated["errors"].extend(errors)
        return validated
    return {"servers": [], "errors": errors or ["Не найден JSON или vless:// ссылки"]}


def validate_servers(servers):
    result = []
    errors = []
    used_tags = set()
    for i, item in enumerate(servers):
        if not isinstance(item, dict):
            errors.append(f"Элемент #{i+1}: не объект")
            continue
        item = dict(item)
        typ = item.get("type")
        tag = safe_tag(item.get("tag") or f"SERVER-{i+1}", f"SERVER-{i+1}")
        if tag in used_tags:
            base = tag
            n = 2
            while f"{base}-{n}" in used_tags:
                n += 1
            tag = f"{base}-{n}"
        item["tag"] = tag
        used_tags.add(tag)
        if not typ:
            errors.append(f"{tag}: не указан type")
            continue
        if typ in ["selector", "urltest", "direct", "block"]:
            errors.append(f"{tag}: служебный outbound не добавлен в список серверов")
            continue
        if typ in ["vless", "vmess", "trojan", "shadowsocks"] and not item.get("server"):
            errors.append(f"{tag}: не указан server")
            continue
        result.append(item)
    return {"servers": result, "errors": errors}


def fetch_text(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyOtBorisa/1.5"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def selector_outbounds(servers):
    tags = [s.get("tag") for s in servers if s.get("tag")]
    if tags:
        return ["auto"] + tags
    return ["direct"]


def make_singbox_config():
    options = load_options()
    settings = load_settings()
    servers = load_servers()
    blocked = load_blocked()
    server_tags = [s.get("tag") for s in servers if s.get("tag")]
    http_port = int(options["http_proxy_port"])
    socks_port = int(options["socks_proxy_port"])
    socks_tag = f"IN-SOCKS5-{socks_port}"
    http_tag = f"IN-HTTP-{http_port}"
    mtg_upstream_tag = f"IN-MTG-UPSTREAM-{MTG_UPSTREAM_SOCKS_PORT}"
    socks_auth = []
    http_auth = []
    if options.get("socks_auth_enabled"):
        socks_auth = [{"username": options.get("proxy_username", ""), "password": options.get("proxy_password", "")}]
    if options.get("http_auth_enabled"):
        http_auth = [{"username": options.get("proxy_username", ""), "password": options.get("proxy_password", "")}]
    inbounds = [
        {"type": "socks", "tag": socks_tag, "listen": "0.0.0.0", "listen_port": socks_port},
        {"type": "http", "tag": http_tag, "listen": "0.0.0.0", "listen_port": http_port},
        {"type": "socks", "tag": mtg_upstream_tag, "listen": "127.0.0.1", "listen_port": MTG_UPSTREAM_SOCKS_PORT},
    ]
    if socks_auth:
        inbounds[0]["users"] = socks_auth
    if http_auth:
        inbounds[1]["users"] = http_auth
    proxy_selector = {
        "type": "selector",
        "tag": "Proxy",
        "outbounds": selector_outbounds(servers),
        "default": "auto" if server_tags else "direct",
    }
    outbounds = [
        {"type": "selector", "tag": "SOCKS_POWER", "outbounds": ["Proxy", "block"], "default": "Proxy" if settings.get("socks_enabled", True) else "block", "interrupt_exist_connections": True},
        {"type": "selector", "tag": "HTTP_POWER", "outbounds": ["Proxy", "block"], "default": "Proxy" if settings.get("http_enabled", True) else "block", "interrupt_exist_connections": True},
        proxy_selector,
    ]
    if server_tags:
        outbounds.append({"type": "urltest", "tag": "auto", "outbounds": server_tags, "url": "https://www.gstatic.com/generate_204", "interval": options.get("urltest_interval", "2m"), "tolerance": int(options.get("urltest_tolerance", 50))})
    outbounds.extend(servers)
    outbounds.extend([{"type": "block", "tag": "block"}, {"type": "direct", "tag": "direct"}])
    rules = []
    blocked_cidrs = [item.get("cidr") for item in blocked if item.get("cidr")]
    if blocked_cidrs:
        rules.append({"source_ip_cidr": blocked_cidrs, "outbound": "block"})
    rules.extend([
        {"inbound": [mtg_upstream_tag], "outbound": "Proxy"},
        {"inbound": [socks_tag], "outbound": "SOCKS_POWER"},
        {"inbound": [http_tag], "outbound": "HTTP_POWER"},
    ])
    return {
        "log": {"level": options.get("log_level", "info"), "timestamp": True},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090", "secret": options.get("secret", "")}},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "Proxy", "auto_detect_interface": True},
    }


def clash_request(method, path, body=None, timeout=8):
    options = load_options()
    url = CLASH_API + path
    data = None
    headers = {"Content-Type": "application/json"}
    if options.get("secret"):
        headers["Authorization"] = "Bearer " + str(options.get("secret"))
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="ignore")
        if not text:
            return None
        return json.loads(text)


def write_config():
    cfg = make_singbox_config()
    write_json(SINGBOX_CONFIG, cfg)
    return cfg


def stop_singbox():
    global singbox_process
    if singbox_process and singbox_process.poll() is None:
        log("SING_BOX", "STOP", "Stopping sing-box")
        singbox_process.terminate()
        try:
            singbox_process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            singbox_process.kill()
            singbox_process.wait(timeout=5)
    singbox_process = None


def start_singbox():
    global singbox_process, last_error
    write_config()
    log("SING_BOX", "START", f"Starting sing-box with {SINGBOX_CONFIG}")
    singbox_process = subprocess.Popen([SINGBOX_BIN, "run", "-c", str(SINGBOX_CONFIG)], stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(0.8)
    if singbox_process.poll() is not None:
        last_error = f"sing-box exited with code {singbox_process.returncode}"
        log("SING_BOX", "ERROR", last_error)
        raise RuntimeError(last_error)
    last_error = ""
    apply_power_selectors()
    start_mtg()


def restart_singbox():
    with lock:
        stop_mtg()
        stop_singbox()
        start_singbox()


def apply_power_selectors():
    settings = load_settings()
    time.sleep(0.2)
    for tag, enabled in [("SOCKS_POWER", settings.get("socks_enabled", True)), ("HTTP_POWER", settings.get("http_enabled", True))]:
        try:
            clash_request("PUT", f"/proxies/{urllib.parse.quote(tag)}", {"name": "Proxy" if enabled else "block"}, timeout=3)
        except Exception as e:
            log("POWER", "WARN", f"Failed to apply {tag}: {e}")


def get_proxies():
    try:
        data = clash_request("GET", "/proxies", timeout=5)
        return data.get("proxies", data) if isinstance(data, dict) else {}
    except Exception:
        return {}


def get_connections_raw():
    try:
        data = clash_request("GET", "/connections", timeout=5)
        if isinstance(data, dict) and isinstance(data.get("connections"), list):
            return data["connections"]
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def get_conn_id(conn):
    return conn.get("id") or conn.get("ID") or conn.get("uuid") or (conn.get("metadata") or {}).get("uid") or ""


def get_source_ip(conn):
    meta = conn.get("metadata") or {}
    return meta.get("sourceIP") or meta.get("source_ip") or conn.get("source") or conn.get("sourceIP") or "—"


def get_host(conn):
    meta = conn.get("metadata") or {}
    return meta.get("host") or meta.get("domain") or meta.get("destinationIP") or meta.get("destination_ip") or conn.get("host") or "—"


def is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return True


def geo_lookup(ip):
    cache = read_json(data_path("geo_cache.json"), {})
    if ip in cache and time.time() - cache[ip].get("ts", 0) < 86400:
        return cache[ip]["data"]
    if is_private_ip(ip):
        info = {"country": "Локальная сеть", "region": "LAN", "city": "", "isp": "", "org": "", "asn": "", "timezone": "", "lat": None, "lon": None, "source": "local"}
    else:
        info = {"country": "—", "region": "—", "city": "", "isp": "геолокация недоступна", "org": "", "asn": "", "timezone": "", "lat": None, "lon": None, "source": "ip-api.com"}
        try:
            url = "http://ip-api.com/json/{}?fields=status,country,regionName,city,isp,org,as,timezone,lat,lon,query".format(urllib.parse.quote(ip))
            data = json.loads(fetch_text(url, timeout=5))
            if data.get("status") == "success":
                info = {"country": data.get("country") or "—", "region": data.get("regionName") or "—", "city": data.get("city") or "", "isp": data.get("isp") or "", "org": data.get("org") or "", "asn": data.get("as") or "", "timezone": data.get("timezone") or "", "lat": data.get("lat"), "lon": data.get("lon"), "source": "ip-api.com"}
        except Exception as e:
            info["error"] = str(e)
    cache[ip] = {"ts": time.time(), "data": info}
    write_json(data_path("geo_cache.json"), cache)
    return info


def update_traffic(connections):
    traffic = load_traffic()
    alive = set()
    for conn in connections:
        cid = get_conn_id(conn)
        if not cid:
            continue
        alive.add(cid)
        total = int(conn.get("upload") or 0) + int(conn.get("download") or 0)
        prev = int((traffic.get("connection_bytes") or {}).get(cid, 0))
        if total > prev:
            traffic["used_bytes"] = int(traffic.get("used_bytes", 0)) + (total - prev)
            traffic.setdefault("connection_bytes", {})[cid] = total
    for cid in list((traffic.get("connection_bytes") or {}).keys()):
        if cid not in alive:
            del traffic["connection_bytes"][cid]
    save_traffic(traffic)


def build_clients(connections):
    now = time.time()
    history = load_clients()
    trusted = load_trusted()
    grouped = {}
    for conn in connections:
        ip = get_source_ip(conn)
        if not ip or ip == "—":
            continue
        old = history.get(ip, {})
        if ip not in grouped:
            was_offline_long = old.get("last_seen") and (now - old.get("last_seen", 0) > SESSION_BREAK_SECONDS)
            first_time = not old.get("first_seen")
            grouped[ip] = {
                "ip": ip,
                "status": "online",
                "connections": [],
                "upload": 0,
                "download": 0,
                "hosts": set(),
                "first_seen": old.get("first_seen") or now,
                "session_started": now if first_time or was_offline_long else old.get("session_started", now),
                "last_seen": now,
                "seen_count": 1 if first_time else (int(old.get("seen_count", 1)) + 1 if was_offline_long else int(old.get("seen_count", 1))),
                "trusted": ip in trusted,
                "trusted_name": (trusted.get(ip) or {}).get("name", ""),
                "trusted_at": (trusted.get(ip) or {}).get("trusted_at"),
                "is_public": not is_private_ip(ip),
            }
        grouped[ip]["connections"].append(conn)
        grouped[ip]["upload"] += int(conn.get("upload") or 0)
        grouped[ip]["download"] += int(conn.get("download") or 0)
        host = get_host(conn)
        port = (conn.get("metadata") or {}).get("destinationPort") or (conn.get("metadata") or {}).get("destination_port") or ""
        if host and host != "—":
            grouped[ip]["hosts"].add(f"{host}:{port}" if port else host)
    active_ips = set(grouped.keys())
    for ip, item in grouped.items():
        history[ip] = {"first_seen": item["first_seen"], "session_started": item["session_started"], "last_seen": item["last_seen"], "seen_count": item["seen_count"]}
    for ip, old in list(history.items()):
        if ip in active_ips:
            continue
        if old.get("last_seen") and now - old["last_seen"] <= RECENT_CLIENT_SECONDS:
            grouped[ip] = {"ip": ip, "status": "recent", "connections": [], "upload": 0, "download": 0, "hosts": set(), "first_seen": old.get("first_seen"), "session_started": old.get("session_started"), "last_seen": old.get("last_seen"), "seen_count": old.get("seen_count", 1), "trusted": ip in trusted, "trusted_name": (trusted.get(ip) or {}).get("name", ""), "trusted_at": (trusted.get(ip) or {}).get("trusted_at"), "is_public": not is_private_ip(ip)}
    save_clients(history)
    result = []
    for ip, item in grouped.items():
        item = dict(item)
        item["hosts"] = list(item["hosts"])[:12]
        item["geo"] = geo_lookup(ip)
        item["risk"] = risk_level(item)
        item["connections_count"] = len(item["connections"])
        item.pop("connections", None)
        result.append(item)
    return sorted(result, key=lambda x: (0 if x["status"] == "online" else 1, 0 if not x["trusted"] else 1, -x["last_seen"]))


def risk_level(client):
    if client.get("trusted"):
        return "trusted"
    if client.get("is_public"):
        return "high"
    if int(client.get("connections_count", len(client.get("connections", [])))) >= 20:
        return "medium"
    if int(client.get("upload", 0)) + int(client.get("download", 0)) > 100 * 1024 * 1024:
        return "medium"
    return "medium" if client.get("status") == "online" else "low"


def current_server_info(proxies):
    group = proxies.get("Proxy") or proxies.get("GLOBAL") or {}
    mode = group.get("now") or group.get("selected") or "—"
    actual = mode
    if mode == "auto" and isinstance(proxies.get("auto"), dict):
        actual = proxies["auto"].get("now") or proxies["auto"].get("selected") or "—"
    p = proxies.get(actual, {}) if isinstance(proxies, dict) else {}
    delay = None
    hist = p.get("history") if isinstance(p, dict) else None
    if isinstance(hist, list) and hist:
        delay = hist[-1].get("delay")
    if not delay:
        delay = p.get("delay") if isinstance(p, dict) else None
    return {"mode": mode, "server": actual, "delay": delay}


def close_connection(cid):
    if not cid:
        return False
    try:
        clash_request("DELETE", f"/connections/{urllib.parse.quote(cid)}", timeout=5)
        return True
    except Exception:
        return False


def close_all_connections():
    try:
        clash_request("DELETE", "/connections", timeout=5)
        return True
    except Exception:
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "ProxyOtBorisa/1.6.0"

    def log_message(self, fmt, *args):
        return

    def send_json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        try:
            return json.loads(raw)
        except Exception:
            return {"raw": raw}

    def serve_file(self, path):
        p = UI_DIR / path.lstrip("/")
        if path in ["", "/"]:
            p = UI_DIR / "index.html"
        if not p.exists() or not p.is_file():
            self.send_error(404)
            return
        content = p.read_bytes()
        ctype = "text/html; charset=utf-8" if p.suffix == ".html" else "application/octet-stream"
        if p.suffix == ".js":
            ctype = "application/javascript; charset=utf-8"
        elif p.suffix == ".css":
            ctype = "text/css; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if not path.startswith("/api"):
                return self.serve_file(path)
            if path == "/api/status":
                options = load_options(); settings = load_settings(); servers = load_servers(); blocked = load_blocked(); proxies = get_proxies(); conns = get_connections_raw(); update_traffic(conns)
                return self.send_json({"app": APP_NAME, "version": APP_VERSION, "singbox_running": bool(singbox_process and singbox_process.poll() is None), "last_error": last_error, "telegram": mtg_status(), "settings": settings, "options": {"http_proxy_port": options["http_proxy_port"], "socks_proxy_port": options["socks_proxy_port"], "socks_auth_enabled": options["socks_auth_enabled"], "http_auth_enabled": options["http_auth_enabled"], "proxy_username": options.get("proxy_username")}, "servers_count": len(servers), "blocked_count": len(blocked), "connections_count": len(conns), "current": current_server_info(proxies), "proxies": proxies})
            if path == "/api/proxies":
                return self.send_json(get_proxies())
            if path == "/api/connections":
                conns = get_connections_raw(); update_traffic(conns); return self.send_json({"connections": conns})
            if path == "/api/clients":
                conns = get_connections_raw(); update_traffic(conns); return self.send_json({"clients": build_clients(conns)})
            if path == "/api/servers":
                settings = load_settings(); return self.send_json({"servers": load_servers(), "subscription_url": settings.get("subscription_url", "")})
            if path == "/api/telegram":
                host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
                return self.send_json({"telegram": mtg_status(), "detected_host": host.split(":")[0] if host else ""})
            if path == "/api/blocklist":
                return self.send_json({"blocked": load_blocked()})
            if path == "/api/trusted":
                return self.send_json({"trusted": load_trusted()})
            if path == "/api/traffic":
                return self.send_json(load_traffic())
            if path.startswith("/api/geo/"):
                ip = urllib.parse.unquote(path.split("/api/geo/", 1)[1]); return self.send_json(geo_lookup(ip))
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            traceback.print_exc()
            self.send_json({"error": str(e)}, 500)

    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            body = self.read_body()
            if path == "/api/power":
                settings = load_settings()
                if "http_enabled" in body:
                    settings["http_enabled"] = bool(body["http_enabled"])
                if "socks_enabled" in body:
                    settings["socks_enabled"] = bool(body["socks_enabled"])
                save_settings(settings)
                apply_power_selectors()
                if "telegram_enabled" in body:
                    tg = load_telegram_settings()
                    tg["enabled"] = bool(body["telegram_enabled"])
                    save_telegram_settings(tg)
                    restart_mtg()
                if not settings.get("http_enabled", True) or not settings.get("socks_enabled", True):
                    close_all_connections()
                return self.send_json({"ok": True, "settings": settings, "telegram": mtg_status()})
            if path == "/api/telegram":
                tg = load_telegram_settings()
                action = body.get("action") or "update"
                if "enabled" in body:
                    tg["enabled"] = bool(body["enabled"])
                if body.get("port"):
                    tg["port"] = int(body.get("port"))
                if body.get("front_domain"):
                    tg["front_domain"] = str(body.get("front_domain")).strip()
                if "public_host" in body:
                    tg["public_host"] = str(body.get("public_host") or "").strip()
                if action == "regenerate_secret":
                    tg["secret"] = make_mtproto_secret(tg.get("front_domain"))
                if action == "disable":
                    tg["enabled"] = False
                if action == "enable":
                    tg["enabled"] = True
                save_telegram_settings(tg)
                if action in ["restart", "regenerate_secret", "enable", "disable", "update"] or "enabled" in body:
                    restart_mtg()
                return self.send_json({"ok": True, "telegram": mtg_status()})
            if path == "/api/proxy/select":
                name = body.get("name")
                clash_request("PUT", "/proxies/Proxy", {"name": name}, timeout=5)
                return self.send_json({"ok": True})
            if path == "/api/ping":
                proxies = get_proxies()
                names = body.get("names") or []
                if not names:
                    group = proxies.get("Proxy") or {}
                    names = [x for x in (group.get("all") or group.get("proxies") or []) if x != "auto"]
                results = {}
                for name in names:
                    try:
                        results[name] = clash_request("GET", f"/proxies/{urllib.parse.quote(name)}/delay?timeout=5000&url={urllib.parse.quote('https://www.gstatic.com/generate_204')}", timeout=8)
                    except Exception as e:
                        results[name] = {"error": str(e)}
                return self.send_json({"ok": True, "results": results})
            if path == "/api/connections/close_all":
                return self.send_json({"ok": close_all_connections()})
            if path == "/api/clients/disconnect":
                ip = body.get("ip")
                conns = get_connections_raw(); closed = 0
                for c in conns:
                    if get_source_ip(c) == ip and close_connection(get_conn_id(c)):
                        closed += 1
                return self.send_json({"ok": True, "closed": closed})
            if path == "/api/blocklist":
                ip = body.get("ip") or body.get("cidr")
                comment = body.get("comment") or ""
                cidr = normalize_ip_cidr(ip)
                items = load_blocked()
                if not any(x.get("cidr") == cidr for x in items):
                    items.append({"cidr": cidr, "ip": extract_ip_from_cidr(cidr), "comment": comment, "created_at": time.time()})
                    save_blocked(items)
                    restart_singbox()
                return self.send_json({"ok": True, "blocked": items})
            if path == "/api/clients/block":
                ip = body.get("ip"); comment = body.get("comment") or "Blocked from clients panel"
                cidr = normalize_ip_cidr(ip)
                items = load_blocked()
                if not any(x.get("cidr") == cidr for x in items):
                    items.append({"cidr": cidr, "ip": extract_ip_from_cidr(cidr), "comment": comment, "created_at": time.time()})
                    save_blocked(items)
                restart_singbox(); close_all_connections()
                return self.send_json({"ok": True, "blocked": items})
            if path == "/api/trusted":
                ip = body.get("ip"); name = body.get("name") or "Моё устройство"
                trusted = load_trusted(); trusted[ip] = {"name": name, "trusted_at": time.time()}; save_trusted(trusted)
                return self.send_json({"ok": True, "trusted": trusted})
            if path == "/api/servers/import":
                mode = body.get("mode", "json")
                append = bool(body.get("append", False))
                text = body.get("text", "")
                url = body.get("url", "")
                settings = load_settings()
                if mode == "url":
                    if not url:
                        raise ValueError("URL подписки не указан")
                    text = fetch_text(url, timeout=25)
                    settings["subscription_url"] = url
                    save_settings(settings)
                parsed = parse_servers_payload(text)
                new_servers = parsed["servers"]
                if not new_servers:
                    return self.send_json({"ok": False, "errors": parsed.get("errors", [])}, 400)
                final = load_servers() + new_servers if append else new_servers
                final = validate_servers(final)["servers"]
                save_servers(final)
                restart_singbox()
                return self.send_json({"ok": True, "count": len(final), "imported": len(new_servers), "errors": parsed.get("errors", [])})
            if path == "/api/servers/refresh":
                settings = load_settings(); url = body.get("url") or settings.get("subscription_url")
                if not url:
                    raise ValueError("Ссылка подписки не сохранена")
                text = fetch_text(url, timeout=25)
                parsed = parse_servers_payload(text)
                if not parsed["servers"]:
                    return self.send_json({"ok": False, "errors": parsed.get("errors", [])}, 400)
                settings["subscription_url"] = url; save_settings(settings)
                save_servers(parsed["servers"]); restart_singbox()
                return self.send_json({"ok": True, "count": len(parsed["servers"]), "errors": parsed.get("errors", [])})
            if path == "/api/traffic":
                traffic = load_traffic()
                if "limit_bytes" in body:
                    traffic["limit_bytes"] = int(body.get("limit_bytes") or 0)
                if "used_bytes" in body:
                    traffic["used_bytes"] = int(body.get("used_bytes") or 0)
                save_traffic(traffic); return self.send_json({"ok": True, "traffic": traffic})
            if path == "/api/traffic/reset":
                traffic = load_traffic(); traffic["used_bytes"] = 0; traffic["connection_bytes"] = {}; save_traffic(traffic); return self.send_json({"ok": True, "traffic": traffic})
            if path == "/api/restart":
                restart_singbox(); return self.send_json({"ok": True})
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            traceback.print_exc()
            self.send_json({"error": str(e)}, 500)

    def do_DELETE(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/api/blocklist/"):
                cidr_or_ip = urllib.parse.unquote(path.split("/api/blocklist/", 1)[1])
                items = [x for x in load_blocked() if x.get("cidr") != cidr_or_ip and x.get("ip") != cidr_or_ip]
                save_blocked(items); restart_singbox(); return self.send_json({"ok": True, "blocked": items})
            if path.startswith("/api/trusted/"):
                ip = urllib.parse.unquote(path.split("/api/trusted/", 1)[1])
                trusted = load_trusted(); trusted.pop(ip, None); save_trusted(trusted); return self.send_json({"ok": True, "trusted": trusted})
            if path.startswith("/api/servers/"):
                tag = urllib.parse.unquote(path.split("/api/servers/", 1)[1])
                servers = [s for s in load_servers() if s.get("tag") != tag]
                save_servers(servers); restart_singbox(); return self.send_json({"ok": True, "servers": servers})
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            traceback.print_exc()
            self.send_json({"error": str(e)}, 500)


def shutdown_handler(signum, frame):
    stop_mtg()
    stop_singbox()
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    load_servers()
    start_singbox()
    server = ThreadingHTTPServer(("0.0.0.0", BACKEND_PORT), Handler)
    log("BACKEND", "READY", f"Management UI listening on 0.0.0.0:{BACKEND_PORT}")
    try:
        server.serve_forever()
    finally:
        stop_mtg()
        stop_singbox()


if __name__ == "__main__":
    main()
