#!/usr/bin/env python3
import base64
import ipaddress
import json
import os
import re
import signal
import socket
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
APP_VERSION = "1.14.0"
DATA_DIR = Path("/data")
UI_DIR = Path("/app/ui")
TMP_DIR = Path("/tmp/boris-proxy")
DEFAULT_SERVERS_FILE = Path("/defaults/servers.example.json")
OPTIONS_FILE = Path("/data/options.json")
RUNTIME_PORTS_FILE = Path("/data/runtime_ports.json")
PORT_KEYS = ["http_proxy_port", "socks_proxy_port", "telegram_proxy_port"]
SINGBOX_BIN = "/usr/local/bin/sing-box"
SINGBOX_CONFIG = TMP_DIR / "sing-box.json"
BACKEND_PORT = 8099
MTG_BIN = "/usr/local/bin/mtg-multi"
MTG_CONFIG = TMP_DIR / "mtg.toml"
MTG_UPSTREAM_SOCKS_PORT = 2084
CLASH_API = "http://127.0.0.1:9090"
SESSION_BREAK_SECONDS = 60
RECENT_CLIENT_SECONDS = 300
OFFLINE_CLIENT_KEEP_SECONDS = 30 * 24 * 3600
EVENT_LOG_LIMIT = 2000
SINGBOX_STARTED_AT = 0
MONITOR_INTERVAL_SECONDS = 15
AUTOBAN_CHECK_INTERVAL_SECONDS = 30
connections_cache = {"items": [], "updated_at": 0, "last_autoban_at": 0}

RULES_DIR = DATA_DIR / "rules"
RULES_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_ROUTING = {
    "mode": "all_proxy",  # all_proxy | blocked_plus_manual | manual_only | all_direct
    "updated_at": 0,
    "last_apply_at": 0,
    "auto_update_enabled": False,
    "auto_update_interval_hours": 24,
    "manual_include_domains": [],
    "manual_include_ips": [],
    "manual_exclude_domains": [],
    "manual_exclude_ips": [],
    "presets": {
        "youtube": False,
        "openai": False,
        "instagram_meta": False,
        "discord": False,
        "telegram": False,
        "nintendo": False,
        "tiktok": False,
        "spotify": False,
    },
    "sources": [
        {
            "tag": "refilter_domains",
            "name": "Re:filter — домены РФ .srs",
            "kind": "domain_suffix",
            "format": "remote_srs",
            "enabled": True,
            "url": "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs",
            "description": "Готовый бинарный rule-set Sing-Box: заблокированные/ограниченные домены РФ. Основной источник."
        },
        {
            "tag": "refilter_ipsum",
            "name": "Re:filter — IP/CIDR РФ .srs",
            "kind": "ip_cidr",
            "format": "remote_srs",
            "enabled": True,
            "url": "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-ip-refilter_ipsum.srs",
            "description": "Готовый бинарный rule-set Sing-Box: суммированный список IP/подсетей Re:filter. Основной источник."
        },
        {
            "tag": "legiz_ru_bundle",
            "name": "legiz-ru ru-bundle.srs",
            "kind": "mixed",
            "format": "remote_srs",
            "enabled": False,
            "url": "https://github.com/legiz-ru/sb-rule-sets/raw/main/ru-bundle.srs",
            "description": "Готовый sing-box rule-set для RU-blocked/unban ресурсов. Дополнительный источник."
        },
        {
            "tag": "legiz_rknasnblock",
            "name": "legiz-ru rknasnblock.srs",
            "kind": "ip_cidr",
            "format": "remote_srs",
            "enabled": False,
            "url": "https://github.com/legiz-ru/sb-rule-sets/raw/main/rknasnblock.srs",
            "description": "Готовый sing-box rule-set по ASN/IP блокировкам. Дополнительный источник."
        },
        {
            "tag": "antifilter_domains",
            "name": "AntiFilter — домены TXT",
            "kind": "domain_suffix",
            "format": "text",
            "enabled": False,
            "url": "https://antifilter.download/list/domains.lst",
            "path": "/data/rules/antifilter_domains.json",
            "description": "Текстовый список доменов antifilter.download, конвертируется backend'ом в source rule-set."
        },
        {
            "tag": "antifilter_ips",
            "name": "AntiFilter — IP/CIDR TXT",
            "kind": "ip_cidr",
            "format": "text",
            "enabled": False,
            "url": "https://antifilter.download/list/ipsum.lst",
            "path": "/data/rules/antifilter_ips.json",
            "description": "Текстовый список IP/CIDR antifilter.download, конвертируется backend'ом в source rule-set."
        }
    ]
}

PRESET_DOMAINS = {
    "youtube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com", "ggpht.com"],
    "openai": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "auth0.openai.com"],
    "instagram_meta": ["instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "meta.com", "threads.net"],
    "discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"],
    "telegram": ["telegram.org", "t.me", "tdesktop.com"],
    "nintendo": ["nintendo.com", "nintendo.net", "nintendo-europe.com", "nintendowifi.net"],
    "tiktok": ["tiktok.com", "tiktokcdn.com", "byteoversea.com", "ibyteimg.com"],
    "spotify": ["spotify.com", "scdn.co", "spotifycdn.com", "spoti.fi"],
}

DEFAULT_SECURITY = {
    "country_filter_enabled": False,
    "allowed_countries": ["RU"],
    "country_source": "ipdeny",
    "custom_allowed_cidrs": [],
    "custom_denied_cidrs": [],
    "autoban_enabled": True,
    "autoban_max_connections_per_ip": 120,
    "autoban_max_new_connections_per_minute": 240,
    "autoban_window_seconds": 60,
    "autoban_duration_seconds": 3600,
    "autoban_exempt_trusted_clients": True,
    "autoban_exempt_registered_users": True,
    "autoban_exempt_allowlist": True,
    "autoban_exempt_cidrs": [],
    "http_public_warning_ack": False,
    "updated_at": 0,
    "country_lists": {}
}

PRIVATE_SOURCE_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10"
]

COUNTRY_SOURCES = {
    "RU": {
        "name": "Russia IPv4 — IPdeny",
        "url": "https://www.ipdeny.com/ipblocks/data/countries/ru.zone",
        "path": "/data/rules/country_ru.json",
    }
}



DATA_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

lock = threading.RLock()
singbox_process = None
mtg_process = None
mtg_processes = {}
last_error = ""
last_mtg_error = ""


def now_ts():
    return time.time()


def iso_time(ts=None):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts or time.time()))



def event_category(stage, result=""):
    stage = str(stage or "").upper()
    result = str(result or "").upper()
    if "ERROR" in result or "ERROR" in stage or "FATAL" in result:
        return "errors"
    if stage in {"SECURITY", "BLOCK", "TRUSTED", "COUNTRY", "AUTOBAN"} or "AUTOBAN" in stage:
        return "security"
    if stage in {"CLIENT", "CLIENTS", "USER", "USERS", "MTG", "TELEGRAM"}:
        return "clients"
    if stage in {"CONNECTION", "CONNECTIONS", "TRAFFIC"}:
        return "connections"
    if stage in {"ROUTING", "SERVERS", "PING", "VPN", "SING_BOX", "POWER"}:
        return "proxy"
    return "app"

def append_event(stage, result, message, actor="system", action="", target="", extra=None):
    try:
        path = data_path("events.json")
        events = read_json(path, [])
        if not isinstance(events, list):
            events = []
        events.append({
            "ts": time.time(),
            "time": iso_time(),
            "category": event_category(stage, result),
            "stage": str(stage),
            "result": str(result),
            "actor": str(actor or "system"),
            "action": str(action or stage),
            "target": str(target or ""),
            "message": str(message),
            "extra": extra or {},
        })
        events = events[-EVENT_LOG_LIMIT:]
        write_json(path, events)
    except Exception:
        pass


def log(stage, result, message, actor="system", action="", target="", extra=None):
    print(f"[{time.strftime('%H:%M:%S')}] INFO: [STAGE={stage}] [RESULT={result}] {message}", flush=True)
    append_event(stage, result, message, actor=actor, action=action or stage, target=target, extra=extra)


def read_json(path, default):
    try:
        if not Path(path).exists():
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, data):
    # ThreadingHTTPServer can handle several API calls at the same time.
    # A fixed name like traffic.json.tmp is unsafe: two requests may write
    # the same temp file, and one os.replace() can remove it before the
    # second os.replace() runs. Use the global lock and a unique temp file
    # in the same directory so os.replace() remains atomic.
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(6)}.tmp")

    with lock:
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass


def _default_options():
    return {
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

def _safe_port(value, fallback):
    try:
        port = int(value)
        if 1 <= port <= 65535:
            return port
    except Exception:
        pass
    return int(fallback)

def load_addon_options():
    options = read_json(OPTIONS_FILE, {})
    defaults = _default_options()
    merged = {**defaults, **options}
    for key in ["http_proxy_port", "socks_proxy_port", "telegram_proxy_port", "urltest_tolerance"]:
        merged[key] = _safe_port(merged.get(key), defaults[key])
    return merged

def load_runtime_ports():
    raw = read_json(RUNTIME_PORTS_FILE, {})
    addon = load_addon_options()
    ports = {}
    for key in PORT_KEYS:
        ports[key] = _safe_port(raw.get(key, addon.get(key)), addon.get(key))
    return ports

def save_runtime_ports(ports):
    addon = load_addon_options()
    clean = {}
    for key in PORT_KEYS:
        clean[key] = _safe_port(ports.get(key), addon.get(key))
    write_json(RUNTIME_PORTS_FILE, clean)
    return clean

def load_options():
    merged = load_addon_options()
    runtime_ports = load_runtime_ports()
    for key, value in runtime_ports.items():
        merged[key] = value
    return merged

def _port_is_free(port, current_ports=None, host="0.0.0.0"):
    port = int(port)
    if current_ports and port in set(int(x) for x in current_ports):
        return True, "current"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
        return True, "free"
    except OSError as e:
        return False, str(e)

def validate_runtime_ports(candidate, allow_current=True):
    addon = load_addon_options()
    current = load_options() if allow_current else addon
    ports = {key: _safe_port(candidate.get(key), current.get(key, addon.get(key))) for key in PORT_KEYS}
    values = list(ports.values())
    if len(values) != len(set(values)):
        raise ValueError("Порты HTTP, SOCKS5 и Telegram должны быть разными")
    reserved = {BACKEND_PORT, 9090, MTG_UPSTREAM_SOCKS_PORT}
    conflict_reserved = [p for p in values if p in reserved]
    if conflict_reserved:
        raise ValueError("Нельзя использовать служебные порты: " + ", ".join(map(str, conflict_reserved)))
    current_values = [int(current.get(k)) for k in PORT_KEYS] if allow_current else []
    checks = {}
    for key, port in ports.items():
        ok, reason = _port_is_free(port, current_values)
        checks[key] = {"port": port, "ok": ok, "reason": reason}
        if not ok:
            raise ValueError(f"Порт {port} занят или недоступен: {reason}")
    return ports, checks

def ports_summary():
    addon = load_addon_options()
    runtime_raw = read_json(RUNTIME_PORTS_FILE, {})
    active = load_options()
    runtime_exists = RUNTIME_PORTS_FILE.exists()
    return {
        "active": {key: int(active.get(key)) for key in PORT_KEYS},
        "addon_defaults": {key: int(addon.get(key)) for key in PORT_KEYS},
        "runtime": {key: int(load_runtime_ports().get(key)) for key in PORT_KEYS},
        "runtime_file_exists": runtime_exists,
        "runtime_file": str(RUNTIME_PORTS_FILE),
        "source": "runtime_ports.json" if runtime_exists else "addon configuration",
        "raw_runtime": runtime_raw if isinstance(runtime_raw, dict) else {},
        "notes": [
            "Порты меняются внутри приложения и сохраняются в /data/runtime_ports.json.",
            "После изменения внешние пробросы на роутере нужно изменить вручную.",
            "Конфигурация add-on остаётся резервным источником для первого запуска и восстановления."
        ]
    }



def deep_merge(default, actual):
    if not isinstance(actual, dict):
        actual = {}
    result = dict(default)
    for k, v in actual.items():
        if isinstance(result.get(k), dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_security():
    sec = read_json(data_path("security.json"), {})
    sec = deep_merge(DEFAULT_SECURITY, sec if isinstance(sec, dict) else {})
    if not isinstance(sec.get("allowed_countries"), list):
        sec["allowed_countries"] = ["RU"]
    if not isinstance(sec.get("custom_allowed_cidrs"), list):
        sec["custom_allowed_cidrs"] = []
    if not isinstance(sec.get("custom_denied_cidrs"), list):
        sec["custom_denied_cidrs"] = []
    if not isinstance(sec.get("country_lists"), dict):
        sec["country_lists"] = {}
    for key in ["autoban_exempt_trusted_clients", "autoban_exempt_registered_users", "autoban_exempt_allowlist"]:
        sec[key] = bool(sec.get(key, True))
    if not isinstance(sec.get("autoban_exempt_cidrs"), list):
        sec["autoban_exempt_cidrs"] = []
    sec["autoban_exempt_cidrs"] = normalize_cidr_list(sec.get("autoban_exempt_cidrs") or [])
    for key, fallback in [("autoban_max_connections_per_ip", 120), ("autoban_max_new_connections_per_minute", 240), ("autoban_window_seconds", 60), ("autoban_duration_seconds", 3600)]:
        try:
            sec[key] = int(sec.get(key) or fallback)
        except Exception:
            sec[key] = fallback
    # One-time migration from the overly aggressive v1.11.1 defaults.
    # Preserve custom values if the user already changed them to something else.
    if sec.get("autoban_defaults_version") != "1.12.0":
        if sec.get("autoban_max_connections_per_ip") == 40:
            sec["autoban_max_connections_per_ip"] = 120
        if sec.get("autoban_max_new_connections_per_minute") == 80:
            sec["autoban_max_new_connections_per_minute"] = 240
        sec["autoban_exempt_trusted_clients"] = bool(sec.get("autoban_exempt_trusted_clients", True))
        sec["autoban_exempt_registered_users"] = bool(sec.get("autoban_exempt_registered_users", True))
        sec["autoban_exempt_allowlist"] = bool(sec.get("autoban_exempt_allowlist", True))
        sec["autoban_defaults_version"] = "1.12.0"
    return sec


def save_security(sec):
    sec = deep_merge(DEFAULT_SECURITY, sec if isinstance(sec, dict) else {})
    sec["updated_at"] = time.time()
    write_json(data_path("security.json"), sec)
    return sec


def normalize_cidr_list(values):
    result = []
    seen = set()
    for item in values or []:
        if item is None:
            continue
        raw = str(item).strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
            else:
                addr = ipaddress.ip_address(raw)
                net = ipaddress.ip_network(raw + ("/32" if addr.version == 4 else "/128"), strict=False)
            cidr = str(net)
            if cidr not in seen:
                seen.add(cidr)
                result.append(cidr)
        except Exception:
            continue
    return result


def country_rule_file(country):
    cc = str(country or "").upper()
    return data_path(f"rules/country_{cc.lower()}.json")


def load_country_cidrs(country):
    cc = str(country or "").upper()
    data = read_json(country_rule_file(cc), {})
    cidrs = data.get("cidrs") if isinstance(data, dict) else []
    return normalize_cidr_list(cidrs)


def fetch_country_cidrs(country="RU"):
    cc = str(country or "RU").upper()
    src = COUNTRY_SOURCES.get(cc)
    if not src:
        raise ValueError(f"Источник для страны {cc} не настроен")
    text = fetch_text(src["url"], timeout=30)
    cidrs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cidrs.append(line)
    cidrs = normalize_cidr_list(cidrs)
    if not cidrs:
        raise ValueError(f"Список {cc} пустой или не распознан")
    payload = {"country": cc, "source": src["url"], "updated_at": time.time(), "count": len(cidrs), "cidrs": cidrs}
    write_json(country_rule_file(cc), payload)
    sec = load_security()
    sec.setdefault("country_lists", {})[cc] = {"updated_at": payload["updated_at"], "count": len(cidrs), "source": src["url"]}
    save_security(sec)
    log("SECURITY", "COUNTRY_UPDATE", f"Updated country list {cc}: {len(cidrs)} CIDR", actor="backend", action="country_update", target=cc)
    return payload


def country_cidr_details(country="RU", limit=20, full=False):
    cc = str(country or "RU").upper()
    src = COUNTRY_SOURCES.get(cc, {})
    data = read_json(country_rule_file(cc), {})
    cidrs = normalize_cidr_list(data.get("cidrs") if isinstance(data, dict) else [])
    try:
        limit = max(1, min(500, int(limit or 20)))
    except Exception:
        limit = 20
    path = country_rule_file(cc)
    size_bytes = path.stat().st_size if path.exists() else 0
    payload = {
        "country": cc,
        "source": data.get("source") if isinstance(data, dict) else src.get("url"),
        "configured_source": src.get("url"),
        "updated_at": data.get("updated_at") if isinstance(data, dict) else None,
        "count": len(cidrs),
        "size_bytes": size_bytes,
        "path": str(path),
        "first": cidrs[:limit],
        "last": cidrs[-limit:] if cidrs else [],
    }
    if full:
        payload["cidrs"] = cidrs
    return payload


def check_country_ip(ip, country="RU"):
    raw_ip = str(ip or "").strip()
    if not raw_ip:
        raise ValueError("IP не указан")
    try:
        addr = ipaddress.ip_address(raw_ip)
    except Exception:
        raise ValueError("Некорректный IP")
    cidrs = load_country_cidrs(country)
    matched = None
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if addr in net:
                matched = str(net)
                break
        except Exception:
            continue
    return {"ip": raw_ip, "country": str(country or "RU").upper(), "in_list": bool(matched), "matched_cidr": matched, "count": len(cidrs)}


def allowed_source_cidrs_from_security(sec=None):
    sec = sec or load_security()
    allowed = list(PRIVATE_SOURCE_CIDRS)
    for cc in sec.get("allowed_countries") or []:
        allowed.extend(load_country_cidrs(cc))
    allowed.extend(sec.get("custom_allowed_cidrs") or [])
    return normalize_cidr_list(allowed)


def denied_source_cidrs_from_security(sec=None):
    sec = sec or load_security()
    return normalize_cidr_list(sec.get("custom_denied_cidrs") or [])


def security_summary(sec=None, options=None):
    sec = sec or load_security()
    options = options or load_options()
    allowed = allowed_source_cidrs_from_security(sec)
    denied = denied_source_cidrs_from_security(sec)
    warnings = []
    if not bool(options.get("http_auth_enabled")):
        warnings.append("HTTP-прокси без авторизации. Если порт 2081 открыт наружу — это открытый публичный proxy.")
    if sec.get("country_filter_enabled") and not any(load_country_cidrs(cc) for cc in (sec.get("allowed_countries") or [])):
        warnings.append("Фильтр по стране включён, но список CIDR ещё не загружен. Нажми обновление списка RU.")
    return {
        "country_filter_enabled": bool(sec.get("country_filter_enabled")),
        "allowed_countries": sec.get("allowed_countries") or [],
        "allowed_cidrs_count": len(allowed),
        "denied_cidrs_count": len(denied),
        "custom_allowed_cidrs": sec.get("custom_allowed_cidrs") or [],
        "custom_denied_cidrs": sec.get("custom_denied_cidrs") or [],
        "autoban_enabled": bool(sec.get("autoban_enabled")),
        "autoban_max_connections_per_ip": int(sec.get("autoban_max_connections_per_ip") or 0),
        "autoban_max_new_connections_per_minute": int(sec.get("autoban_max_new_connections_per_minute") or 0),
        "autoban_window_seconds": int(sec.get("autoban_window_seconds") or 0),
        "autoban_duration_seconds": int(sec.get("autoban_duration_seconds") or 0),
        "country_lists": sec.get("country_lists") or {},
        "warnings": warnings,
        "http_auth_enabled": bool(options.get("http_auth_enabled")),
        "socks_auth_enabled": bool(options.get("socks_auth_enabled")),
        "ports": {"http": options.get("http_proxy_port"), "socks": options.get("socks_proxy_port"), "telegram": options.get("telegram_proxy_port")},
    }



def ip_in_any_cidr(ip, cidrs):
    try:
        addr = ipaddress.ip_address(str(ip))
    except Exception:
        return False
    for raw in cidrs or []:
        try:
            if addr in ipaddress.ip_network(str(raw), strict=False):
                return True
        except Exception:
            continue
    return False


def autoban_exempt_cidrs(sec=None):
    """CIDRs that must never be autobanned.

    This includes manually trusted clients, optional manual exemptions, and
    optionally the security allow-list.  It is deliberately evaluated before any
    counters are updated so a trusted router/gateway is not accidentally banned
    even if it legitimately has hundreds or thousands of connections behind it.
    """
    sec = sec or load_security()
    cidrs = []
    cidrs.extend(normalize_cidr_list(sec.get("autoban_exempt_cidrs") or []))
    if sec.get("autoban_exempt_trusted_clients", True):
        for ip in (load_trusted() or {}).keys():
            cidrs.append(ip)
    if sec.get("autoban_exempt_allowlist", True):
        cidrs.extend(sec.get("custom_allowed_cidrs") or [])
    return normalize_cidr_list(cidrs)


def is_autoban_exempt_ip(ip, sec=None):
    if not ip or ip == "—":
        return True
    if is_private_ip(ip) or is_loopback_ip(ip):
        return True
    return ip_in_any_cidr(ip, autoban_exempt_cidrs(sec))


def purge_exempt_autobans(sec=None):
    """Remove old autobans that now match trusted/allowed clients.

    If a user has already marked a work PC or a router as trusted, it must not
    remain blocked because of an older automatic ban. Manual bans are not
    removed here.
    """
    sec = sec or load_security()
    exempt = autoban_exempt_cidrs(sec)
    if not exempt:
        return 0
    items = load_blocked(include_expired=True)
    kept = []
    removed = []
    for item in items:
        ip = item.get("ip") or extract_ip_from_cidr(item.get("cidr") or "")
        if item.get("source") == "autoban" and ip and ip_in_any_cidr(ip, exempt):
            removed.append(item)
            continue
        kept.append(item)
    if removed:
        save_blocked(kept)
        log("SECURITY", "AUTOBAN_EXEMPT_CLEAN", f"Removed {len(removed)} autoban(s) for trusted/allowed clients", actor="backend", action="autoban_exempt_clean", extra={"removed": removed})
    return len(removed)

def run_security_autoban(connections):
    """Autoban by two signals:
    1) too many active connections from one public IP;
    2) too many new connection IDs from one public IP within a rolling window.

    This is not a replacement for authentication, but it cuts off noisy scanners and open-proxy abuse.
    Every automatic ban is written to blocked_ips.json, so it appears in the Blocklist tab and can be removed manually.
    """
    sec = load_security()
    if not sec.get("autoban_enabled"):
        return []

    active_threshold = int(sec.get("autoban_max_connections_per_ip") or 40)
    new_threshold = int(sec.get("autoban_max_new_connections_per_minute") or 80)
    window_seconds = max(10, int(sec.get("autoban_window_seconds") or 60))
    duration = int(sec.get("autoban_duration_seconds") or 3600)
    now = time.time()

    active_counts = {}
    events = read_json(data_path("security_autoban_events.json"), {})
    if not isinstance(events, dict):
        events = {}

    # Keep only recent event timestamps and compact old IP keys.
    compacted = {}
    for ip, ids in events.items():
        if not isinstance(ids, dict):
            continue
        recent = {cid: ts for cid, ts in ids.items() if isinstance(ts, (int, float)) and now - float(ts) <= window_seconds}
        if recent:
            compacted[ip] = recent
    events = compacted

    users_by_name = user_by_username_map()
    purge_exempt_autobans(sec)
    exempt_cidrs = autoban_exempt_cidrs(sec)
    exempt_seen = set()
    for conn in connections or []:
        ip = get_source_ip(conn)
        if not ip or ip == "—" or is_private_ip(ip) or is_loopback_ip(ip):
            continue
        # Never autoban trusted/allowed IPs. This is critical for routers/gateways:
        # one trusted router may have hundreds or thousands of legitimate LAN connections behind it.
        if ip_in_any_cidr(ip, exempt_cidrs):
            # Trusted/allowed clients are expected to be noisy, especially routers/gateways.
            # Do not log every skip: polling /connections every few seconds would flood logs.
            exempt_seen.add(ip)
            continue
        # Never autoban a known authenticated user, unless this protection is explicitly disabled.
        username = get_connection_username(conn)
        if sec.get("autoban_exempt_registered_users", True) and username and username in users_by_name:
            continue
        active_counts[ip] = active_counts.get(ip, 0) + 1
        cid = str(get_conn_id(conn) or "")
        if not cid:
            # Fallback fingerprint: enough for rate detection, without being persistent identity.
            meta = conn.get("metadata") or {}
            cid = f"{ip}|{meta.get('host') or meta.get('domain') or meta.get('destinationIP') or ''}|{meta.get('destinationPort') or ''}|{conn.get('start') or ''}"
        events.setdefault(ip, {})[cid] = now

    # Remove event history for exempt IPs so a trusted client is not banned from old counters.
    for ip in list(events.keys()):
        if ip_in_any_cidr(ip, exempt_cidrs):
            events.pop(ip, None)
    write_json(data_path("security_autoban_events.json"), events)

    items = load_blocked()
    existing = {x.get("cidr") for x in items}
    added = []

    def add_ban(ip, reason, count, threshold):
        cidr = normalize_ip_cidr(ip)
        if cidr in existing:
            return
        expires_at = now + duration if duration else None
        entry = {
            "cidr": cidr,
            "ip": extract_ip_from_cidr(cidr),
            "comment": f"Автоблокировка: {reason}; значение={count}; порог={threshold}",
            "created_at": now,
            "duration_seconds": duration,
            "expires_at": expires_at,
            "source": "autoban",
            "reason": reason,
            "count": count,
            "threshold": threshold,
        }
        items.append(entry)
        existing.add(cidr)
        added.append(entry)

    if active_threshold > 0:
        for ip, count in active_counts.items():
            if count >= active_threshold:
                add_ban(ip, "too_many_active_connections", count, active_threshold)

    if new_threshold > 0:
        for ip, ids in events.items():
            count = len(ids)
            if count >= new_threshold:
                add_ban(ip, f"too_many_new_connections_in_{window_seconds}s", count, new_threshold)

    if added:
        save_blocked(items)
        log("SECURITY", "AUTOBAN", f"Autobanned {len(added)} IP(s)", actor="backend", action="autoban", extra={"items": added})
        try:
            restart_singbox()
        except Exception as e:
            log("SECURITY", "WARN", f"Autoban restart failed: {e}")
    return added

def data_path(name):
    return DATA_DIR / name


def load_settings():
    return read_json(data_path("settings.json"), {
        "http_enabled": True,
        "socks_enabled": True,
        "subscription_url": "",
        "traffic_limit_bytes": 0,
        "traffic_used_offset_bytes": 0,
        "proxy_started_at": time.time(),
        "proxy_last_enabled_at": time.time(),
        "proxy_last_disabled_at": None,
        "created_at": time.time(),
        "updated_at": time.time(),
    })


def save_settings(settings):
    settings["updated_at"] = time.time()
    write_json(data_path("settings.json"), settings)


def merge_routing_defaults(value):
    base = json.loads(json.dumps(DEFAULT_ROUTING))
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "sources" and isinstance(v, list):
                by_tag = {s.get("tag"): s for s in base["sources"]}
                for item in v:
                    if not isinstance(item, dict) or not item.get("tag"):
                        continue
                    tag = item["tag"]
                    if tag in by_tag:
                        by_tag[tag].update(item)
                    else:
                        base["sources"].append(item)
            elif k == "presets" and isinstance(v, dict):
                base["presets"].update(v)
            else:
                base[k] = v
    # normalize arrays
    for key in ["manual_include_domains", "manual_include_ips", "manual_exclude_domains", "manual_exclude_ips"]:
        base[key] = normalize_list(base.get(key, []))
    return base


def load_routing():
    return merge_routing_defaults(read_json(data_path("routing.json"), {}))


def save_routing(routing):
    routing = merge_routing_defaults(routing)
    routing["updated_at"] = time.time()
    write_json(data_path("routing.json"), routing)
    return routing


def normalize_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        raw = re.split(r"[\n,;\s]+", value)
    elif isinstance(value, list):
        raw = value
    else:
        raw = [str(value)]
    out = []
    seen = set()
    for item in raw:
        item = str(item).strip().lower()
        item = item.replace("http://", "").replace("https://", "")
        item = item.split("/", 1)[0]
        item = item.strip(" .")
        if not item or item.startswith("#"):
            continue
        if item not in seen:
            out.append(item); seen.add(item)
    return out


def normalize_domains(value):
    result = []
    for item in normalize_list(value):
        if re.match(r"^[a-z0-9а-яё_.-]+$", item, re.I) and "." in item:
            result.append(item.lstrip("."))
    return result


def normalize_cidrs(value):
    result = []
    for item in normalize_list(value):
        try:
            if "/" in item:
                result.append(str(ipaddress.ip_network(item, strict=False)))
            else:
                ip = ipaddress.ip_address(item)
                result.append(str(ipaddress.ip_network(item + ("/32" if ip.version == 4 else "/128"), strict=False)))
        except Exception:
            continue
    return result


def source_to_ruleset_json(tag, kind, values):
    if kind == "ip_cidr":
        rules = [{"ip_cidr": normalize_cidrs(values)}]
    else:
        rules = [{"domain_suffix": normalize_domains(values)}]
    rules = [r for r in rules if list(r.values())[0]]
    return {"version": 3, "rules": rules, "tag": tag, "generated_at": iso_time()}


def write_source_ruleset(path, tag, kind, values):
    p = Path(path)
    data = source_to_ruleset_json(tag, kind, values)
    write_json(p, data)
    return {"path": str(p), "rules": len(data.get("rules", [])), "items": sum(len(list(r.values())[0]) for r in data.get("rules", []))}


def fetch_text_with_fallback(url, timeout=35):
    errors = []
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyOtBorisa/1.14"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore"), "direct"
    except Exception as e:
        errors.append(f"direct: {e}")
    try:
        options = load_options()
        http_port = int(options.get("http_proxy_port", 2081))
        proxy_url = f"http://127.0.0.1:{http_port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore"), "local_proxy"
    except Exception as e:
        errors.append(f"via local proxy: {e}")
    raise RuntimeError(" | ".join(errors))


def update_routing_sources(selected_tags=None):
    routing = load_routing()
    selected = set(selected_tags or [])
    updated = []
    for src in routing.get("sources", []):
        if selected and src.get("tag") not in selected:
            continue
        if not src.get("enabled"):
            continue
        if src.get("format") == "remote_srs":
            src["last_status"] = "remote"
            src["last_update_at"] = time.time()
            updated.append({"tag": src.get("tag"), "status": "remote", "url": src.get("url")})
            continue
        try:
            txt, method = fetch_text_with_fallback(src.get("url", ""))
            lines = []
            for line in txt.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                lines.append(line)
            info = write_source_ruleset(src.get("path") or str(RULES_DIR / (src.get("tag") + ".json")), src.get("tag"), src.get("kind"), lines)
            src.update({
                "last_status": "ok",
                "last_error": "",
                "last_update_at": time.time(),
                "last_items": info.get("items", 0),
                "last_bytes": len(txt.encode("utf-8")),
                "download_method": method,
            })
            updated.append({"tag": src.get("tag"), "status": "ok", **info})
        except Exception as e:
            src["last_status"] = "error"
            src["last_error"] = str(e)
            src["last_update_at"] = time.time()
            updated.append({"tag": src.get("tag"), "status": "error", "error": str(e)})
    routing["last_sources_update_at"] = time.time()
    save_routing(routing)
    log("ROUTING", "UPDATE", f"Routing sources updated: {len(updated)}", actor="ui", action="routing_update", extra={"updated": updated})
    return {"routing": routing, "updated": updated}


def build_manual_routing_rules(routing):
    include_domains = normalize_domains(routing.get("manual_include_domains", []))
    include_ips = normalize_cidrs(routing.get("manual_include_ips", []))
    exclude_domains = normalize_domains(routing.get("manual_exclude_domains", []))
    exclude_ips = normalize_cidrs(routing.get("manual_exclude_ips", []))
    for preset, enabled in (routing.get("presets") or {}).items():
        if enabled:
            include_domains.extend(PRESET_DOMAINS.get(preset, []))
    include_domains = sorted(set(include_domains))
    include_ips = sorted(set(include_ips))
    exclude_domains = sorted(set(exclude_domains))
    exclude_ips = sorted(set(exclude_ips))
    return include_domains, include_ips, exclude_domains, exclude_ips


def routing_summary(routing=None):
    routing = routing or load_routing()
    enabled = [s for s in routing.get("sources", []) if s.get("enabled")]
    ok = [s for s in enabled if s.get("format") == "remote_srs" or s.get("last_status") == "ok" or Path(str(s.get("path", ""))).exists()]
    return {
        "mode": routing.get("mode"),
        "enabled_sources": len(enabled),
        "ready_sources": len(ok),
        "manual_include_domains": len(normalize_domains(routing.get("manual_include_domains", []))),
        "manual_include_ips": len(normalize_cidrs(routing.get("manual_include_ips", []))),
        "manual_exclude_domains": len(normalize_domains(routing.get("manual_exclude_domains", []))),
        "manual_exclude_ips": len(normalize_cidrs(routing.get("manual_exclude_ips", []))),
        "last_sources_update_at": routing.get("last_sources_update_at"),
    }


def make_mtproto_secret(hostname):
    host = (hostname or "www.google.com").strip() or "www.google.com"
    return "ee" + secrets.token_hex(16) + host.encode("utf-8").hex()




def random_token(length=18):
    return secrets.token_urlsafe(length).replace('-', '').replace('_', '')[:length]


def slugify_username(value, fallback='client'):
    value = str(value or '').strip().lower()
    value = re.sub(r'[^a-z0-9_\-]+', '_', value)
    value = value.strip('_-')
    if not value:
        value = fallback
    return value[:32]


def users_path():
    return data_path('proxy_users.json')


def is_user_block_active(user, ts=None):
    ts = ts or time.time()
    until = user.get('blocked_until')
    return bool(until and (until == 'permanent' or float(until) > ts))


def next_telegram_port(users, preferred=None):
    options = load_options()
    base = int(preferred or options.get('telegram_proxy_port', 2083) or 2083)
    used = {int(u.get('telegram_port')) for u in users if u.get('telegram_port')}
    used.update({int(options.get('http_proxy_port', 2081)), int(options.get('socks_proxy_port', 2080)), int(MTG_UPSTREAM_SOCKS_PORT), BACKEND_PORT, 9090})
    port = base
    while port in used:
        port += 1
    return port


def create_default_user():
    options = load_options()
    tg = read_json(data_path('telegram_proxy.json'), {})
    front = tg.get('front_domain') or options.get('telegram_front_domain') or 'www.google.com'
    secret_value = tg.get('secret') or make_mtproto_secret(front)
    return {
        'id': 'default',
        'name': 'Основной клиент',
        'enabled': True,
        'trusted': True,
        'username': str(options.get('proxy_username') or 'user'),
        'password': str(options.get('proxy_password') or 'ChangeThisProxyPassword'),
        'socks_enabled': True,
        'http_enabled': True,
        'telegram_enabled': bool(options.get('telegram_proxy_enabled', False)),
        'telegram_port': int(tg.get('port') or options.get('telegram_proxy_port', 2083) or 2083),
        'telegram_secret': secret_value,
        'telegram_front_domain': front,
        'public_host': tg.get('public_host') or '',
        'notes': 'Создан автоматически из настроек add-on',
        'created_at': time.time(),
        'updated_at': time.time(),
        'blocked_until': None,
        'blocked_comment': '',
    }


def normalize_user(user, existing_users=None):
    existing_users = existing_users or []
    now = time.time()
    user = dict(user or {})
    user.setdefault('id', secrets.token_hex(6))
    user['id'] = safe_tag(user.get('id'), 'client')
    user['name'] = str(user.get('name') or user.get('username') or 'Клиент').strip()
    user['username'] = slugify_username(user.get('username') or user.get('name') or user['id'], 'client')
    user.setdefault('password', random_token(20))
    user['enabled'] = bool(user.get('enabled', True))
    user['trusted'] = bool(user.get('trusted', True))
    user['socks_enabled'] = bool(user.get('socks_enabled', True))
    user['http_enabled'] = bool(user.get('http_enabled', True))
    user['telegram_enabled'] = bool(user.get('telegram_enabled', True))
    user['telegram_front_domain'] = str(user.get('telegram_front_domain') or load_options().get('telegram_front_domain') or 'www.google.com').strip()
    if not user.get('telegram_secret'):
        user['telegram_secret'] = make_mtproto_secret(user['telegram_front_domain'])
    try:
        user['telegram_port'] = int(user.get('telegram_port') or next_telegram_port(existing_users))
    except Exception:
        user['telegram_port'] = next_telegram_port(existing_users)
    user.setdefault('public_host', '')
    user.setdefault('notes', '')
    user.setdefault('created_at', now)
    user['updated_at'] = now
    user.setdefault('blocked_until', None)
    user.setdefault('blocked_comment', '')
    return user


def load_proxy_users():
    users = read_json(users_path(), None)
    if not isinstance(users, list) or not users:
        users = [create_default_user()]
        write_json(users_path(), users)
        log('USERS', 'INIT', 'Created default proxy user from add-on configuration', action='users_init')
    normalized = []
    seen_ids = set()
    changed = False
    for u in users:
        if not isinstance(u, dict):
            changed = True
            continue
        nu = normalize_user(u, normalized)
        base_id = nu['id']
        if base_id in seen_ids:
            nu['id'] = base_id + '-' + secrets.token_hex(2)
            changed = True
        seen_ids.add(nu['id'])
        normalized.append(nu)
    if changed:
        write_json(users_path(), normalized)
    return normalized


def save_proxy_users(users):
    normalized = []
    seen_usernames = set()
    seen_ports = set()
    for u in users:
        nu = normalize_user(u, normalized)
        base_username = nu['username']
        n = 2
        while nu['username'] in seen_usernames:
            nu['username'] = f'{base_username}_{n}'
            n += 1
        seen_usernames.add(nu['username'])
        while int(nu['telegram_port']) in seen_ports:
            nu['telegram_port'] = int(nu['telegram_port']) + 1
        seen_ports.add(int(nu['telegram_port']))
        normalized.append(nu)
    write_json(users_path(), normalized)
    return normalized


def find_proxy_user(user_id):
    for u in load_proxy_users():
        if str(u.get('id')) == str(user_id) or str(u.get('username')) == str(user_id):
            return u
    return None


def active_proxy_users_for(protocol):
    now = time.time()
    result = []
    for u in load_proxy_users():
        if not u.get('enabled', True):
            continue
        if protocol == 'socks' and not u.get('socks_enabled', True):
            continue
        if protocol == 'http' and not u.get('http_enabled', True):
            continue
        # Заблокированные пользователи остаются в auth-списке, чтобы правило auth_user могло отправить их в block.
        result.append(u)
    return result


def user_public_urls(user, public_host=None):
    host = (public_host or user.get('public_host') or '').strip()
    port = int(user.get('telegram_port') or 0)
    secret_value = user.get('telegram_secret') or ''
    if not host or not port or not secret_value:
        return {'tg_url': '', 'tme_url': ''}
    q = urllib.parse.urlencode({'server': host, 'port': str(port), 'secret': secret_value})
    return {'tg_url': 'tg://proxy?' + q, 'tme_url': 'https://t.me/proxy?' + q}


def users_safe(public_host=None):
    result = []
    for u in load_proxy_users():
        item = dict(u)
        item['blocked_active'] = is_user_block_active(item)
        item['urls'] = user_public_urls(item, public_host=public_host)
        result.append(item)
    return result


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




# --- Multi-user MTProto backend overrides ---
def mtg_config_for_user(user):
    return TMP_DIR / f"mtg_{safe_tag(user.get('id'), 'client')}.toml"


def write_mtg_config_for_user(user):
    secret_value = user.get('telegram_secret') or make_mtproto_secret(user.get('telegram_front_domain'))
    port = int(user.get('telegram_port'))
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
    path = mtg_config_for_user(user)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def stop_mtg_user(user_id):
    global mtg_processes
    proc = mtg_processes.get(str(user_id))
    if proc and proc.poll() is None:
        log('MTG', 'STOP', f'Stopping MTProto user={user_id}', action='mtg_stop', target=str(user_id))
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    mtg_processes.pop(str(user_id), None)


def start_mtg_user(user):
    global mtg_processes, last_mtg_error
    uid = str(user.get('id'))
    if not user.get('enabled', True) or not user.get('telegram_enabled', True) or is_user_block_active(user):
        stop_mtg_user(uid)
        return False
    if not os.path.exists(MTG_BIN):
        last_mtg_error = 'mtg binary not found'
        log('MTG', 'ERROR', last_mtg_error)
        return False
    stop_mtg_user(uid)
    cfg = write_mtg_config_for_user(user)
    log('MTG', 'START', f"Starting MTProto for {user.get('name')} on 0.0.0.0:{user.get('telegram_port')} via SOCKS5 127.0.0.1:{MTG_UPSTREAM_SOCKS_PORT}", action='mtg_start', target=uid)
    proc = subprocess.Popen([MTG_BIN, 'run', str(cfg)], stdout=sys.stdout, stderr=sys.stderr)
    mtg_processes[uid] = proc
    time.sleep(0.35)
    if proc.poll() is not None:
        last_mtg_error = f"mtg user={uid} exited with code {proc.returncode}"
        log('MTG', 'ERROR', last_mtg_error, target=uid)
        mtg_processes.pop(uid, None)
        return False
    last_mtg_error = ''
    return True


def stop_mtg():
    for uid in list(mtg_processes.keys()):
        stop_mtg_user(uid)


def start_mtg():
    users = load_proxy_users()
    desired = {str(u.get('id')) for u in users if u.get('enabled', True) and u.get('telegram_enabled', True) and not is_user_block_active(u)}
    for uid in list(mtg_processes.keys()):
        if uid not in desired:
            stop_mtg_user(uid)
    ok = False
    for user in users:
        if str(user.get('id')) in desired:
            ok = start_mtg_user(user) or ok
    return ok


def restart_mtg():
    with lock:
        stop_mtg()
        return start_mtg()


def mtg_status():
    users = users_safe()
    running = []
    for u in users:
        proc = mtg_processes.get(str(u.get('id')))
        u['telegram_running'] = bool(proc and proc.poll() is None)
        if u['telegram_running']:
            running.append(u.get('id'))
    primary = users[0] if users else {}
    return {
        'enabled': any(u.get('telegram_enabled') and u.get('enabled') for u in users),
        'running': bool(running),
        'running_count': len(running),
        'port': primary.get('telegram_port') or load_options().get('telegram_proxy_port', 2083),
        'front_domain': primary.get('telegram_front_domain') or 'www.google.com',
        'public_host': primary.get('public_host') or '',
        'secret': primary.get('telegram_secret') or '',
        'last_error': last_mtg_error,
        'upstream': f'socks5://127.0.0.1:{MTG_UPSTREAM_SOCKS_PORT}',
        'users': users,
        **user_public_urls(primary),
        'urls': user_public_urls(primary),
    }


# --- Single-port multi-secret MTProto backend overrides (v1.8.1) ---
MTG_MULTI_API_PORT = 2093


def telegram_shared_port():
    return int(load_options().get('telegram_proxy_port', 2083) or 2083)


def create_default_user():
    options = load_options()
    tg = read_json(data_path('telegram_proxy.json'), {})
    front = tg.get('front_domain') or options.get('telegram_front_domain') or 'www.google.com'
    secret_value = tg.get('secret') or make_mtproto_secret(front)
    return {
        'id': 'default',
        'name': 'Основной клиент',
        'enabled': True,
        'trusted': True,
        'username': str(options.get('proxy_username') or 'user'),
        'password': str(options.get('proxy_password') or 'ChangeThisProxyPassword'),
        'socks_enabled': True,
        'http_enabled': True,
        'telegram_enabled': bool(options.get('telegram_proxy_enabled', False)),
        'telegram_port': telegram_shared_port(),
        'telegram_secret': secret_value,
        'telegram_front_domain': front,
        'public_host': tg.get('public_host') or '',
        'notes': 'Создан автоматически из настроек add-on. Telegram использует общий порт для всех пользователей.',
        'created_at': time.time(),
        'updated_at': time.time(),
        'blocked_until': None,
        'blocked_comment': '',
    }


def normalize_user(user, existing_users=None):
    existing_users = existing_users or []
    now = time.time()
    user = dict(user or {})
    user.setdefault('id', secrets.token_hex(6))
    user['id'] = safe_tag(user.get('id'), 'client')
    user['name'] = str(user.get('name') or user.get('username') or 'Клиент').strip()
    user['username'] = slugify_username(user.get('username') or user.get('name') or user['id'], 'client')
    user.setdefault('password', random_token(20))
    user['enabled'] = bool(user.get('enabled', True))
    user['trusted'] = bool(user.get('trusted', True))
    user['socks_enabled'] = bool(user.get('socks_enabled', True))
    user['http_enabled'] = bool(user.get('http_enabled', True))
    user['telegram_enabled'] = bool(user.get('telegram_enabled', True))
    user['telegram_front_domain'] = str(user.get('telegram_front_domain') or load_options().get('telegram_front_domain') or 'www.google.com').strip()
    if not user.get('telegram_secret'):
        user['telegram_secret'] = make_mtproto_secret(user['telegram_front_domain'])
    # Важно: с mtg-multi все Telegram-пользователи работают через один внешний порт.
    user['telegram_port'] = telegram_shared_port()
    user.setdefault('public_host', '')
    user.setdefault('notes', '')
    user.setdefault('created_at', now)
    user['updated_at'] = now
    user.setdefault('blocked_until', None)
    user.setdefault('blocked_comment', '')
    return user


def save_proxy_users(users):
    normalized = []
    seen_usernames = set()
    for u in users:
        nu = normalize_user(u, normalized)
        base_username = nu['username']
        n = 2
        while nu['username'] in seen_usernames:
            nu['username'] = f'{base_username}_{n}'
            n += 1
        seen_usernames.add(nu['username'])
        nu['telegram_port'] = telegram_shared_port()
        normalized.append(nu)
    write_json(users_path(), normalized)
    return normalized


def user_public_urls(user, public_host=None):
    host = (public_host or user.get('public_host') or load_telegram_settings().get('public_host') or '').strip()
    port = telegram_shared_port()
    secret_value = user.get('telegram_secret') or ''
    if not host or not port or not secret_value:
        return {'tg_url': '', 'tme_url': ''}
    q = urllib.parse.urlencode({'server': host, 'port': str(port), 'secret': secret_value})
    return {'tg_url': 'tg://proxy?' + q, 'tme_url': 'https://t.me/proxy?' + q}


def write_mtg_config():
    tg = load_telegram_settings()
    port = telegram_shared_port()
    upstream = f"socks5://127.0.0.1:{MTG_UPSTREAM_SOCKS_PORT}"
    users = [u for u in load_proxy_users() if u.get('enabled', True) and u.get('telegram_enabled', True) and not is_user_block_active(u)]
    if not users:
        raise RuntimeError('No enabled Telegram users')
    lines = [
        f"bind-to = {toml_quote('0.0.0.0:' + str(port))}",
        f"api-bind-to = {toml_quote('127.0.0.1:' + str(MTG_MULTI_API_PORT))}",
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
        '[throttle]',
        'max-connections = 5000',
        'check-interval = "5s"',
        '',
        '# [secrets] must be the last section in the global TOML scope.',
        '[secrets]',
    ]
    for user in users:
        name = slugify_username(user.get('username'), user.get('id') or 'client')
        secret_value = user.get('telegram_secret') or make_mtproto_secret(user.get('telegram_front_domain'))
        lines.append(f"{name} = {toml_quote(secret_value)}")
    MTG_CONFIG.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return MTG_CONFIG


def stop_mtg():
    global mtg_process, mtg_processes
    for uid in list(mtg_processes.keys()):
        stop_mtg_user(uid)
    mtg_processes = {}
    if mtg_process and mtg_process.poll() is None:
        log('MTG', 'STOP', 'Stopping shared MTProto multi-secret proxy', action='mtg_stop', target='shared')
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
    if not tg.get('enabled', False):
        stop_mtg()
        last_mtg_error = ''
        return False
    users = [u for u in load_proxy_users() if u.get('enabled', True) and u.get('telegram_enabled', True) and not is_user_block_active(u)]
    if not users:
        stop_mtg()
        last_mtg_error = 'No enabled Telegram users'
        log('MTG', 'SKIP', last_mtg_error, action='mtg_skip')
        return False
    if not os.path.exists(MTG_BIN):
        last_mtg_error = 'mtg-multi binary not found'
        log('MTG', 'ERROR', last_mtg_error, action='mtg_error')
        return False
    try:
        cfg = write_mtg_config()
    except Exception as e:
        last_mtg_error = str(e)
        log('MTG', 'ERROR', last_mtg_error, action='mtg_config')
        return False
    stop_mtg()
    port = telegram_shared_port()
    log('MTG', 'START', f'Starting shared MTProto multi-secret proxy on 0.0.0.0:{port} for {len(users)} users via SOCKS5 127.0.0.1:{MTG_UPSTREAM_SOCKS_PORT}', action='mtg_start', target='shared')
    mtg_process = subprocess.Popen([MTG_BIN, 'run', str(cfg)], stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(0.8)
    if mtg_process.poll() is not None:
        last_mtg_error = f'mtg-multi exited with code {mtg_process.returncode}'
        log('MTG', 'ERROR', last_mtg_error, action='mtg_error', target='shared')
        mtg_process = None
        return False
    last_mtg_error = ''
    return True


def restart_mtg():
    with lock:
        stop_mtg()
        return start_mtg()


def mtg_multi_stats():
    try:
        return json.loads(fetch_text(f'http://127.0.0.1:{MTG_MULTI_API_PORT}/stats', timeout=2))
    except Exception as e:
        return {'error': str(e), 'users': {}}


def mtg_status():
    users = users_safe()
    running = bool(mtg_process and mtg_process.poll() is None)
    stats = mtg_multi_stats() if running else {'users': {}}
    stats_users = stats.get('users') if isinstance(stats, dict) else {}
    for u in users:
        u['telegram_port'] = telegram_shared_port()
        u['telegram_running'] = running and u.get('enabled', True) and u.get('telegram_enabled', True) and not is_user_block_active(u)
        su = stats_users.get(u.get('username')) if isinstance(stats_users, dict) else None
        if isinstance(su, dict):
            u['telegram_stats'] = su
    primary = users[0] if users else {}
    return {
        'enabled': bool(load_telegram_settings().get('enabled', False)),
        'running': running,
        'running_count': 1 if running else 0,
        'port': telegram_shared_port(),
        'front_domain': load_telegram_settings().get('front_domain') or 'www.google.com',
        'public_host': load_telegram_settings().get('public_host') or primary.get('public_host') or '',
        'secret': primary.get('telegram_secret') or '',
        'last_error': last_mtg_error,
        'upstream': f'socks5://127.0.0.1:{MTG_UPSTREAM_SOCKS_PORT}',
        'stats': stats,
        'users': users,
        **user_public_urls(primary),
        'urls': user_public_urls(primary),
    }


def get_mtg_client_connections():
    """Return real MTProto client peers.

    Important: registered Telegram users/secrets are NOT clients by themselves.
    A client is shown only when there is a real TCP peer connected to the shared
    MTProto port. Older builds created synthetic clients like telegram:<user> from
    mtg-multi stats; that made newly created users appear online without traffic.
    """
    real_peers = list_tcp_peers_for_local_port(telegram_shared_port())
    if not real_peers:
        return []

    status = mtg_status()
    stats = status.get('stats') or {}
    stats_users = stats.get('users') if isinstance(stats, dict) else {}
    users_by_name = user_by_username_map()

    active_stats = []
    if isinstance(stats_users, dict):
        for username, su in stats_users.items():
            if not isinstance(su, dict):
                continue
            user = users_by_name.get(username)
            if not user:
                continue
            connections = int(su.get('connections') or 0)
            bytes_in = int(su.get('bytes_in') or 0)
            bytes_out = int(su.get('bytes_out') or 0)
            last_seen = su.get('last_seen') or ''
            # Treat stats as useful only as identity metadata. Do not create a
            # client from stats alone. Some mtg-multi builds expose configured
            # secrets in stats even before a real network peer is active.
            if connections > 0 or bytes_in > 0 or bytes_out > 0 or last_seen:
                active_stats.append({
                    'user': user,
                    'username': username,
                    'connections': connections,
                    'bytes_in': bytes_in,
                    'bytes_out': bytes_out,
                    'last_seen': last_seen,
                })

    mapped_user = None
    mapped_stat = None
    # Safe automatic mapping: only one active user in mtg stats. If multiple
    # users are active on one shared port, do not guess; show real IP as
    # Telegram MTProto unknown user. Later this can be improved with mtg logs.
    if len(active_stats) == 1:
        mapped_stat = active_stats[0]
        mapped_user = mapped_stat.get('user')

    result = []
    for peer in real_peers:
        if mapped_user:
            peer['user_id'] = mapped_user.get('id')
            peer['username'] = mapped_user.get('username')
            peer['user_name'] = mapped_user.get('name')
            peer['connections'] = max(1, int(mapped_stat.get('connections') or 1))
            peer['bytes_in'] = int(mapped_stat.get('bytes_in') or 0)
            peer['bytes_out'] = int(mapped_stat.get('bytes_out') or 0)
            peer['last_seen'] = mapped_stat.get('last_seen') or ''
            peer['unmapped'] = False
        else:
            peer['user_id'] = ''
            peer['username'] = ''
            peer['user_name'] = ''
            peer['connections'] = 1
            peer['bytes_in'] = 0
            peer['bytes_out'] = 0
            peer['last_seen'] = ''
            peer['unmapped'] = True
        peer['telegram_port'] = telegram_shared_port()
        result.append(peer)
    return result

def infer_server_priority(server):
    tag = str(server.get("tag") or "").upper()
    # Российские/локальные узлы держим как резерв: они часто дают лучший ping,
    # но для обхода блокировок не должны выигрывать auto-выбор.
    if tag.startswith("RU") or tag.endswith("-RU") or " RUSSIA" in tag:
        return 200
    return 50


def normalize_server_priority(server):
    item = dict(server)
    try:
        pr = int(item.get("priority"))
    except Exception:
        pr = infer_server_priority(item)
    item["priority"] = max(1, min(999, pr))
    return item


def sort_servers_for_display(servers):
    return sorted([normalize_server_priority(s) for s in servers if isinstance(s, dict)], key=lambda x: (int(x.get("priority", 50)), str(x.get("tag") or "")))


def auto_server_tags(servers):
    normalized = sort_servers_for_display(servers)
    primary = [s.get("tag") for s in normalized if s.get("tag") and int(s.get("priority", 50)) < 100]
    if primary:
        return primary
    return [s.get("tag") for s in normalized if s.get("tag")]


def server_to_singbox_outbound(server):
    """Return a clean sing-box outbound object.

    The UI/backend may store management-only fields such as priority.
    sing-box rejects unknown outbound fields, so these keys must never be
    written into /tmp/boris-proxy/sing-box.json.
    """
    item = dict(server)
    for key in [
        "priority",
        "last_ping",
        "last_ping_at",
        "note",
        "enabled",
    ]:
        item.pop(key, None)
    return item


def load_server_pings():
    data = read_json(data_path("server_pings.json"), {})
    return data if isinstance(data, dict) else {}


def save_server_pings(data):
    write_json(data_path("server_pings.json"), data if isinstance(data, dict) else {})


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
        write_json(path, sort_servers_for_display(servers))
    servers = read_json(path, [])
    normalized = sort_servers_for_display(servers)
    if normalized != servers:
        write_json(path, normalized)
    return normalized


def save_servers(servers):
    servers = sort_servers_for_display(servers)
    backup_path = data_path(f"servers.backup.{int(time.time())}.json")
    current = read_json(data_path("servers.json"), None)
    if current is not None:
        write_json(backup_path, current)
    write_json(data_path("servers.json"), servers)


def load_blocked(include_expired=False):
    items = read_json(data_path("blocked_ips.json"), [])
    if not isinstance(items, list):
        items = []
    now = time.time()
    changed = False
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        exp = item.get("expires_at")
        expired = bool(exp and float(exp) <= now)
        item["expired"] = expired
        if expired and not include_expired:
            changed = True
            continue
        normalized.append(item)
    if changed:
        save_blocked(normalized)
    return normalized


def save_blocked(items):
    write_json(data_path("blocked_ips.json"), items)


def block_duration_to_seconds(value):
    if value in [None, "", "permanent", "perm", "forever", 0, "0"]:
        return None
    try:
        return int(value)
    except Exception:
        return None


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
        "started_at": time.time(),
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
        item = normalize_server_priority(item)
        result.append(item)
    return {"servers": result, "errors": errors}


def fetch_text(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyOtBorisa/1.14"})
    errors = []

    # 1) Пробуем напрямую. Это работает, если подписка доступна с Raspberry/HAOS.
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        errors.append(f"direct: {e}")

    # 2) Если прямой доступ к подписке заблокирован, пробуем скачать через наш HTTP proxy.
    # Это сработает после того, как серверы уже один раз добавлены вручную и sing-box запущен.
    try:
        options = load_options()
        http_port = int(options.get("http_proxy_port", 2081))
        proxy_url = f"http://127.0.0.1:{http_port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        errors.append(f"via local http proxy: {e}")

    raise RuntimeError("Не удалось загрузить подписку: " + " | ".join(errors))


def selector_outbounds(servers):
    tags = [s.get("tag") for s in sort_servers_for_display(servers) if s.get("tag")]
    if tags:
        return ["auto"] + tags
    return ["direct"]


def make_singbox_config():
    options = load_options()
    settings = load_settings()
    routing = load_routing()
    servers = load_servers()
    blocked = load_blocked()
    server_tags = [s.get("tag") for s in servers if s.get("tag")]
    auto_tags = auto_server_tags(servers)
    http_port = int(options["http_proxy_port"])
    socks_port = int(options["socks_proxy_port"])
    socks_tag = f"IN-SOCKS5-{socks_port}"
    http_tag = f"IN-HTTP-{http_port}"
    mtg_upstream_tag = f"IN-MTG-UPSTREAM-{MTG_UPSTREAM_SOCKS_PORT}"
    users = load_proxy_users()
    socks_auth = []
    http_auth = []
    if options.get("socks_auth_enabled"):
        socks_auth = [
            {"username": u.get("username", ""), "password": u.get("password", "")}
            for u in users
            if u.get("enabled", True) and u.get("socks_enabled", True)
        ]
    if options.get("http_auth_enabled"):
        http_auth = [
            {"username": u.get("username", ""), "password": u.get("password", "")}
            for u in users
            if u.get("enabled", True) and u.get("http_enabled", True)
        ]
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
    if auto_tags:
        outbounds.append({"type": "urltest", "tag": "auto", "outbounds": auto_tags, "url": "https://www.gstatic.com/generate_204", "interval": options.get("urltest_interval", "2m"), "tolerance": int(options.get("urltest_tolerance", 50))})
    outbounds.extend([server_to_singbox_outbound(s) for s in servers])
    outbounds.extend([{"type": "block", "tag": "block"}, {"type": "direct", "tag": "direct"}])

    route_rule_sets = []
    rules = []
    blocked_auth_users = [u.get("username") for u in users if u.get("username") and is_user_block_active(u)]
    if blocked_auth_users:
        rules.append({"auth_user": blocked_auth_users, "outbound": "block"})
    blocked_cidrs = [item.get("cidr") for item in blocked if item.get("cidr")]
    if blocked_cidrs:
        rules.append({"source_ip_cidr": blocked_cidrs, "outbound": "block"})

    security = load_security()
    denied_source_cidrs = denied_source_cidrs_from_security(security)
    if denied_source_cidrs:
        rules.append({"source_ip_cidr": denied_source_cidrs, "outbound": "block"})
    if security.get("country_filter_enabled"):
        allowed_source_cidrs = allowed_source_cidrs_from_security(security)
        if allowed_source_cidrs:
            # Разрешаем только частные сети + выбранные страны/ручные CIDR.
            # Всё остальное блокируется до обычной маршрутизации.
            rules.append({"source_ip_cidr": allowed_source_cidrs, "invert": True, "outbound": "block"})

    # Power switches: if a port is disabled, block it before any routing logic.
    if not settings.get("socks_enabled", True):
        rules.append({"inbound": [socks_tag], "outbound": "block"})
    if not settings.get("http_enabled", True):
        rules.append({"inbound": [http_tag], "outbound": "block"})

    # Telegram MTProto must always use VPN path; otherwise Raspberry would reach Telegram directly from RU.
    rules.append({"inbound": [mtg_upstream_tag], "outbound": "Proxy"})

    include_domains, include_ips, exclude_domains, exclude_ips = build_manual_routing_rules(routing)
    if exclude_domains:
        rules.append({"domain_suffix": exclude_domains, "outbound": "direct"})
    if exclude_ips:
        rules.append({"ip_cidr": exclude_ips, "outbound": "direct"})
    if include_domains:
        rules.append({"domain_suffix": include_domains, "outbound": "Proxy"})
    if include_ips:
        rules.append({"ip_cidr": include_ips, "outbound": "Proxy"})

    enabled_rule_tags = []
    if routing.get("mode") in ["blocked_plus_manual", "blocked_only"]:
        for src in routing.get("sources", []):
            if not src.get("enabled"):
                continue
            tag = src.get("tag")
            if src.get("format") == "remote_srs":
                route_rule_sets.append({"type": "remote", "tag": tag, "format": "binary", "url": src.get("url"), "download_detour": "Proxy" if server_tags else "direct"})
                enabled_rule_tags.append(tag)
            else:
                p = Path(str(src.get("path") or ""))
                if p.exists():
                    route_rule_sets.append({"type": "local", "tag": tag, "format": "source", "path": str(p)})
                    enabled_rule_tags.append(tag)
    if enabled_rule_tags:
        rules.append({"rule_set": enabled_rule_tags, "outbound": "Proxy"})

    mode = routing.get("mode", "all_proxy")
    if mode == "all_direct":
        final_out = "direct"
    elif mode in ["blocked_plus_manual", "blocked_only", "manual_only"]:
        final_out = "direct"
    else:
        final_out = "Proxy"

    route = {"rules": rules, "final": final_out, "auto_detect_interface": True}
    if route_rule_sets:
        route["rule_set"] = route_rule_sets
    return {
        "log": {"level": options.get("log_level", "info"), "timestamp": True},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090", "secret": options.get("secret", "")}, "cache_file": {"enabled": True, "path": "/data/sing-box-cache.db"}},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
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
    global singbox_process, last_error, SINGBOX_STARTED_AT
    write_config()
    log("SING_BOX", "START", f"Starting sing-box with {SINGBOX_CONFIG}")
    singbox_process = subprocess.Popen([SINGBOX_BIN, "run", "-c", str(SINGBOX_CONFIG)], stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(0.8)
    if singbox_process.poll() is not None:
        last_error = f"sing-box exited with code {singbox_process.returncode}"
        log("SING_BOX", "ERROR", last_error)
        raise RuntimeError(last_error)
    last_error = ""
    SINGBOX_STARTED_AT = time.time()
    apply_power_selectors()
    start_mtg()




def validate_singbox_config():
    """Generate and validate config without replacing the running process."""
    cfg = write_config()
    try:
        proc = subprocess.run([SINGBOX_BIN, "check", "-c", str(SINGBOX_CONFIG)], capture_output=True, text=True, timeout=20)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "sing-box check failed").strip()
            raise RuntimeError(err[-2000:])
        return {"ok": True, "config": str(SINGBOX_CONFIG)}
    except FileNotFoundError:
        # Should never happen inside the add-on, but keep the API error explicit.
        raise RuntimeError("sing-box binary not found")
    except subprocess.TimeoutExpired:
        raise RuntimeError("sing-box check timeout")

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

def get_monitored_connections(force=False, run_autoban=True):
    """Return connections with a small cache.

    The UI can ask several endpoints at once (/status, /clients, /connections).
    Without a cache every call hits sing-box, updates traffic and runs security checks.
    This function makes normal polling cheap, while manual refresh can still force reload.
    """
    global connections_cache
    now = time.time()
    with lock:
        age = now - float(connections_cache.get("updated_at") or 0)
        if not force and age < MONITOR_INTERVAL_SECONDS:
            return list(connections_cache.get("items") or [])

    conns = get_connections_raw()
    try:
        update_traffic(conns)
    except Exception as e:
        log("TRAFFIC", "ERROR", f"Failed to update traffic: {e}")

    with lock:
        connections_cache["items"] = conns
        connections_cache["updated_at"] = now
        last_autoban_at = float(connections_cache.get("last_autoban_at") or 0)

    if run_autoban and now - last_autoban_at >= AUTOBAN_CHECK_INTERVAL_SECONDS:
        try:
            run_security_autoban(conns)
        except Exception as e:
            log("SECURITY", "ERROR", f"Autoban check failed: {e}", action="autoban_check")
        with lock:
            connections_cache["last_autoban_at"] = now

    return conns


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


def is_loopback_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except Exception:
        return False


def tcp_state_name(code):
    return {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }.get(str(code).upper(), str(code))


def decode_proc_ipv4(hex_ip):
    raw = bytes.fromhex(hex_ip)
    return str(ipaddress.IPv4Address(raw[::-1]))


def decode_proc_ipv6(hex_ip):
    raw = bytes.fromhex(hex_ip)
    # /proc/net/tcp6 stores IPv6 as 4 little-endian 32-bit words.
    fixed = b"".join(raw[i:i+4][::-1] for i in range(0, 16, 4))
    ip = ipaddress.IPv6Address(fixed)
    if ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return str(ip)


def list_tcp_peers_for_local_port(port):
    """Return remote peers connected to a local TCP port.

    Used to identify real Telegram MTProto clients. sing-box sees MTProto
    traffic only as 127.0.0.1 because mtg forwards it to the internal SOCKS5
    upstream. The actual phone/client IP is visible on mtg's listening port.
    """
    result = []
    targets = [("/proc/net/tcp", decode_proc_ipv4), ("/proc/net/tcp6", decode_proc_ipv6)]
    wanted_port = int(port)

    for path, decoder in targets:
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
        except Exception:
            continue

        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            local, remote, state = parts[1], parts[2], parts[3].upper()
            try:
                local_ip_hex, local_port_hex = local.split(":")
                remote_ip_hex, remote_port_hex = remote.split(":")
                local_port = int(local_port_hex, 16)
                if local_port != wanted_port:
                    continue
                if state == "0A":
                    continue
                remote_ip = decoder(remote_ip_hex)
                remote_port = int(remote_port_hex, 16)
                if remote_ip in ["0.0.0.0", "::"] or is_loopback_ip(remote_ip):
                    continue
                result.append({
                    "ip": remote_ip,
                    "port": remote_port,
                    "state": tcp_state_name(state),
                    "state_code": state,
                    "local_port": wanted_port,
                    "source": "telegram_mtproto",
                })
            except Exception:
                continue

    return result


def get_mtg_client_connections():
    """Return real TCP clients connected to MTProto port(s).

    With multi-secret MTProto one external port can serve several users. The OS
    TCP table only shows remote IP:port, not which MTProto secret was used.
    Therefore we must NOT create one client per registered user on the same
    port: that caused fake/offline clients after creating users.

    If exactly one active Telegram user exists for a port, we can attribute the
    peer to that user. If several users share the port, the peer is shown by IP
    only with a Telegram MTProto service label.
    """
    users_by_port = {}
    for user in load_proxy_users():
        if not user.get('enabled', True) or not user.get('telegram_enabled', True) or is_user_block_active(user):
            continue
        try:
            port = int(user.get('telegram_port') or 0)
        except Exception:
            continue
        if port <= 0:
            continue
        users_by_port.setdefault(port, []).append(user)

    peers = []
    seen = set()
    for port, users in users_by_port.items():
        single_user = users[0] if len(users) == 1 else None
        for peer in list_tcp_peers_for_local_port(port):
            identity = (peer.get('ip'), peer.get('port'), port, peer.get('state'))
            if identity in seen:
                continue
            seen.add(identity)
            if single_user:
                peer['user_id'] = single_user.get('id')
                peer['username'] = single_user.get('username')
                peer['user_name'] = single_user.get('name')
            else:
                peer['user_id'] = ''
                peer['username'] = ''
                peer['user_name'] = ''
                peer['ambiguous_user'] = True
                peer['possible_users'] = [u.get('username') for u in users if u.get('username')]
            peer['telegram_port'] = port
            peers.append(peer)
    return peers

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


def extract_connection_identity(conn):
    meta = conn.get("metadata") or {}
    identities = []
    for key in ["auth_user", "user", "username", "authUser", "inbound_user", "client", "client_id"]:
        val = meta.get(key) or conn.get(key)
        if val:
            identities.append(f"{key}:{val}")
    inbound = conn.get("inbound") or meta.get("inbound") or meta.get("inboundTag")
    if inbound:
        identities.append(f"inbound:{inbound}")
    return sorted(set(identities))


def get_connection_username(conn):
    meta = conn.get('metadata') or {}
    for key in ['auth_user', 'authUser', 'user', 'username', 'socks_username', 'inbound_user']:
        val = meta.get(key) or conn.get(key)
        if val:
            return str(val)
    return ''


def user_by_username_map():
    return {str(u.get('username')): u for u in load_proxy_users() if u.get('username')}


def client_key_for(ip, username='', user_id=''):
    if user_id:
        return 'user:' + str(user_id)
    if username:
        return 'auth:' + str(username)
    return 'ip:' + str(ip)


def ensure_client_group(grouped, history, trusted, ip, now, source_label=None, user=None, username=''):
    user_id = user.get('id') if user else ''
    key = client_key_for(ip, username=username or (user.get('username') if user else ''), user_id=user_id)
    old = history.get(key, {})
    was_offline_long = old.get('last_seen') and (now - old.get('last_seen', 0) > SESSION_BREAK_SECONDS)
    first_time = not old.get('first_seen')
    if key not in grouped:
        trusted_by_ip = trusted.get(ip) or {}
        grouped[key] = {
            'key': key,
            'ip': ip,
            'username': username or (user.get('username') if user else ''),
            'registered_user_id': user_id or '',
            'registered_name': user.get('name') if user else '',
            'status': 'online',
            'connections': [],
            'upload': 0,
            'download': 0,
            'hosts': set(),
            'services': set(old.get('services') or []),
            'mtproto_connections': 0,
            'tcp_states': {},
            'first_seen': old.get('first_seen') or now,
            'session_started': now if first_time or was_offline_long else old.get('session_started', now),
            'last_seen': now,
            'seen_count': 1 if first_time else (int(old.get('seen_count', 1)) + 1 if was_offline_long else int(old.get('seen_count', 1))),
            'trusted': bool(user) or bool(trusted_by_ip),
            'trusted_name': (user.get('name') if user else trusted_by_ip.get('name', '')),
            'trusted_at': (user.get('created_at') if user else trusted_by_ip.get('trusted_at')),
            'is_public': not is_private_ip(ip),
            'user_blocked': bool(user and is_user_block_active(user)),
            'user_enabled': bool(user.get('enabled', True)) if user else None,
        }
    if source_label:
        grouped[key]['services'].add(source_label)
    return grouped[key]


def simplify_host(host):
    host = str(host or '').strip().lower().strip('.')
    if not host or host == '—':
        return '—'
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        pass
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    two_part_suffixes = {'co.uk', 'com.br', 'com.tr', 'com.au', 'co.jp', 'co.kr'}
    suffix2 = '.'.join(parts[-2:])
    if suffix2 in two_part_suffixes and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def build_clients(connections):
    now = time.time()
    history = load_clients()
    trusted = load_trusted()
    users_by_name = user_by_username_map()
    users_by_id = {str(u.get('id')): u for u in load_proxy_users()}
    grouped = {}

    for conn in connections:
        ip = get_source_ip(conn)
        if not ip or ip == '—' or is_loopback_ip(ip):
            continue
        username = get_connection_username(conn)
        user = users_by_name.get(username) if username else None
        item = ensure_client_group(grouped, history, trusted, ip, now, 'HTTP/SOCKS', user=user, username=username)
        item['connections'].append(conn)
        item['upload'] += int(conn.get('upload') or 0)
        item['download'] += int(conn.get('download') or 0)
        item.setdefault('identities', set()).update(extract_connection_identity(conn))
        if username:
            item.setdefault('identities', set()).add('auth_user:' + username)
        host = get_host(conn)
        port = (conn.get('metadata') or {}).get('destinationPort') or (conn.get('metadata') or {}).get('destination_port') or ''
        if host and host != '—':
            item['hosts'].add(f'{host}:{port}' if port else host)
            item.setdefault('main_hosts', {})[simplify_host(host)] = item.setdefault('main_hosts', {}).get(simplify_host(host), 0) + 1

    for peer in get_mtg_client_connections():
        ip = peer.get('ip')
        if not ip or ip == '—' or is_loopback_ip(ip):
            continue
        user = users_by_id.get(str(peer.get('user_id')))
        item = ensure_client_group(grouped, history, trusted, ip, now, 'Telegram MTProto', user=user, username=user.get('username') if user else '')
        item['mtproto_connections'] = int(item.get('mtproto_connections') or 0) + int(peer.get('connections') or 1)
        item['upload'] += int(peer.get('bytes_in') or 0)
        item['download'] += int(peer.get('bytes_out') or 0)
        item['hosts'].add('Telegram MTProto proxy')
        item.setdefault('main_hosts', {})['telegram'] = item.setdefault('main_hosts', {}).get('telegram', 0) + 1
        item.setdefault('identities', set()).add('service:Telegram MTProto')
        if user:
            item.setdefault('identities', set()).add('telegram_user:' + user.get('name', ''))
            item.setdefault('identities', set()).add('auth_user:' + user.get('username', ''))
        state = peer.get('state') or 'UNKNOWN'
        item['tcp_states'][state] = item['tcp_states'].get(state, 0) + 1

    active_keys = set(grouped.keys())
    for key, item in grouped.items():
        old = history.get(key, {})
        became_online = not old.get('last_seen') or (now - old.get('last_seen', 0) > SESSION_BREAK_SECONDS)
        history[key] = {
            'key': key,
            'ip': item['ip'],
            'username': item.get('username') or '',
            'registered_user_id': item.get('registered_user_id') or '',
            'registered_name': item.get('registered_name') or '',
            'first_seen': item['first_seen'],
            'session_started': item['session_started'],
            'last_seen': item['last_seen'],
            'seen_count': item['seen_count'],
            'services': sorted(item.get('services') or []),
            'last_identities': sorted(item.get('identities') or []),
        }
        if became_online:
            log('CLIENT', 'ONLINE', f"Client online: {item.get('registered_name') or item.get('username') or item['ip']}", actor='backend', action='client_online', target=key, extra={'ip': item['ip'], 'services': sorted(item.get('services') or [])})

    for key, old in list(history.items()):
        if key in active_keys:
            continue
        ip = old.get('ip') or (key.split(':', 1)[-1] if key.startswith('ip:') else '—')
        # Remove stale synthetic Telegram clients created by older builds.
        # Registered users must not appear in Clients until real network activity exists.
        # Unknown LAN/private IPs are usually browser/HA internal/local noise. Show them only while online;
        # do not keep them as offline clients after user creation/restart.
        has_registered_identity = bool(old.get('registered_user_id') or old.get('username'))
        has_manual_trust = bool(trusted.get(ip))
        if str(ip).startswith('telegram:') or is_loopback_ip(str(ip)):
            history.pop(key, None)
            continue
        if is_private_ip(ip) and not has_registered_identity and not has_manual_trust:
            history.pop(key, None)
            continue
        if old.get('last_seen') and now - old['last_seen'] > OFFLINE_CLIENT_KEEP_SECONDS:
            continue
        status = 'recent' if old.get('last_seen') and now - old['last_seen'] <= RECENT_CLIENT_SECONDS else 'offline'
        user = users_by_id.get(str(old.get('registered_user_id') or '')) or users_by_name.get(str(old.get('username') or ''))
        grouped[key] = {
            'key': key,
            'ip': ip,
            'username': old.get('username') or (user.get('username') if user else ''),
            'registered_user_id': old.get('registered_user_id') or (user.get('id') if user else ''),
            'registered_name': old.get('registered_name') or (user.get('name') if user else ''),
            'status': status,
            'connections': [],
            'upload': 0,
            'download': 0,
            'hosts': set(),
            'main_hosts': {},
            'services': set(old.get('services') or []),
            'identities': set(old.get('last_identities') or []),
            'mtproto_connections': 0,
            'tcp_states': {},
            'first_seen': old.get('first_seen'),
            'session_started': old.get('session_started'),
            'last_seen': old.get('last_seen'),
            'seen_count': old.get('seen_count', 1),
            'trusted': bool(user) or ip in trusted,
            'trusted_name': (user.get('name') if user else (trusted.get(ip) or {}).get('name', '')),
            'trusted_at': (user.get('created_at') if user else (trusted.get(ip) or {}).get('trusted_at')),
            'is_public': not is_private_ip(ip),
            'user_blocked': bool(user and is_user_block_active(user)),
            'user_enabled': bool(user.get('enabled', True)) if user else None,
        }

    save_clients(history)

    result = []
    for key, item in grouped.items():
        item = dict(item)
        main_hosts = item.get('main_hosts') or {}
        item['hosts'] = list(item['hosts'])[:20]
        item['main_hosts'] = sorted([{'host': k, 'count': v} for k, v in main_hosts.items() if k and k != '—'], key=lambda x: -x['count'])[:12]
        item['services'] = sorted(item.get('services') or [])
        item['identities'] = sorted(item.get('identities') or [])
        item['geo'] = geo_lookup(item.get('ip') or '—')
        item['connections_count'] = len(item.get('connections') or []) + int(item.get('mtproto_connections') or 0)
        item['risk'] = risk_level(item)
        item['registered'] = bool(item.get('registered_user_id')) or bool(item.get('trusted'))
        item.pop('connections', None)
        result.append(item)

    status_order = {'online': 0, 'recent': 1, 'offline': 2}
    return sorted(result, key=lambda x: (status_order.get(x.get('status'), 9), 0 if not x.get('trusted') else 1, -(x.get('last_seen') or 0)))


def risk_level(client):
    if client.get('user_blocked'):
        return 'high'
    if client.get('trusted') or client.get('registered_user_id'):
        return 'trusted'
    if client.get('is_public'):
        return 'high'
    if int(client.get('connections_count', 0)) >= 20:
        return 'medium'
    if int(client.get('upload', 0)) + int(client.get('download', 0)) > 100 * 1024 * 1024:
        return 'medium'
    return 'medium' if client.get('status') == 'online' else 'low'

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


def normalize_request_path(raw_path):
    """Return the path as the backend should handle it.

    Home Assistant Ingress normally strips /api/hassio_ingress/<token>
    before proxying the request to the add-on, but in practice different
    entry points and browser navigation can still leave the prefix in the
    path.  All handlers use this normalizer so /api/... works both directly
    and through an ingress-prefixed URL.
    """
    parsed = urllib.parse.urlparse(raw_path)
    path = parsed.path or "/"

    marker = "/api/hassio_ingress/"
    if marker in path:
        before, after = path.split(marker, 1)
        parts = after.split("/", 1)
        if len(parts) == 1:
            path = "/"
        else:
            suffix = parts[1]
            path = "/" + suffix.lstrip("/")
            if path == "//":
                path = "/"

    # Be tolerant if HA forwards /ingress/<token>/...
    marker2 = "/ingress/"
    if marker2 in path:
        before, after = path.split(marker2, 1)
        parts = after.split("/", 1)
        if len(parts) == 1:
            path = "/"
        else:
            path = "/" + parts[1].lstrip("/")

    if not path.startswith("/"):
        path = "/" + path
    return path



def power_summary(settings=None, tg_status=None):
    settings = settings or load_settings()
    tg_status = tg_status or mtg_status()
    http_on = bool(settings.get("http_enabled", True))
    socks_on = bool(settings.get("socks_enabled", True))
    telegram_on = bool((tg_status.get("telegram") or {}).get("enabled") if isinstance(tg_status, dict) and "telegram" in tg_status else tg_status.get("enabled", False)) if isinstance(tg_status, dict) else False
    flags = [http_on, socks_on, telegram_on]
    if all(flags):
        state = "all_on"
        label = "Все прокси включены"
    elif not any(flags):
        state = "all_off"
        label = "Все прокси выключены"
    else:
        state = "partial"
        label = "Включены не все прокси"
    # Runtime uptime: do not use stale /data value after add-on or sing-box restart.
    # This shows how long the currently running proxy core has really been alive.
    started_at = SINGBOX_STARTED_AT if any(flags) and SINGBOX_STARTED_AT else None
    uptime = int(time.time() - started_at) if started_at else 0
    return {"state": state, "label": label, "http_enabled": http_on, "socks_enabled": socks_on, "telegram_enabled": telegram_on, "proxy_started_at": started_at, "uptime_seconds": uptime, "last_disabled_at": settings.get("proxy_last_disabled_at")}


def update_proxy_lifecycle(settings, telegram_enabled=None):
    prev_any = bool(settings.get("http_enabled", True) or settings.get("socks_enabled", True) or settings.get("_last_telegram_enabled", False))
    if telegram_enabled is None:
        try:
            telegram_enabled = bool(load_telegram_settings().get("enabled", False))
        except Exception:
            telegram_enabled = False
    new_any = bool(settings.get("http_enabled", True) or settings.get("socks_enabled", True) or telegram_enabled)
    settings["_last_telegram_enabled"] = bool(telegram_enabled)
    if new_any and not prev_any:
        settings["proxy_started_at"] = time.time()
        settings["proxy_last_enabled_at"] = settings["proxy_started_at"]
        log("POWER", "ON", "Proxy stack enabled", action="power_on")
    elif not new_any and prev_any:
        settings["proxy_last_disabled_at"] = time.time()
        log("POWER", "OFF", "Proxy stack disabled", action="power_off")
    elif new_any and not settings.get("proxy_started_at"):
        settings["proxy_started_at"] = time.time()
    return settings


def vpn_status(proxies=None):
    proxies = proxies if proxies is not None else get_proxies()
    current = current_server_info(proxies or {})
    server = current.get("server")
    ok = bool(server and server != "—" and (server in (proxies or {}) or server == "direct"))
    delay = current.get("delay")
    if server == "direct" or not load_servers():
        ok = False
    return {"connected": ok, "server": server, "mode": current.get("mode"), "delay": delay, "checked_at": time.time(), "message": "VPN-сервер выбран" if ok else "VPN-сервер не выбран или список серверов пуст"}


def get_events(limit=200, category="all"):
    events = read_json(data_path("events.json"), [])
    if not isinstance(events, list):
        return []
    try:
        limit = max(1, min(int(limit), EVENT_LOG_LIMIT))
    except Exception:
        limit = 200
    if category and category != "all":
        events = [e for e in events if str(e.get("category") or event_category(e.get("stage"), e.get("result"))) == category]
    return events[-limit:][::-1]

class Handler(BaseHTTPRequestHandler):
    server_version = "ProxyOtBorisa/1.14.0"

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
            # For Home Assistant Ingress and simple browser refreshes, serve
            # the SPA index instead of returning a static-file 404.
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
        elif p.suffix == ".png":
            ctype = "image/png"
        elif p.suffix in [".jpg", ".jpeg"]:
            ctype = "image/jpeg"
        elif p.suffix == ".svg":
            ctype = "image/svg+xml"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        try:
            path = normalize_request_path(self.path)
            if not path.startswith("/api"):
                return self.serve_file(path)
            if path == "/api/status":
                options = load_options(); settings = load_settings(); servers = load_servers(); blocked = load_blocked(); proxies = get_proxies(); conns = get_monitored_connections(force=False, run_autoban=True); sec_summary = security_summary(options=options); ru = ((sec_summary.get("country_lists") or {}).get("RU") or {})
                return self.send_json({"app": APP_NAME, "version": APP_VERSION, "singbox_running": bool(singbox_process and singbox_process.poll() is None), "last_error": last_error, "telegram": mtg_status(), "settings": settings, "power": power_summary(settings, mtg_status()), "vpn": vpn_status(proxies), "options": {"http_proxy_port": options["http_proxy_port"], "socks_proxy_port": options["socks_proxy_port"], "telegram_proxy_port": options.get("telegram_proxy_port"), "socks_auth_enabled": options["socks_auth_enabled"], "http_auth_enabled": options["http_auth_enabled"], "proxy_username": options.get("proxy_username")}, "security": sec_summary, "security_status": {"autoban_enabled": bool(load_security().get("autoban_enabled")), "country_filter_enabled": bool(load_security().get("country_filter_enabled")), "ru_cidrs": int(ru.get("count") or 0), "http_auth_enabled": bool(options["http_auth_enabled"]), "socks_auth_enabled": bool(options["socks_auth_enabled"])}, "monitor": {"interval_seconds": MONITOR_INTERVAL_SECONDS, "autoban_interval_seconds": AUTOBAN_CHECK_INTERVAL_SECONDS, "connections_updated_at": connections_cache.get("updated_at", 0), "last_autoban_at": connections_cache.get("last_autoban_at", 0)}, "servers_count": len(servers), "blocked_count": len(blocked), "connections_count": len(conns), "current": current_server_info(proxies), "routing": routing_summary(), "proxies": proxies})
            if path == "/api/proxies":
                return self.send_json(get_proxies())
            if path == "/api/connections":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                conns = get_monitored_connections(force=(qs.get("force", ["0"])[0] == "1"), run_autoban=True); return self.send_json({"connections": conns, "updated_at": connections_cache.get("updated_at", 0)})
            if path == "/api/clients":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                conns = get_monitored_connections(force=(qs.get("force", ["0"])[0] == "1"), run_autoban=True); return self.send_json({"clients": build_clients(conns), "updated_at": connections_cache.get("updated_at", 0)})
            if path == "/api/servers":
                settings = load_settings(); servers = load_servers(); return self.send_json({"servers": servers, "subscription_url": settings.get("subscription_url", ""), "pings": load_server_pings(), "auto_tags": auto_server_tags(servers)})
            if path == "/api/routing":
                return self.send_json({"routing": load_routing(), "summary": routing_summary()})
            if path == "/api/telegram":
                host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
                return self.send_json({"telegram": mtg_status(), "detected_host": host.split(":")[0] if host else ""})
            if path == "/api/users":
                host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
                return self.send_json({"users": users_safe(public_host=host.split(":")[0] if host else "")})
            if path == "/api/blocklist":
                return self.send_json({"blocked": load_blocked()})
            if path == "/api/trusted":
                return self.send_json({"trusted": load_trusted()})
            if path == "/api/security":
                return self.send_json({"security": load_security(), "summary": security_summary(), "ru": country_cidr_details("RU", limit=20, full=False)})
            if path.startswith("/api/security/country/"):
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                country = urllib.parse.unquote(normalize_request_path(parsed.path).split("/api/security/country/", 1)[1] or "RU")
                limit = (qs.get("limit") or [20])[-1]
                full = (qs.get("full") or ["0"])[-1] in ["1", "true", "yes"]
                return self.send_json(country_cidr_details(country, limit=limit, full=full))
            if path == "/api/security/check_ip":
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                ip = (qs.get("ip") or [""])[-1]
                country = (qs.get("country") or ["RU"])[-1]
                return self.send_json(check_country_ip(ip, country))
            if path == "/api/servers/priority":
                tag = str(body.get("tag") or "")
                priority = int(body.get("priority") or 50)
                servers = load_servers()
                changed = False
                for srv in servers:
                    if srv.get("tag") == tag:
                        srv["priority"] = max(1, min(999, priority))
                        changed = True
                        break
                if not changed:
                    raise ValueError("Сервер не найден")
                save_servers(servers)
                log("SERVERS", "PRIORITY", f"Priority updated for {tag}: {priority}", actor="ui", action="server_priority", target=tag, extra={"priority": priority})
                restart_singbox()
                return self.send_json({"ok": True, "servers": load_servers(), "auto_tags": auto_server_tags(load_servers())})
            if path == "/api/servers/reorder":
                order = body.get("order") or []
                if not isinstance(order, list):
                    raise ValueError("order должен быть списком tag")
                servers = load_servers()
                by_tag = {s.get("tag"): s for s in servers}
                new_servers = []
                for i, tag in enumerate(order):
                    srv = by_tag.pop(str(tag), None)
                    if srv:
                        srv["priority"] = 10 + i * 10
                        new_servers.append(srv)
                new_servers.extend(by_tag.values())
                save_servers(new_servers)
                log("SERVERS", "REORDER", "Server priorities reordered", actor="ui", action="server_reorder", extra={"count": len(new_servers)})
                restart_singbox()
                return self.send_json({"ok": True, "servers": load_servers(), "auto_tags": auto_server_tags(load_servers())})
            if path == "/api/ports":
                return self.send_json(ports_summary())
            if path == "/api/traffic":
                return self.send_json(load_traffic())
            if path == "/api/logs":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                limit = (qs.get("limit") or [200])[-1]
                category = (qs.get("category") or ["all"])[-1]
                return self.send_json({"events": get_events(limit, category), "category": category, "limit": limit, "max_retention": EVENT_LOG_LIMIT})
            if path.startswith("/api/geo/"):
                ip = urllib.parse.unquote(path.split("/api/geo/", 1)[1]); return self.send_json(geo_lookup(ip))
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            traceback.print_exc()
            self.send_json({"error": str(e)}, 500)

    def do_POST(self):
        try:
            path = normalize_request_path(self.path)
            body = self.read_body()
            if path == "/api/power":
                settings = load_settings()
                if "http_enabled" in body:
                    settings["http_enabled"] = bool(body["http_enabled"])
                if "socks_enabled" in body:
                    settings["socks_enabled"] = bool(body["socks_enabled"])
                telegram_enabled = None
                if "telegram_enabled" in body:
                    telegram_enabled = bool(body["telegram_enabled"])
                    users = load_proxy_users()
                    for u in users:
                        u["telegram_enabled"] = telegram_enabled
                    save_proxy_users(users)
                    tg = load_telegram_settings()
                    tg["enabled"] = telegram_enabled
                    save_telegram_settings(tg)
                    restart_mtg()
                settings = update_proxy_lifecycle(settings, telegram_enabled)
                save_settings(settings)
                apply_power_selectors()
                if not settings.get("http_enabled", True) or not settings.get("socks_enabled", True) or telegram_enabled is False:
                    close_all_connections()
                log("POWER", "CHANGE", "Power settings changed", actor="ui", action="power_change", extra={"http_enabled": settings.get("http_enabled"), "socks_enabled": settings.get("socks_enabled"), "telegram_enabled": telegram_enabled})
                return self.send_json({"ok": True, "settings": settings, "power": power_summary(settings, mtg_status()), "telegram": mtg_status()})
            if path == "/api/ports":
                candidate = {
                    "http_proxy_port": body.get("http_proxy_port"),
                    "socks_proxy_port": body.get("socks_proxy_port"),
                    "telegram_proxy_port": body.get("telegram_proxy_port"),
                }
                old_ports = load_options()
                ports, checks = validate_runtime_ports(candidate, allow_current=True)
                changed = any(int(old_ports.get(k)) != int(ports.get(k)) for k in PORT_KEYS)
                save_runtime_ports(ports)
                applied = False
                if bool(body.get("apply", True)) and changed:
                    validate_singbox_config()
                    restart_singbox()
                    restart_mtg()
                    applied = True
                log("PORTS", "SAVE", "Runtime ports saved", actor="ui", action="ports_save", extra={"ports": ports, "applied": applied, "changed": changed})
                return self.send_json({"ok": True, "changed": changed, "applied": applied, "checks": checks, "ports": ports_summary(), "message": "Порты сохранены" + (" и применены." if applied else ".")})
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
                settings = load_settings(); settings = update_proxy_lifecycle(settings, tg.get("enabled", False)); save_settings(settings)
                if action in ["restart", "regenerate_secret", "enable", "disable", "update"] or "enabled" in body:
                    restart_mtg()
                log("TELEGRAM", "CHANGE", f"Telegram proxy action={action}", actor="ui", action="telegram_" + str(action), extra={"enabled": tg.get("enabled"), "port": tg.get("port")})
                return self.send_json({"ok": True, "telegram": mtg_status(), "power": power_summary(settings, mtg_status())})
            if path == "/api/users":
                users = load_proxy_users()
                action = body.get('action') or 'create'
                if action == 'create':
                    candidate = {
                        'id': secrets.token_hex(5),
                        'name': body.get('name') or 'Новый клиент',
                        'username': body.get('username') or body.get('name') or 'client',
                        'password': body.get('password') or random_token(20),
                        'enabled': body.get('enabled', True),
                        'trusted': True,
                        'socks_enabled': body.get('socks_enabled', True),
                        'http_enabled': body.get('http_enabled', True),
                        'telegram_enabled': body.get('telegram_enabled', True),
                        'telegram_port': body.get('telegram_port') or next_telegram_port(users),
                        'telegram_secret': body.get('telegram_secret') or '',
                        'telegram_front_domain': body.get('telegram_front_domain') or load_options().get('telegram_front_domain') or 'www.google.com',
                        'public_host': body.get('public_host') or '',
                        'notes': body.get('notes') or '',
                        'created_at': time.time(),
                        'blocked_until': None,
                        'blocked_comment': '',
                    }
                    users.append(candidate)
                    users = save_proxy_users(users)
                    log('USERS', 'CREATE', 'Created proxy client', actor='ui', action='user_create', target=candidate.get('username'))
                    restart_singbox()
                    return self.send_json({'ok': True, 'users': users_safe()})
                if action == 'update':
                    uid = str(body.get('id') or body.get('username') or '')
                    changed = False
                    for u in users:
                        if str(u.get('id')) == uid or str(u.get('username')) == uid:
                            for key in ['name','username','password','enabled','trusted','socks_enabled','http_enabled','telegram_enabled','telegram_port','telegram_secret','telegram_front_domain','public_host','notes']:
                                if key in body:
                                    if key == 'telegram_port':
                                        u[key] = int(body[key])
                                    elif key in ['enabled','trusted','socks_enabled','http_enabled','telegram_enabled']:
                                        u[key] = bool(body[key])
                                    else:
                                        u[key] = body[key]
                            u['updated_at'] = time.time()
                            changed = True
                            break
                    if not changed:
                        raise ValueError('Клиент не найден')
                    users = save_proxy_users(users)
                    log('USERS', 'UPDATE', 'Updated proxy client', actor='ui', action='user_update', target=uid)
                    restart_singbox()
                    return self.send_json({'ok': True, 'users': users_safe()})
                if action == 'regenerate_password':
                    uid = str(body.get('id') or '')
                    for u in users:
                        if str(u.get('id')) == uid:
                            u['password'] = random_token(20)
                            u['updated_at'] = time.time()
                            break
                    users = save_proxy_users(users)
                    log('USERS', 'PASSWORD', 'Regenerated proxy client password', actor='ui', action='user_password', target=uid)
                    restart_singbox()
                    return self.send_json({'ok': True, 'users': users_safe()})
                if action == 'regenerate_secret':
                    uid = str(body.get('id') or '')
                    for u in users:
                        if str(u.get('id')) == uid:
                            u['telegram_secret'] = make_mtproto_secret(u.get('telegram_front_domain') or 'www.google.com')
                            u['updated_at'] = time.time()
                            break
                    users = save_proxy_users(users)
                    log('USERS', 'SECRET', 'Regenerated proxy client Telegram secret', actor='ui', action='user_secret', target=uid)
                    restart_singbox()
                    return self.send_json({'ok': True, 'users': users_safe()})
                if action in ['block','unblock']:
                    uid = str(body.get('id') or '')
                    duration = block_duration_to_seconds(body.get('duration_seconds'))
                    for u in users:
                        if str(u.get('id')) == uid:
                            if action == 'block':
                                u['blocked_until'] = time.time() + duration if duration else 'permanent'
                                u['blocked_comment'] = body.get('comment') or 'Blocked from users panel'
                            else:
                                u['blocked_until'] = None
                                u['blocked_comment'] = ''
                            u['updated_at'] = time.time()
                            break
                    users = save_proxy_users(users)
                    log('USERS', action.upper(), f'User {action}', actor='ui', action='user_'+action, target=uid)
                    restart_singbox(); close_all_connections()
                    return self.send_json({'ok': True, 'users': users_safe()})
                raise ValueError('Неизвестное действие users')
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
                pings = load_server_pings()
                checked_at = time.time()
                for name in names:
                    try:
                        results[name] = clash_request("GET", f"/proxies/{urllib.parse.quote(name)}/delay?timeout=5000&url={urllib.parse.quote('https://www.gstatic.com/generate_204')}", timeout=8)
                    except Exception as e:
                        results[name] = {"error": str(e)}
                    pings[name] = {"checked_at": checked_at, **(results[name] if isinstance(results[name], dict) else {})}
                save_server_pings(pings)
                log("PING", "OK", f"Ping test completed for {len(names)} server(s)", actor="ui", action="ping", extra={"count": len(names)})
                return self.send_json({"ok": True, "results": results, "checked_at": checked_at})
            if path == "/api/connections/close_all":
                return self.send_json({"ok": close_all_connections()})
            if path == "/api/clients/disconnect":
                ip = body.get("ip")
                conns = get_connections_raw(); closed = 0
                for c in conns:
                    if get_source_ip(c) == ip and close_connection(get_conn_id(c)):
                        closed += 1
                return self.send_json({"ok": True, "closed": closed})
            if path == "/api/clients/delete":
                ip = str(body.get("ip") or "")
                key = str(body.get("key") or "")
                conns = get_connections_raw(); closed = 0
                for c in conns:
                    if ip and get_source_ip(c) == ip and close_connection(get_conn_id(c)):
                        closed += 1
                # MTProto clients are external TCP sessions to mtg; sing-box cannot close them by client IP.
                # Restart mtg to drop current Telegram sessions if this IP had MTProto activity.
                mtg_restarted = False
                try:
                    if ip and any((p.get('ip') == ip) for p in get_mtg_client_connections()):
                        restart_mtg(); mtg_restarted = True
                except Exception:
                    pass
                history = load_clients()
                removed_keys = []
                for hk, hv in list(history.items()):
                    if (key and hk == key) or (ip and hv.get('ip') == ip) or (ip and hk == 'ip:' + ip):
                        removed_keys.append(hk)
                        history.pop(hk, None)
                save_clients(history)
                if ip:
                    trusted = load_trusted(); trusted.pop(ip, None); save_trusted(trusted)
                log("CLIENT", "DELETE", f"Deleted client from list: {ip or key}", actor="ui", action="client_delete", target=key or ip, extra={"closed": closed, "removed_keys": removed_keys, "mtg_restarted": mtg_restarted})
                return self.send_json({"ok": True, "closed": closed, "removed_keys": removed_keys, "mtg_restarted": mtg_restarted})
            if path == "/api/blocklist":
                ip = body.get("ip") or body.get("cidr")
                comment = body.get("comment") or ""
                duration = block_duration_to_seconds(body.get("duration_seconds"))
                expires_at = time.time() + duration if duration else None
                cidr = normalize_ip_cidr(ip)
                items = load_blocked()
                if not any(x.get("cidr") == cidr for x in items):
                    items.append({"cidr": cidr, "ip": extract_ip_from_cidr(cidr), "comment": comment, "created_at": time.time(), "duration_seconds": duration, "expires_at": expires_at, "source": "manual"})
                    save_blocked(items)
                    log("BLOCK", "ADD", f"Blocked {cidr}", actor="ui", action="block_add", target=cidr, extra={"duration_seconds": duration, "expires_at": expires_at})
                    restart_singbox()
                return self.send_json({"ok": True, "blocked": items})
            if path == "/api/clients/block":
                ip = body.get("ip"); comment = body.get("comment") or "Blocked from clients panel"
                duration = block_duration_to_seconds(body.get("duration_seconds"))
                expires_at = time.time() + duration if duration else None
                cidr = normalize_ip_cidr(ip)
                items = load_blocked()
                if not any(x.get("cidr") == cidr for x in items):
                    items.append({"cidr": cidr, "ip": extract_ip_from_cidr(cidr), "comment": comment, "created_at": time.time(), "duration_seconds": duration, "expires_at": expires_at, "source": "manual"})
                    save_blocked(items)
                    log("BLOCK", "ADD", f"Blocked client {cidr}", actor="ui", action="client_block", target=cidr, extra={"duration_seconds": duration, "expires_at": expires_at})
                restart_singbox(); close_all_connections()
                return self.send_json({"ok": True, "blocked": items})
            if path == "/api/trusted":
                ip = body.get("ip"); name = body.get("name") or "Моё устройство"
                trusted = load_trusted(); trusted[ip] = {"name": name, "trusted_at": time.time()}; save_trusted(trusted)
                removed_autobans = purge_exempt_autobans(load_security())
                if removed_autobans:
                    try:
                        restart_singbox()
                    except Exception:
                        pass
                log("TRUSTED", "ADD", f"Trusted client {ip} as {name}", actor="ui", action="trusted_add", target=ip, extra={"removed_autobans": removed_autobans})
                return self.send_json({"ok": True, "trusted": trusted, "removed_autobans": removed_autobans})
            if path == "/api/security":
                sec = load_security()
                for key in ["country_filter_enabled", "allowed_countries", "custom_allowed_cidrs", "custom_denied_cidrs", "autoban_enabled", "autoban_max_connections_per_ip", "autoban_max_new_connections_per_minute", "autoban_window_seconds", "autoban_duration_seconds", "autoban_exempt_trusted_clients", "autoban_exempt_registered_users", "autoban_exempt_allowlist", "autoban_exempt_cidrs", "http_public_warning_ack"]:
                    if key in body:
                        sec[key] = body[key]
                sec["custom_allowed_cidrs"] = normalize_cidr_list(sec.get("custom_allowed_cidrs") or [])
                sec["custom_denied_cidrs"] = normalize_cidr_list(sec.get("custom_denied_cidrs") or [])
                sec["autoban_exempt_cidrs"] = normalize_cidr_list(sec.get("autoban_exempt_cidrs") or [])
                save_security(sec)
                removed_autobans = purge_exempt_autobans(sec)
                log("SECURITY", "SAVE", "Security settings saved", actor="ui", action="security_save", extra={"country_filter_enabled": sec.get("country_filter_enabled"), "autoban_enabled": sec.get("autoban_enabled")})
                # Saving security settings must be fast and must not restart sing-box.
                # Use /api/security/apply explicitly when the user wants rules applied.
                return self.send_json({"ok": True, "security": load_security(), "summary": security_summary(), "removed_autobans": removed_autobans, "needs_apply": True, "message": "Настройки безопасности сохранены. Нажми «Применить правила», чтобы обновить sing-box."})
            if path == "/api/security/apply":
                validate_singbox_config()
                restart_singbox()
                log("SECURITY", "APPLY", "Security rules applied", actor="ui", action="security_apply")
                return self.send_json({"ok": True, "summary": security_summary(), "message": "Правила безопасности проверены и применены."})
            if path == "/api/security/update_country":
                country = str(body.get("country") or "RU").upper()
                payload = fetch_country_cidrs(country)
                # Do not restart sing-box here. Updating the country database is a data refresh,
                # not a rule change by itself. Restarting here made the UI look like the whole
                # add-on rebooted and hid the operation result. Security settings save/apply will
                # restart sing-box when the filter is enabled or changed.
                details = country_cidr_details(country, limit=20, full=False)
                return self.send_json({"ok": True, "country": country, "count": payload.get("count"), "updated_at": payload.get("updated_at"), "summary": security_summary(), "details": details, "message": "RU IP-список обновлён. Нажми «Применить правила», если геофильтр включён."})
            if path == "/api/routing":
                routing = load_routing()
                for key in ["mode", "auto_update_enabled", "auto_update_interval_hours", "manual_include_domains", "manual_include_ips", "manual_exclude_domains", "manual_exclude_ips", "presets", "sources"]:
                    if key in body:
                        routing[key] = body[key]
                routing = save_routing(routing)
                log("ROUTING", "SAVE", "Routing settings saved", actor="ui", action="routing_save", extra={"mode": routing.get("mode")})
                restart_singbox()
                return self.send_json({"ok": True, "routing": routing, "summary": routing_summary(routing)})
            if path == "/api/routing/update_sources":
                result = update_routing_sources(body.get("tags") or None)
                restart_singbox()
                return self.send_json({"ok": True, **result, "summary": routing_summary(result.get("routing"))})
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
                log("SERVERS", "IMPORT", f"Imported {len(new_servers)} server(s), total {len(final)}", actor="ui", action="servers_import", extra={"mode": mode, "append": append})
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
                save_servers(parsed["servers"]); log("SERVERS", "REFRESH", f"Subscription refreshed, {len(parsed['servers'])} server(s)", actor="ui", action="servers_refresh", target=url); restart_singbox()
                return self.send_json({"ok": True, "count": len(parsed["servers"]), "errors": parsed.get("errors", [])})
            if path == "/api/servers/priority":
                tag = str(body.get("tag") or "")
                priority = int(body.get("priority") or 50)
                servers = load_servers()
                changed = False
                for srv in servers:
                    if srv.get("tag") == tag:
                        srv["priority"] = max(1, min(999, priority))
                        changed = True
                        break
                if not changed:
                    raise ValueError("Сервер не найден")
                save_servers(servers)
                log("SERVERS", "PRIORITY", f"Priority updated for {tag}: {priority}", actor="ui", action="server_priority", target=tag, extra={"priority": priority})
                restart_singbox()
                return self.send_json({"ok": True, "servers": load_servers(), "auto_tags": auto_server_tags(load_servers())})
            if path == "/api/servers/reorder":
                order = body.get("order") or []
                if not isinstance(order, list):
                    raise ValueError("order должен быть списком tag")
                servers = load_servers()
                by_tag = {s.get("tag"): s for s in servers}
                new_servers = []
                for i, tag in enumerate(order):
                    srv = by_tag.pop(str(tag), None)
                    if srv:
                        srv["priority"] = 10 + i * 10
                        new_servers.append(srv)
                new_servers.extend(by_tag.values())
                save_servers(new_servers)
                log("SERVERS", "REORDER", "Server priorities reordered", actor="ui", action="server_reorder", extra={"count": len(new_servers)})
                restart_singbox()
                return self.send_json({"ok": True, "servers": load_servers(), "auto_tags": auto_server_tags(load_servers())})
            if path == "/api/traffic":
                traffic = load_traffic()
                if "limit_bytes" in body:
                    traffic["limit_bytes"] = int(body.get("limit_bytes") or 0)
                if "used_bytes" in body:
                    traffic["used_bytes"] = int(body.get("used_bytes") or 0)
                save_traffic(traffic); log("TRAFFIC", "SAVE", "Traffic settings saved", actor="ui", action="traffic_save", extra={"limit_bytes": traffic.get("limit_bytes"), "used_bytes": traffic.get("used_bytes")}); return self.send_json({"ok": True, "traffic": traffic})
            if path == "/api/traffic/reset":
                traffic = load_traffic(); traffic["used_bytes"] = 0; traffic["connection_bytes"] = {}; traffic["started_at"] = time.time(); save_traffic(traffic); log("TRAFFIC", "RESET", "Traffic counter reset", actor="ui", action="traffic_reset"); return self.send_json({"ok": True, "traffic": traffic})
            if path == "/api/restart":
                restart_singbox(); return self.send_json({"ok": True})
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            traceback.print_exc()
            self.send_json({"error": str(e)}, 500)

    def do_DELETE(self):
        try:
            path = normalize_request_path(self.path)
            if path.startswith("/api/blocklist/"):
                cidr_or_ip = urllib.parse.unquote(path.split("/api/blocklist/", 1)[1])
                items = [x for x in load_blocked(include_expired=True) if x.get("cidr") != cidr_or_ip and x.get("ip") != cidr_or_ip]
                save_blocked(items); log("BLOCK", "DELETE", f"Unblocked {cidr_or_ip}", actor="ui", action="block_delete", target=cidr_or_ip); restart_singbox(); return self.send_json({"ok": True, "blocked": items})
            if path.startswith("/api/users/"):
                uid = urllib.parse.unquote(path.split("/api/users/", 1)[1])
                users = [u for u in load_proxy_users() if str(u.get("id")) != uid]
                save_proxy_users(users)
                log("USERS", "DELETE", f"Deleted proxy client {uid}", actor="ui", action="user_delete", target=uid)
                restart_singbox()
                return self.send_json({"ok": True, "users": users_safe()})
            if path.startswith("/api/trusted/"):
                ip = urllib.parse.unquote(path.split("/api/trusted/", 1)[1])
                trusted = load_trusted(); trusted.pop(ip, None); save_trusted(trusted); log("TRUSTED", "DELETE", f"Untrusted client {ip}", actor="ui", action="trusted_delete", target=ip); return self.send_json({"ok": True, "trusted": trusted})
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
    settings = load_settings(); settings = update_proxy_lifecycle(settings, load_telegram_settings().get("enabled", False)); save_settings(settings)
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
