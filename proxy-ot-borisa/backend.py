#!/usr/bin/env python3
import base64
import ipaddress
import json
import hashlib
import os
import re
import signal
import socket
import subprocess
import shutil
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
APP_VERSION = "1.23.2"
DATA_DIR = Path("/data")
UI_DIR = Path("/app/ui")
TMP_DIR = Path("/tmp/boris-proxy")
DEFAULT_SERVERS_FILE = Path("/defaults/servers.example.json")
OPTIONS_FILE = Path("/data/options.json")
RUNTIME_PORTS_FILE = Path("/data/runtime_ports.json")
RUNTIME_OPTIONS_FILE = Path("/data/runtime_options.json")
SUBSCRIPTION_INFO_FILE = Path("/data/subscription_info.json")
SUBSCRIPTION_SERVERS_FILE = Path("/data/subscription_servers.json")
SERVER_SOURCES_FILE = Path("/data/server_sources.json")
PORT_KEYS = ["http_proxy_port", "socks_proxy_port", "telegram_proxy_port"]
BACKUP_VERSION = 2
DATA_SCHEMA_VERSION = 3
MIGRATIONS_FILE = Path("/data/migrations.json")
AUDIT_LOG_FILE = Path("/data/audit.json")
MTG_ACTIVITY_FILE = Path("/data/mtproto_activity.json")
NETWORK_QUALITY_FILE = Path("/data/network_quality.json")
AUDIT_LOG_LIMIT = 5000
LAST_GOOD_SINGBOX_CONFIG = DATA_DIR / "sing-box.last-good.json"
EVENT_LOG_LIMIT = 2000
CLIENT_HISTORY_MAX_SESSIONS = 2000
CLIENT_HISTORY_RETENTION_SECONDS = 30 * 24 * 3600
MTG_ONLINE_GRACE_SECONDS = 90
MTG_RECENT_GRACE_SECONDS = 10 * 60
MTG_ACTIVITY_RETENTION_SECONDS = 30 * 24 * 3600
MTG_ACTIVITY_MAX_RECORDS = 1000
SERVER_BACKUP_KEEP = 5
CLIENTS_CACHE_RETENTION_SECONDS = 30 * 24 * 3600
GEO_CACHE_RETENTION_SECONDS = 7 * 24 * 3600
GEO_CACHE_MAX_RECORDS = 5000
AUTOBAN_EVENTS_MAX_IPS = 2000
DATA_REGISTRY = {
    "settings": {"path": DATA_DIR / "settings.json", "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Основные настройки"},
    "runtime_ports": {"path": RUNTIME_PORTS_FILE, "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Рабочие порты"},
    "runtime_options": {"path": RUNTIME_OPTIONS_FILE, "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": True, "description": "Runtime-настройки"},
    "servers": {"path": DATA_DIR / "servers.json", "backup": True, "maintenance": True, "cleanup": "prune_server_sources", "contains_secrets": True, "description": "VPN-серверы"},
    "server_sources": {"path": SERVER_SOURCES_FILE, "backup": True, "maintenance": True, "cleanup": "prune_server_sources", "contains_secrets": True, "description": "Источники VPN-серверов"},
    "server_pings": {"path": DATA_DIR / "server_pings.json", "backup": True, "maintenance": True, "cleanup": "prune_server_pings", "contains_secrets": False, "description": "Результаты ping"},
    "routing": {"path": DATA_DIR / "routing.json", "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Маршрутизация"},
    "users": {"path": DATA_DIR / "proxy_users.json", "backup": True, "maintenance": True, "cleanup": "prune_user_related_data", "contains_secrets": True, "description": "Пользователи"},
    "trusted": {"path": DATA_DIR / "trusted_clients.json", "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Доверенные IP"},
    "clients": {"path": DATA_DIR / "clients.json", "backup": True, "maintenance": True, "cleanup": "prune_clients_file", "contains_secrets": False, "description": "Кэш клиентов", "retention_days": 30},
    "blocklist": {"path": DATA_DIR / "blocked_ips.json", "backup": True, "maintenance": True, "cleanup": "prune_blocked_ips", "contains_secrets": False, "description": "Блокировки"},
    "security": {"path": DATA_DIR / "security.json", "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Безопасность"},
    "traffic": {"path": DATA_DIR / "traffic.json", "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Трафик"},
    "manual_traffic": {"path": DATA_DIR / "manual_traffic.json", "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Ручной трафик"},
    "subscription_info": {"path": SUBSCRIPTION_INFO_FILE, "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": True, "description": "Информация подписки"},
    "subscription_servers": {"path": SUBSCRIPTION_SERVERS_FILE, "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": True, "description": "JSON подписки"},
    "telegram": {"path": DATA_DIR / "telegram_proxy.json", "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": True, "description": "Telegram MTProto настройки"},
    "events": {"path": DATA_DIR / "events.json", "backup": True, "maintenance": True, "cleanup": "prune_events", "contains_secrets": False, "description": "Технические события", "limit": EVENT_LOG_LIMIT},
    "security_autoban_events": {"path": DATA_DIR / "security_autoban_events.json", "backup": False, "maintenance": True, "cleanup": "prune_security_autoban_events_file", "contains_secrets": False, "description": "Временные счётчики автобана", "retention_days": 1, "max_records": AUTOBAN_EVENTS_MAX_IPS},
    "geo_cache": {"path": DATA_DIR / "geo_cache.json", "backup": False, "maintenance": True, "cleanup": "prune_geo_cache_file", "contains_secrets": False, "description": "Кэш геолокации IP", "retention_days": 7, "max_records": GEO_CACHE_MAX_RECORDS},
    "server_backups": {"path": DATA_DIR, "glob": "servers.backup.*.json", "backup": False, "maintenance": True, "cleanup": "prune_server_backup_files", "contains_secrets": True, "description": "Автобэкапы servers.json", "max_records": SERVER_BACKUP_KEEP},
    "audit": {"path": AUDIT_LOG_FILE, "backup": True, "maintenance": True, "cleanup": "prune_audit_events", "contains_secrets": False, "description": "Аудит", "limit": AUDIT_LOG_LIMIT},
    "client_sessions": {"path": DATA_DIR / "client_sessions.json", "backup": True, "maintenance": True, "cleanup": "prune_client_sessions_file", "contains_secrets": False, "description": "История клиентов", "retention_days": 30, "max_records": CLIENT_HISTORY_MAX_SESSIONS},
    "client_limits": {"path": DATA_DIR / "client_limits.json", "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Лимиты клиентов"},
    "mtproto_activity": {"path": MTG_ACTIVITY_FILE, "backup": True, "maintenance": True, "cleanup": "prune_mtg_activity_file", "contains_secrets": False, "description": "Активность MTProto", "retention_days": 30, "max_records": MTG_ACTIVITY_MAX_RECORDS},
    "network_quality": {"path": NETWORK_QUALITY_FILE, "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Диагностика задержек"},
    "migrations": {"path": MIGRATIONS_FILE, "backup": True, "maintenance": True, "cleanup": None, "contains_secrets": False, "description": "Миграции"},
    "last_good_singbox_config": {"path": LAST_GOOD_SINGBOX_CONFIG, "backup": False, "maintenance": True, "cleanup": None, "contains_secrets": True, "description": "Последний рабочий конфиг sing-box"},
}
BACKUP_FILES = {key: Path(meta["path"]).name for key, meta in DATA_REGISTRY.items() if meta.get("backup")}
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
SINGBOX_STARTED_AT = 0
MONITOR_INTERVAL_SECONDS = 15
AUTOBAN_CHECK_INTERVAL_SECONDS = 30
connections_cache = {"items": [], "updated_at": 0, "last_autoban_at": 0}
BOOT_STATE_LOCK = threading.Lock()
BOOT_STATE = {
    "stage": "boot",
    "state": "starting",
    "message": "Подготовка запуска add-on",
    "web_ready": False,
    "app_ready": False,
    "started_at": time.time(),
    "updated_at": time.time(),
}

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


def format_bytes(value):
    try:
        value = float(value or 0)
    except Exception:
        value = 0.0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    while abs(value) >= 1024 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(value)} {units[idx]}"
    return f"{value:.2f} {units[idx]}"


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


def append_audit(stage, result, message, actor="system", action="", target="", extra=None):
    try:
        events = read_json(AUDIT_LOG_FILE, [])
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
        write_json(AUDIT_LOG_FILE, events[-AUDIT_LOG_LIMIT:])
    except Exception:
        pass


def is_audit_event(stage, action="", result=""):
    st = str(stage or "").upper()
    ac = str(action or "").lower()
    rs = str(result or "").upper()
    if "ERROR" in rs or "FATAL" in rs:
        return True
    if st in {"USERS", "USER", "MTG", "TELEGRAM", "SECURITY", "BLOCK", "TRUSTED", "COUNTRY", "AUTOBAN", "BACKUP", "WIZARD", "SERVERS", "ROUTING", "PORTS", "MAINTENANCE"}:
        return True
    return ac.startswith(("user_", "server_", "security_", "backup_", "routing_", "port_", "audit_"))


def log(stage, result, message, actor="system", action="", target="", extra=None):
    print(f"[{time.strftime('%H:%M:%S')}] INFO: [STAGE={stage}] [RESULT={result}] {message}", flush=True)
    append_event(stage, result, message, actor=actor, action=action or stage, target=target, extra=extra)
    if is_audit_event(stage, action or stage, result):
        append_audit(stage, result, message, actor=actor, action=action or stage, target=target, extra=extra)


def log_exception(stage, action, error, actor="system", target="", extra=None):
    tb = traceback.format_exc()
    print(f"[{time.strftime('%H:%M:%S')}] ERROR: [STAGE={stage}] [ACTION={action}] {error}", flush=True)
    append_event(stage, "ERROR", str(error), actor=actor, action=action or stage, target=target, extra={**(extra or {}), "traceback": tb[-4000:]})


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
        "urltest_tolerance": 5,
        "log_level": "warn",
        "production_mode": "normal",
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


VALID_SINGBOX_LOG_LEVELS = {"trace", "debug", "info", "warn", "error", "fatal", "panic"}

def normalize_log_level(value, fallback="warn"):
    value = str(value or "").strip().lower()
    aliases = {"warning": "warn", "err": "error", "quiet": "error", "normal": "warn"}
    value = aliases.get(value, value)
    return value if value in VALID_SINGBOX_LOG_LEVELS else fallback

def load_runtime_options():
    raw = read_json(RUNTIME_OPTIONS_FILE, {})
    if not isinstance(raw, dict):
        raw = {}
    result = {}
    if "log_level" in raw:
        result["log_level"] = normalize_log_level(raw.get("log_level"))
    return result

def save_runtime_options(options):
    current = load_runtime_options()
    if "log_level" in options:
        current["log_level"] = normalize_log_level(options.get("log_level"))
    write_json(RUNTIME_OPTIONS_FILE, current)
    return current

def load_options():
    merged = load_addon_options()
    runtime_ports = load_runtime_ports()
    for key, value in runtime_ports.items():
        merged[key] = value
    runtime_options = load_runtime_options()
    if "log_level" in runtime_options:
        merged["log_level"] = normalize_log_level(runtime_options.get("log_level"))
    else:
        # v1.19.13: previous builds defaulted to info, which flooded the add-on log
        # with every single connection. Quiet operational default is warn.
        merged["log_level"] = normalize_log_level(merged.get("log_level"), "warn")
        if merged.get("log_level") == "info":
            merged["log_level"] = "warn"
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
        restart_singbox_background('autoban')
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


def set_boot_state(stage, message, state_value=None, web_ready=None, app_ready=None, **extra):
    with BOOT_STATE_LOCK:
        BOOT_STATE["stage"] = stage
        BOOT_STATE["message"] = message
        BOOT_STATE["updated_at"] = time.time()
        if state_value is not None:
            BOOT_STATE["state"] = state_value
        if web_ready is not None:
            BOOT_STATE["web_ready"] = bool(web_ready)
        if app_ready is not None:
            BOOT_STATE["app_ready"] = bool(app_ready)
        if extra:
            BOOT_STATE.update(extra)
        return dict(BOOT_STATE)


def get_boot_state():
    with BOOT_STATE_LOCK:
        return dict(BOOT_STATE)


def app_activity():
    boot = get_boot_state()
    if not boot.get("app_ready"):
        message = boot.get("message") or "Add-on запускается"
        return {"state": boot.get("state", "starting"), "message": message, "updated_at": boot.get("updated_at", time.time()), "startup": boot}
    if last_error:
        return {"state": "error", "message": f"Ошибка: {last_error}", "updated_at": time.time(), "startup": boot}
    if not (singbox_process and singbox_process.poll() is None):
        return {"state": "starting", "message": "sing-box ещё не запущен или перезапускается", "updated_at": time.time(), "startup": boot}
    cur = current_server_info(get_proxies())
    if not cur.get("server") or cur.get("server") == "—":
        return {"state": "connecting", "message": "Прокси запущен, идёт определение текущего VPN-сервера", "updated_at": time.time(), "startup": boot}
    if not cur.get("delay"):
        return {"state": "checking", "message": f"Прокси работает через {cur.get('server')}; пинг ещё не проверен", "updated_at": time.time(), "startup": boot}
    return {"state": "ok", "message": f"Прокси работает через {cur.get('server')}, пинг {cur.get('delay')} мс", "updated_at": time.time(), "startup": boot}



def registry_path(key):
    meta = DATA_REGISTRY.get(key) or {}
    return Path(meta.get("path") or data_path(f"{key}.json"))


def registry_backup_items():
    return {k: v for k, v in DATA_REGISTRY.items() if v.get("backup")}


def registry_maintenance_items():
    return {k: v for k, v in DATA_REGISTRY.items() if v.get("maintenance")}


def json_record_count(path):
    data = read_json(path, None)
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        if isinstance(data.get("users"), dict):
            return len(data.get("users") or {})
        if isinstance(data.get("sessions"), list):
            return len(data.get("sessions") or [])
        if isinstance(data.get("items"), list):
            return len(data.get("items") or [])
        return len(data)
    return 0



def registry_product_info(key, meta):
    description = meta.get("description") or key
    contains = bool(meta.get("contains_secrets"))
    backup = bool(meta.get("backup"))
    cleanup = bool(meta.get("cleanup"))
    retention = meta.get("retention_days")
    max_records = meta.get("max_records") or meta.get("limit")
    purpose_map = {
        "settings": "Основные настройки включения HTTP/SOCKS, ссылка основной подписки и служебные даты.",
        "runtime_ports": "Порты, которые пользователь изменил уже после установки add-on.",
        "runtime_options": "Рабочие настройки режима, авторизации, логирования и диагностики.",
        "servers": "Единый рабочий пул VPN/VLESS-серверов, из которого строится конфиг sing-box.",
        "server_sources": "Карточки источников серверов: подписки, JSON-импорт, ручные и ранее добавленные серверы.",
        "server_pings": "Кэш последних проверок ping по серверам, чтобы интерфейс и auto не проверяли всё заново каждую секунду.",
        "routing": "Правила split-routing: какие домены/IP идут через VPN, а какие напрямую.",
        "users": "Пользователи прокси, их доступы, пароли, MTProto secret, группы и сроки действия.",
        "trusted": "Доверенные IP-клиенты, которые администратор пометил как известные.",
        "clients": "Кэш видимых клиентов: IP, статус, первое/последнее появление. Это не содержимое трафика.",
        "blocklist": "Список заблокированных IP/CIDR и сроков временной блокировки.",
        "security": "Настройки геофильтра, автобана и исключений безопасности.",
        "traffic": "Состояние автоматического трафика подписки, если провайдер отдаёт лимиты.",
        "manual_traffic": "Ручной учёт лимитов для сторонних серверов/подписок, где нет автоматических данных.",
        "subscription_info": "Информация о подписке и лимитах, полученная из заголовков/ответа провайдера.",
        "subscription_servers": "Нормализованный JSON серверов, полученный из ссылки подписки.",
        "telegram": "Настройки Telegram MTProto-сервиса и общего MTProto-порта.",
        "events": "Технические события приложения: запуск, ошибки, применение конфигов, системные операции.",
        "security_autoban_events": "Временные счётчики новых соединений по IP для алгоритма автобана.",
        "geo_cache": "Кэш геолокации IP, чтобы не выполнять повторные проверки для одних и тех же адресов.",
        "server_backups": "Автоматические локальные копии servers.json перед изменениями списка серверов.",
        "audit": "Аудит действий администратора и событий безопасности: создание, удаление, включение, очистка.",
        "client_sessions": "История сессий клиентов: кто, когда, сколько был онлайн, через какой сервис и маршрут.",
        "client_limits": "Лимиты клиентов и будущие ограничения/предупреждения по использованию.",
        "mtproto_activity": "Активность MTProto-пользователей по безопасному fingerprint secret без хранения полного secret.",
        "network_quality": "Последний отчёт диагностики задержек: прямые проверки и проверки через proxy/VPN.",
        "migrations": "Версия схемы данных и отметки о выполненных миграциях.",
        "last_good_singbox_config": "Последний рабочий конфиг sing-box для отката при неудачном применении.",
    }
    purpose = purpose_map.get(key, description)
    if backup:
        backup_policy = "Входит в резервную копию add-on."
        if contains:
            backup_policy += " Содержит чувствительные данные; при экспорте без секретов значения маскируются или исключаются."
    else:
        backup_policy = "Не входит в обычную резервную копию: это кэш, временный файл или аварийный локальный откат."
    if cleanup:
        details = []
        if retention:
            details.append(f"хранение {retention} дн.")
        if max_records:
            details.append(f"лимит {max_records}")
        cleanup_policy = "Очищается автоматически по правилам хранения"
        if details:
            cleanup_policy += ": " + ", ".join(details)
        cleanup_policy += ". Также участвует в кнопке «Очистить по правилам хранения»."
    else:
        cleanup_policy = "Автоочистка не применяется: файл хранит текущие настройки/состояние, а не растущий журнал."
    user_action_map = {
        "server_backups": "Обычно трогать не нужно. Старые копии удаляются сами, остаются только последние 5.",
        "events": "Для повседневной работы можно очищать через обслуживание; важные действия остаются в аудите.",
        "audit": "Очищать только осознанно: это журнал действий администратора и безопасности.",
        "client_sessions": "Можно очищать, если нужна новая история подключений. На текущие доступы это не влияет.",
        "mtproto_activity": "Можно очищать для сброса статусов Telegram; после новых подключений активность соберётся заново.",
        "geo_cache": "Можно очищать без риска: кэш заполнится заново.",
        "security_autoban_events": "Временные счётчики; можно очищать при диагностике автобана.",
    }
    user_action = user_action_map.get(key, "Обычно изменяется через соответствующий раздел интерфейса, вручную файл трогать не нужно.")
    growth_control = "контролируется" if cleanup or not (key in {"events", "audit", "client_sessions", "mtproto_activity", "geo_cache", "security_autoban_events", "server_backups"}) else "проверить"
    return {
        "purpose": purpose,
        "backup_policy": backup_policy,
        "cleanup_policy": cleanup_policy,
        "user_action": user_action,
        "growth_control": growth_control,
    }

def data_registry_status():
    result = {}
    for key, meta in registry_maintenance_items().items():
        path = Path(meta["path"])
        glob_pattern = meta.get("glob")
        if glob_pattern:
            files = list(path.glob(str(glob_pattern))) if path.exists() and path.is_dir() else []
            size = sum(file_size(x) for x in files)
            exists = bool(files)
            records = len(files)
            shown_path = str(path / str(glob_pattern))
        else:
            exists = path.exists()
            size = file_size(path)
            records = json_record_count(path) if exists else 0
            shown_path = str(path)
        product_info = registry_product_info(key, meta)
        result[key] = {
            "path": shown_path,
            "exists": exists,
            "size_bytes": size,
            "records": records,
            "backup": bool(meta.get("backup")),
            "cleanup": bool(meta.get("cleanup")),
            "contains_secrets": bool(meta.get("contains_secrets")),
            "description": meta.get("description") or key,
            "purpose": product_info.get("purpose"),
            "backup_policy": product_info.get("backup_policy"),
            "cleanup_policy": product_info.get("cleanup_policy"),
            "user_action": product_info.get("user_action"),
            "growth_control": product_info.get("growth_control"),
            "retention_days": meta.get("retention_days"),
            "max_records": meta.get("max_records") or meta.get("limit"),
        }
    return result


def prune_list_file(path, limit):
    data = read_json(path, [])
    if not isinstance(data, list):
        data = []
    pruned = data[-int(limit):]
    if len(pruned) != len(data):
        write_json(path, pruned)
    return {"before": len(data), "after": len(pruned)}


def prune_events():
    return prune_list_file(data_path("events.json"), EVENT_LOG_LIMIT)


def prune_audit_events():
    return prune_list_file(AUDIT_LOG_FILE, AUDIT_LOG_LIMIT)


def prune_security_autoban_events_file():
    sec = load_security()
    window = max(60, int(sec.get("autoban_window_seconds") or 60))
    now = time.time()
    data = read_json(data_path("security_autoban_events.json"), {})
    if not isinstance(data, dict):
        data = {}
    before = len(data)
    cleaned = {}
    for ip, ids in data.items():
        if not isinstance(ids, dict):
            continue
        recent = {cid: ts for cid, ts in ids.items() if isinstance(ts, (int, float)) and now - float(ts) <= window}
        if recent:
            cleaned[ip] = recent
    if len(cleaned) > AUTOBAN_EVENTS_MAX_IPS:
        ranked = sorted(cleaned.items(), key=lambda kv: max(float(x) for x in kv[1].values()), reverse=True)[:AUTOBAN_EVENTS_MAX_IPS]
        cleaned = dict(ranked)
    if cleaned != data:
        write_json(data_path("security_autoban_events.json"), cleaned)
    return {"before": before, "after": len(cleaned)}


def prune_geo_cache_file():
    now = time.time()
    data = read_json(data_path("geo_cache.json"), {})
    if not isinstance(data, dict):
        data = {}
    before = len(data)
    cutoff = now - GEO_CACHE_RETENTION_SECONDS
    items = []
    for ip, rec in data.items():
        if not isinstance(rec, dict):
            continue
        ts = float(rec.get("ts") or 0)
        if ts >= cutoff:
            items.append((ip, rec, ts))
    items.sort(key=lambda x: x[2], reverse=True)
    cleaned = {ip: rec for ip, rec, _ in items[:GEO_CACHE_MAX_RECORDS]}
    if cleaned != data:
        write_json(data_path("geo_cache.json"), cleaned)
    return {"before": before, "after": len(cleaned)}


def prune_server_backup_files():
    files = sorted(DATA_DIR.glob("servers.backup.*.json"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    before = len(files)
    for path in files[SERVER_BACKUP_KEEP:]:
        try:
            path.unlink()
        except Exception:
            pass
    return {"before": before, "after": min(before, SERVER_BACKUP_KEEP)}


def prune_clients_file():
    now = time.time()
    data = load_clients()
    if not isinstance(data, dict):
        data = {}
    before = len(data)
    trusted = load_trusted()
    users = load_proxy_users()
    active_user_ids = {str(u.get("id") or "") for u in users if u.get("id")}
    active_usernames = {str(u.get("username") or "") for u in users if u.get("username")}
    kept = {}
    for key, item in data.items():
        if not isinstance(item, dict):
            continue
        ip = item.get("ip") or (str(key).split(":", 1)[-1] if str(key).startswith("ip:") else "")
        last_seen = float(item.get("last_seen") or item.get("updated_at") or item.get("first_seen") or 0)
        is_registered = str(item.get("registered_user_id") or "") in active_user_ids or str(item.get("username") or "") in active_usernames
        is_trusted = bool(ip and ip in trusted)
        if is_registered or is_trusted or last_seen >= now - CLIENTS_CACHE_RETENTION_SECONDS:
            kept[key] = item
    if kept != data:
        save_clients(kept)
    return {"before": before, "after": len(kept)}


def prune_client_sessions_file():
    data = load_client_sessions()
    before = len((normalize_client_sessions(data)).get("sessions") or [])
    pruned = prune_client_sessions(data)
    save_client_sessions(pruned)
    after = len((pruned.get("sessions") or []))
    return {"before": before, "after": after}


def prune_mtg_activity(data=None, now=None):
    now = float(now or time.time())
    data = data if isinstance(data, dict) else load_mtg_activity()
    records = data.setdefault("users", {})
    if not isinstance(records, dict):
        records = {}; data["users"] = records
    active_user_ids = {str(u.get("id") or "") for u in load_proxy_users() if u.get("id")}
    cutoff = now - MTG_ACTIVITY_RETENTION_SECONDS
    before = len(records)
    kept = {}
    current = []
    stale = []
    for uid, rec in records.items():
        if not isinstance(rec, dict):
            continue
        last_seen = float(rec.get("last_seen") or rec.get("updated_at") or rec.get("first_seen") or 0)
        item = (uid, rec, last_seen)
        if uid in active_user_ids or last_seen >= cutoff or float(rec.get("online_until") or 0) >= now:
            current.append(item)
        else:
            stale.append(item)
    current.sort(key=lambda x: x[2], reverse=True)
    stale.sort(key=lambda x: x[2], reverse=True)
    for uid, rec, _ in current[:MTG_ACTIVITY_MAX_RECORDS]:
        kept[uid] = rec
    if len(kept) < MTG_ACTIVITY_MAX_RECORDS:
        for uid, rec, _ in stale[:MTG_ACTIVITY_MAX_RECORDS - len(kept)]:
            kept[uid] = rec
    data["users"] = kept
    data["retention"] = {
        "days": int(MTG_ACTIVITY_RETENTION_SECONDS // 86400),
        "max_records": MTG_ACTIVITY_MAX_RECORDS,
        "pruned_at": now,
        "before": before,
        "after": len(kept),
    }
    return data


def prune_mtg_activity_file():
    data = load_mtg_activity()
    before = len(data.get("users") or {})
    pruned = prune_mtg_activity(data)
    save_mtg_activity(pruned)
    return {"before": before, "after": len(pruned.get("users") or {})}


def prune_server_pings():
    pings = load_server_pings()
    if not isinstance(pings, dict):
        pings = {}
    servers = {str(s.get("tag") or s.get("name") or "") for s in load_servers()}
    before = len(pings)
    pings = {k: v for k, v in pings.items() if k in servers}
    write_json(data_path("server_pings.json"), pings)
    return {"before": before, "after": len(pings)}


def prune_blocked_ips():
    now = time.time()
    items = load_blocked()
    before = len(items)
    kept = []
    for b in items:
        until = b.get("until") or b.get("blocked_until")
        try:
            expired = until not in [None, "", "permanent"] and float(until) <= now
        except Exception:
            expired = False
        if not expired:
            kept.append(b)
    if len(kept) != before:
        write_json(data_path("blocked_ips.json"), kept)
    return {"before": before, "after": len(kept)}


def prune_user_related_data():
    # Placeholder hook: user-related cleanup is handled by specific files
    # such as mtproto_activity and client_sessions, not by deleting users.
    return {"before": len(load_proxy_users()), "after": len(load_proxy_users())}


def prune_all_data_files():
    results = {}
    for key, meta in DATA_REGISTRY.items():
        cleanup_name = meta.get("cleanup")
        if not cleanup_name:
            continue
        fn = globals().get(cleanup_name)
        if not callable(fn):
            results[key] = {"error": f"cleanup function {cleanup_name} not found"}
            continue
        try:
            results[key] = fn()
        except Exception as e:
            results[key] = {"error": str(e)}
    return results

def export_backup(include_events=False, include_secrets=True):
    files = {}
    for key, meta in registry_backup_items().items():
        if key in {"events", "audit"} and not include_events:
            continue
        path = Path(meta["path"])
        if path.exists():
            files[key] = read_json(path, None)
        elif key in {"events", "audit"}:
            files[key] = []
    if not include_secrets:
        files = sanitize_sensitive(files)
    options = load_options()
    ports = load_runtime_ports()
    return {
        "format": "proxy_ot_borisa_backup",
        "backup_version": BACKUP_VERSION,
        "data_schema_version": DATA_SCHEMA_VERSION,
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "created_at": time.time(),
        "created_time": iso_time(),
        "include_secrets": bool(include_secrets),
        "note": "Резервная копия содержит настройки и пользователей" + (", включая секреты. Храните файл безопасно." if include_secrets else ", но секреты замаскированы для безопасной передачи в поддержку."),
        "addon_options_snapshot": sanitize_sensitive({
            "http_proxy_port": options.get("http_proxy_port"),
            "socks_proxy_port": options.get("socks_proxy_port"),
            "telegram_proxy_port": options.get("telegram_proxy_port"),
            "http_auth_enabled": options.get("http_auth_enabled"),
            "socks_auth_enabled": options.get("socks_auth_enabled"),
            "telegram_proxy_enabled": options.get("telegram_proxy_enabled"),
            "log_level": options.get("log_level"),
            "production_mode": options.get("production_mode"),
        }) if not include_secrets else {
            "http_proxy_port": options.get("http_proxy_port"),
            "socks_proxy_port": options.get("socks_proxy_port"),
            "telegram_proxy_port": options.get("telegram_proxy_port"),
            "http_auth_enabled": options.get("http_auth_enabled"),
            "socks_auth_enabled": options.get("socks_auth_enabled"),
            "telegram_proxy_enabled": options.get("telegram_proxy_enabled"),
            "log_level": options.get("log_level"),
            "production_mode": options.get("production_mode"),
        },
        "active_ports_snapshot": ports,
        "files": files,
    }

def import_backup(payload, mode="replace"):
    if not isinstance(payload, dict):
        raise ValueError("Некорректный JSON резервной копии")
    if payload.get("format") != "proxy_ot_borisa_backup":
        raise ValueError("Это не резервная копия Proxy от Бориса")
    files = payload.get("files")
    if not isinstance(files, dict):
        raise ValueError("В резервной копии нет блока files")
    restored = []
    for key, meta in registry_backup_items().items():
        if key not in files:
            continue
        if key in {"events", "audit"} and mode != "replace_with_logs":
            continue
        write_json(Path(meta["path"]), files[key])
        restored.append(key)
    log("BACKUP", "IMPORT", f"Backup imported: {', '.join(restored)}", actor="ui", action="backup_import", extra={"restored": restored, "mode": mode})
    return restored



SENSITIVE_KEYS = {
    "password", "secret", "telegram_secret", "subscription_url", "url", "uuid", "server", "flow",
    "private_key", "short_id", "public_key", "proxy_password", "proxy_username"
}

def mask_secret_value(value, keep=4):
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= keep * 2:
        return "*" * max(4, len(text))
    return text[:keep] + "…" + text[-keep:]


def sanitize_sensitive(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in SENSITIVE_KEYS or any(x in lk for x in ["password", "secret", "token", "uuid"]):
                out[k] = mask_secret_value(v)
            else:
                out[k] = sanitize_sensitive(v)
        return out
    if isinstance(obj, list):
        return [sanitize_sensitive(x) for x in obj]
    return obj


def file_size(path):
    try:
        return Path(path).stat().st_size
    except Exception:
        return 0


def maintenance_status():
    try:
        du = shutil.disk_usage(str(DATA_DIR))
        disk = {"total": du.total, "used": du.used, "free": du.free, "free_pct": round(du.free / du.total * 100, 2) if du.total else 0}
    except Exception:
        disk = {"total": 0, "used": 0, "free": 0, "free_pct": 0}
    files = data_registry_status()
    return {
        "schema_version": read_json(MIGRATIONS_FILE, {}).get("schema_version", 0),
        "target_schema_version": DATA_SCHEMA_VERSION,
        "disk": disk,
        "files": files,
        "retention": {
            "events_limit": EVENT_LOG_LIMIT,
            "audit_limit": AUDIT_LOG_LIMIT,
            "client_history_days": int(CLIENT_HISTORY_RETENTION_SECONDS/86400),
            "client_history_max_sessions": CLIENT_HISTORY_MAX_SESSIONS,
            "mtproto_activity_days": int(MTG_ACTIVITY_RETENTION_SECONDS/86400),
            "mtproto_activity_max_records": MTG_ACTIVITY_MAX_RECORDS,
        },
        "registry": {k: {kk: vv for kk, vv in meta.items() if kk != "path"} for k, meta in DATA_REGISTRY.items()},
        "updated_at": time.time(),
    }

def clear_events():
    write_json(data_path("events.json"), [])
    return {"ok": True, "events": []}


def get_audit_events(limit=300, category="all"):
    events = read_json(AUDIT_LOG_FILE, [])
    if not isinstance(events, list):
        return []
    try:
        limit = max(1, min(int(limit), AUDIT_LOG_LIMIT))
    except Exception:
        limit = 300
    if category and category != "all":
        events = [e for e in events if str(e.get("category") or event_category(e.get("stage"), e.get("result"))) == category]
    return events[-limit:][::-1]


def clear_audit_events():
    write_json(AUDIT_LOG_FILE, [])
    return {"ok": True, "events": []}


def production_mode_from_options(options=None):
    options = options or load_options()
    mode = str(options.get("production_mode") or "normal").lower().strip()
    return mode if mode in {"normal", "diagnostic", "debug", "safe"} else "normal"


def apply_production_mode(mode):
    mode = str(mode or "normal").lower().strip()
    if mode not in {"normal", "diagnostic", "debug", "safe"}:
        raise ValueError("Некорректный режим работы")
    opts = load_runtime_options()
    opts["production_mode"] = mode
    if mode == "normal":
        opts["log_level"] = "warn"
    elif mode == "diagnostic":
        opts["log_level"] = "info"
    elif mode == "debug":
        opts["log_level"] = "debug"
    elif mode == "safe":
        opts["log_level"] = "warn"
    save_runtime_options(opts)
    return load_options()


def mutating_path_allowed_in_safe_mode(path):
    # Safe mode is for recovery: viewing/exporting is allowed, destructive/apply
    # actions are blocked. Changing mode back is intentionally allowed.
    allowed = {
        "/api/options/mode",
        "/api/options/logging",
        "/api/wizard/complete",
        "/api/audit/clear",
        "/api/maintenance/prune",
    }
    return path in allowed


def ensure_not_safe_mode_for_mutation(path):
    if production_mode_from_options(load_options()) == "safe" and not mutating_path_allowed_in_safe_mode(path):
        raise PermissionError("Безопасный режим: изменения заблокированы. Переключи режим работы на обычный/диагностику, если нужно применить настройки.")


def migrate_data():
    """Small idempotent data migrations for old /data files."""
    state = read_json(MIGRATIONS_FILE, {})
    if not isinstance(state, dict):
        state = {}
    current = int(state.get("schema_version") or 0)
    changed = []
    if current < 1:
        users = load_proxy_users()
        for u in users:
            u.setdefault("group", "Без группы")
            u.setdefault("expires_at", None)
            u.setdefault("traffic_policy", {"enabled": False, "monthly_limit_gb": 0})
            u.setdefault("created_at", time.time())
            u.setdefault("updated_at", u.get("created_at") or time.time())
        save_proxy_users(users)
        changed.append("users-v1")
        current = 1
    if current < 2:
        # Ensure traffic/history files have retention-friendly structure.
        normalize_client_sessions(load_client_sessions())
        prune_client_sessions(load_client_sessions())
        changed.append("history-v2")
        current = 2
    if current < 3:
        opts = load_runtime_options()
        if "log_level" not in opts:
            opts["log_level"] = "warn"
            save_runtime_options(opts)
        changed.append("runtime-options-v3")
        current = 3
    state.update({"schema_version": DATA_SCHEMA_VERSION, "updated_at": time.time(), "last_migrations": changed})
    write_json(MIGRATIONS_FILE, state)
    if changed:
        log("MIGRATION", "OK", "Data migrations applied: " + ", ".join(changed), action="data_migration", extra={"migrations": changed})
    return state


def user_safe_for_ui(user):
    item = dict(user or {})
    # Hide full secrets by default, but keep full values in copyable URLs where they are already explicitly intended for configuration.
    item["password_masked"] = mask_secret_value(item.get("password"))
    item["telegram_secret_masked"] = mask_secret_value(item.get("telegram_secret"))
    item.setdefault("group", "Без группы")
    item.setdefault("expires_at", None)
    return item


def rotate_user_access(uid, rotate_password=False, rotate_telegram=False, rotate_username=False):
    users = load_proxy_users()
    found = None
    for u in users:
        if str(u.get("id")) == str(uid) or str(u.get("username")) == str(uid):
            found = u
            break
    if not found:
        raise ValueError("Пользователь не найден")
    changes = []
    if rotate_username:
        base = slugify_username(found.get("name") or found.get("username") or "client")
        existing = {x.get("username") for x in users if x is not found}
        i = 1
        new_name = base
        while new_name in existing:
            i += 1
            new_name = f"{base}-{i}"
        found["username"] = new_name
        changes.append("username")
    if rotate_password:
        found["password"] = random_token(20)
        changes.append("password")
    if rotate_telegram:
        found["telegram_secret"] = make_mtproto_secret(found.get("telegram_front_domain") or "www.google.com")
        changes.append("telegram_secret")
    if not changes:
        found["password"] = random_token(20)
        found["telegram_secret"] = make_mtproto_secret(found.get("telegram_front_domain") or "www.google.com")
        changes = ["password", "telegram_secret"]
    found["updated_at"] = time.time()
    save_proxy_users(users)
    log("USERS", "ROTATE", "Rotated user access: " + ", ".join(changes), actor="ui", action="user_rotate", target=found.get("username"), extra={"changes": changes})
    restart_singbox_background("user_rotate")
    return {"ok": True, "changes": changes, "users": users_safe(), "apply_background": True}


def route_test_domain(value):
    raw = str(value or "").strip().lower()
    if not raw:
        raise ValueError("Укажите домен или IP")
    raw = re.sub(r"^https?://", "", raw).split("/")[0].split(":")[0].strip(".")
    routing = load_routing()
    include_domains = set(normalize_domains(routing.get("manual_include_domains") or []))
    exclude_domains = set(normalize_domains(routing.get("manual_exclude_domains") or []))
    include_ips = set(normalize_cidrs(routing.get("manual_include_ips") or []))
    exclude_ips = set(normalize_cidrs(routing.get("manual_exclude_ips") or []))
    mode = routing.get("mode") or "all_proxy"
    is_ip = False
    try:
        ipaddress.ip_address(raw)
        is_ip = True
    except Exception:
        pass
    def domain_matches(domains):
        return any(raw == d or raw.endswith("." + d) for d in domains)
    result = {"query": value, "normalized": raw, "mode": mode, "route": "Proxy", "reason": "default", "updated_at": time.time()}
    if mode == "all_direct":
        result.update(route="direct", reason="mode_all_direct")
    elif mode in ["blocked_plus_manual", "blocked_only", "manual_only"]:
        result.update(route="direct", reason="mode_default_direct")
    if is_ip:
        if any(ipaddress.ip_address(raw) in ipaddress.ip_network(c, strict=False) for c in include_ips):
            result.update(route="Proxy", reason="manual_include_ip")
        if any(ipaddress.ip_address(raw) in ipaddress.ip_network(c, strict=False) for c in exclude_ips):
            result.update(route="direct", reason="manual_exclude_ip")
    else:
        if domain_matches(include_domains):
            result.update(route="Proxy", reason="manual_include_domain")
        if domain_matches(exclude_domains):
            result.update(route="direct", reason="manual_exclude_domain")
        for preset, enabled in (routing.get("presets") or {}).items():
            if enabled and domain_matches(PRESET_DOMAINS.get(preset, [])):
                result.update(route="Proxy", reason="preset_" + preset)
                break
    cur = current_server_info(get_proxies())
    result["proxy_mode"] = cur.get("mode")
    result["proxy_server"] = cur.get("server")
    result["proxy_delay"] = cur.get("delay")
    return result

def _port_listening(port):
    try:
        port = int(port)
        with socket.create_connection(("127.0.0.1", port), timeout=0.6):
            return True
    except Exception:
        return False


def _check_item(status, title, details="", fix="", group="system"):
    return {"status": status, "title": title, "details": details, "fix": fix, "group": group}


def system_check_report():
    options = load_options()
    settings = load_settings()
    servers = load_servers()
    users = load_proxy_users()
    routing = load_routing()
    security = load_security()
    ports = load_runtime_ports()
    blocked = load_blocked()
    sub = load_subscription_info()
    ru = country_cidr_details("RU", limit=3, full=False)
    items = []

    singbox_ok = bool(singbox_process and singbox_process.poll() is None)
    items.append(_check_item("ok" if singbox_ok else "bad", "sing-box", "Основной прокси-процесс работает." if singbox_ok else f"sing-box не запущен: {last_error or 'ошибка неизвестна'}", "Проверьте логи и перезапустите add-on." if not singbox_ok else "", "proxy"))

    if servers:
        items.append(_check_item("ok", "VPN-серверы", f"Добавлено серверов: {len(servers)}.", "", "vpn"))
    else:
        items.append(_check_item("bad", "VPN-серверы", "Серверы не добавлены.", "Откройте вкладку VPN-серверы и добавьте JSON, vless:// ссылки или ссылку подписки.", "vpn"))

    cur = current_server_info(get_proxies())
    if cur.get("server") and cur.get("server") != "—":
        items.append(_check_item("ok" if cur.get("delay") else "warn", "Текущий VPN-сервер", f"Выбран: {cur.get('server')}; пинг: {cur.get('delay') or 'не проверен'}.", "Нажмите «Пинг всех», если пинг не отображается.", "vpn"))
    else:
        items.append(_check_item("warn", "Текущий VPN-сервер", "Фактический сервер не подтверждён.", "Проверьте серверы и выберите auto или конкретный сервер.", "vpn"))

    if sub.get("url"):
        traffic = sub.get("traffic") or {}
        total = traffic.get("total") or 0
        items.append(_check_item("ok", "VPN-подписка", f"Ссылка сохранена. Серверов: {sub.get('servers_count') or len(servers)}. Лимит: {format_bytes(total) if total else 'не указан'}.", "", "vpn"))
    else:
        items.append(_check_item("warn", "VPN-подписка", "Ссылка подписки не сохранена.", "Если провайдер выдаёт ссылку подписки, добавьте её во вкладке VPN-серверы.", "vpn"))

    mode = routing.get("mode") or "all_proxy"
    items.append(_check_item("ok", "Маршрутизация", f"Текущий режим: {mode}.", "Для режима обхода блокировок обычно удобен blocked_plus_manual.", "routing"))
    enabled_sources = [s for s in routing.get("sources", []) if s.get("enabled")]
    if mode == "blocked_plus_manual" and not enabled_sources and not routing.get("manual_include_domains") and not routing.get("manual_include_ips"):
        items.append(_check_item("warn", "Списки маршрутизации", "Режим списков включён, но источники/ручные правила пустые.", "Включите источники или добавьте домены вручную.", "routing"))
    else:
        items.append(_check_item("ok", "Списки маршрутизации", f"Включено источников: {len(enabled_sources)}; ручных доменов: {len(routing.get('manual_include_domains') or [])}.", "", "routing"))

    if users:
        enabled_users = [u for u in users if u.get("enabled", True)]
        items.append(_check_item("ok", "Пользователи", f"Пользователей: {len(users)}, активных: {len(enabled_users)}.", "", "users"))
    else:
        items.append(_check_item("warn", "Пользователи", "Отдельные пользователи не созданы.", "Создайте пользователей для людей/устройств, чтобы видеть и управлять доступом отдельно.", "users"))

    if options.get("http_auth_enabled"):
        items.append(_check_item("ok", "HTTP auth", "HTTP-прокси защищён авторизацией.", "", "security"))
    else:
        items.append(_check_item("warn", "HTTP auth", "HTTP-прокси без авторизации. Это опасно, если порт открыт в интернет.", "Не пробрасывайте HTTP-порт наружу или включите авторизацию, если клиенты её поддерживают.", "security"))
    items.append(_check_item("ok" if options.get("socks_auth_enabled") else "warn", "SOCKS5 auth", "SOCKS5 защищён авторизацией." if options.get("socks_auth_enabled") else "SOCKS5 без авторизации.", "Включите SOCKS5 auth для внешнего доступа." if not options.get("socks_auth_enabled") else "", "security"))
    items.append(_check_item("ok" if security.get("autoban_enabled") else "warn", "Автоблокировка", "Автоблокировка включена." if security.get("autoban_enabled") else "Автоблокировка выключена.", "Включите автоблокировку, если прокси доступен из интернета." if not security.get("autoban_enabled") else "", "security"))
    if security.get("country_filter_enabled"):
        items.append(_check_item("ok" if ru.get("count") else "warn", "RU CIDR геофильтр", f"Включён. CIDR в базе: {ru.get('count') or 0}.", "Обновите RU IP-список, если база пустая." if not ru.get("count") else "", "security"))
    else:
        items.append(_check_item("warn", "RU CIDR геофильтр", "Геофильтр выключен.", "Можно включить, если прокси нужен только из России и доверенных сетей.", "security"))
    items.append(_check_item("ok", "Блокировки", f"Активных записей блокировки: {len(blocked)}.", "", "security"))

    for key, label in [("http_proxy_port", "HTTP"), ("socks_proxy_port", "SOCKS5"), ("telegram_proxy_port", "Telegram")]:
        port = ports.get(key) or options.get(key)
        if not port:
            continue
        listening = _port_listening(port)
        required = key != "telegram_proxy_port" or bool(options.get("telegram_proxy_enabled"))
        status = "ok" if listening else ("warn" if not required else "bad")
        items.append(_check_item(status, f"Порт {label} {port}", "Сервис слушает порт." if listening else "Порт сейчас не отвечает внутри add-on.", "Проверьте, включён ли соответствующий прокси и применены ли порты." if not listening and required else "", "ports"))

    try:
        du = shutil.disk_usage(str(DATA_DIR))
        free_pct = du.free / du.total * 100 if du.total else 0
        items.append(_check_item("ok" if free_pct > 10 else "warn", "Свободное место", f"Свободно: {format_bytes(du.free)} из {format_bytes(du.total)} ({free_pct:.1f}%).", "Освободите место или уменьшите логи, если свободно меньше 10%.", "system"))
    except Exception:
        pass

    bad = sum(1 for i in items if i["status"] == "bad")
    warn = sum(1 for i in items if i["status"] == "warn")
    ok = sum(1 for i in items if i["status"] == "ok")
    overall = "bad" if bad else ("warn" if warn else "ok")
    # First-launch and production-hardening checks.
    if str(options.get("secret") or "").startswith("ChangeThis"):
        items.append(_check_item("warn", "Clash/API secret оставлен по умолчанию", "Смени secret в конфигурации add-on или runtime-настройках.", "Открыть конфигурацию add-on", "security")); warn += 1
    if str(options.get("proxy_password") or "").startswith("ChangeThis"):
        items.append(_check_item("warn", "Пароль прокси по умолчанию", "Смени стандартный proxy_password перед внешним доступом.", "Открыть пользователей/конфигурацию", "security")); warn += 1
    if not bool(options.get("http_auth_enabled")) or not bool(options.get("socks_auth_enabled")):
        items.append(_check_item("warn", "Авторизация прокси включена не полностью", "Для публичных портов HTTP и SOCKS5 должны быть с авторизацией.", "Включить авторизацию", "security")); warn += 1
    users = load_proxy_users()
    if not users:
        items.append(_check_item("warn", "Нет зарегистрированных пользователей", "Создай отдельных пользователей для устройств/людей, иначе не будет нормальной идентификации.", "Открыть пользователей", "users")); warn += 1
    overall = "bad" if bad else ("warn" if warn else "ok")
    return {"overall": overall, "ok": ok, "warn": warn, "bad": bad, "items": items, "generated_at": time.time(), "wizard_completed": bool(settings.get("wizard_completed"))}


def mark_wizard_completed(value=True):
    settings = load_settings()
    settings["wizard_completed"] = bool(value)
    settings["wizard_completed_at"] = time.time() if value else None
    save_settings(settings)
    return settings


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
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyOtBorisa/1.19"})
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




def users_safe(public_host=None):
    result = []
    for u in load_proxy_users():
        item = user_safe_for_ui(u)
        item['blocked_active'] = is_user_block_active(item)
        item['expired'] = bool(item.get('expires_at') and float(item.get('expires_at') or 0) <= time.time()) if item.get('expires_at') not in [None, '', 0] else False
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
    try:
        exp = user.get('expires_at')
        if exp not in [None, '', 0] and float(exp) <= time.time():
            user['enabled'] = False
    except Exception:
        pass
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
    user.setdefault('group', 'Без группы')
    user.setdefault('expires_at', None)
    user.setdefault('traffic_policy', {'enabled': False, 'monthly_limit_gb': 0})
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


def secret_fingerprint(value):
    raw = str(value or '').encode('utf-8', errors='ignore')
    if not raw:
        return ''
    return hashlib.sha256(raw).hexdigest()[:16]


def load_mtg_activity():
    data = read_json(MTG_ACTIVITY_FILE, {})
    if not isinstance(data, dict):
        data = {}
    users = data.get('users')
    if not isinstance(users, dict):
        data['users'] = {}
    data.setdefault('updated_at', 0)
    data.setdefault('version', 1)
    return data


def save_mtg_activity(data):
    if not isinstance(data, dict):
        data = {'users': {}}
    data = prune_mtg_activity(data)
    data['updated_at'] = time.time()
    data.setdefault('version', 1)
    write_json(MTG_ACTIVITY_FILE, data)
    return data


def mtg_stat_number(item, *keys):
    return _mtg_stat_int(item, *keys)


def mtg_stat_seen_ts(value):
    if value in [None, '', 0]:
        return 0.0
    try:
        val = float(value)
        if val > 1000000000000:
            val = val / 1000.0
        if val > 1000000000:
            return val
    except Exception:
        pass
    return 0.0


def mtg_user_presence_from_record(record, now=None):
    now = now or time.time()
    if not isinstance(record, dict) or not record.get('first_seen'):
        return {'status': 'never', 'online': False, 'recent': False, 'last_seen': 0, 'status_text': 'не подключался'}
    last_seen = float(record.get('last_seen') or 0)
    online_until = float(record.get('online_until') or 0)
    if online_until >= now:
        return {'status': 'online', 'online': True, 'recent': True, 'last_seen': last_seen, 'status_text': 'онлайн'}
    if last_seen and now - last_seen <= MTG_RECENT_GRACE_SECONDS:
        return {'status': 'recent', 'online': False, 'recent': True, 'last_seen': last_seen, 'status_text': 'недавно был'}
    return {'status': 'offline', 'online': False, 'recent': False, 'last_seen': last_seen, 'status_text': 'оффлайн'}


def update_mtg_activity_from_stats(stats=None, users=None, real_peers=None):
    """Refresh per-secret MTProto activity.

    mtg-multi builds differ: some expose active connection count, others only
    expose counters/last_seen. We therefore treat a counter delta or a fresh
    last_seen as confirmed activity and keep the user online for a short grace
    window. This avoids showing "offline" while Telegram works through the
    issued secret.
    """
    now = time.time()
    users = users if users is not None else load_proxy_users()
    stats = stats if stats is not None else mtg_multi_stats()
    real_peers = real_peers if real_peers is not None else []
    stats_users = stats.get('users') if isinstance(stats, dict) else {}
    if not isinstance(stats_users, dict):
        stats_users = {}
    activity = load_mtg_activity()
    records = activity.setdefault('users', {})
    enabled_users = [u for u in users if u.get('enabled', True) and u.get('telegram_enabled', True) and not is_user_block_active(u)]
    enabled_ids = {str(u.get('id')) for u in enabled_users}

    for user in users:
        uid = str(user.get('id') or '')
        if not uid:
            continue
        rec = records.setdefault(uid, {})
        rec.update({
            'user_id': uid,
            'username': user.get('username') or '',
            'name': user.get('name') or user.get('username') or uid,
            'secret_hash': secret_fingerprint(user.get('telegram_secret') or ''),
            'enabled': bool(user.get('enabled', True)),
            'telegram_enabled': bool(user.get('telegram_enabled', True)),
        })

    saw_any_stats = False
    for user in enabled_users:
        uid = str(user.get('id') or '')
        username = str(user.get('username') or '')
        su = stats_users.get(username) or stats_users.get(uid)
        if not isinstance(su, dict):
            continue
        saw_any_stats = True
        rec = records.setdefault(uid, {})
        connections = mtg_stat_number(su, 'connections', 'active_connections', 'connection_count', 'conn', 'conns', 'clients', 'active')
        bytes_in = mtg_stat_number(su, 'bytes_in', 'bytesIn', 'in', 'rx', 'download', 'recv', 'received')
        bytes_out = mtg_stat_number(su, 'bytes_out', 'bytesOut', 'out', 'tx', 'upload', 'sent')
        requests = mtg_stat_number(su, 'requests', 'request_count', 'hits', 'accepted', 'total')
        stat_last_seen = mtg_stat_seen_ts(su.get('last_seen') or su.get('lastSeen') or su.get('updated_at') or su.get('updatedAt'))
        counter_total = connections + bytes_in + bytes_out + requests
        prev_total = int(rec.get('counter_total') or 0)
        prev_stat_seen = float(rec.get('stat_last_seen') or 0)
        counter_changed = counter_total > prev_total
        stat_seen_changed = stat_last_seen > prev_stat_seen
        explicit_active = connections > 0 or bool(su.get('online') or su.get('active') or su.get('connected'))
        confirmed_activity = explicit_active or counter_changed or stat_seen_changed
        if confirmed_activity:
            rec.setdefault('first_seen', now)
            rec['last_seen'] = now
            rec['online_until'] = now + MTG_ONLINE_GRACE_SECONDS
            rec['activity_events'] = int(rec.get('activity_events') or 0) + (1 if counter_changed or stat_seen_changed or explicit_active else 0)
        rec.update({
            'counter_total': max(prev_total, counter_total),
            'stat_last_seen': max(prev_stat_seen, stat_last_seen),
            'active_connections': max(0, connections),
            'bytes_in': max(int(rec.get('bytes_in') or 0), bytes_in),
            'bytes_out': max(int(rec.get('bytes_out') or 0), bytes_out),
            'requests': max(int(rec.get('requests') or 0), requests),
            'raw_keys': sorted(list(su.keys()))[:40],
            'last_stats_at': now,
            'identity_source': 'mtg_multi_stats',
        })

    # Fallback: if mtg-multi stats are empty but exactly one Telegram user is enabled
    # and there are TCP peers on the MTProto port, mark that user as active. We still
    # do not guess among multiple users, because IP/NAT/mobile networks make this unsafe.
    if not saw_any_stats and len(enabled_users) == 1 and real_peers:
        user = enabled_users[0]
        uid = str(user.get('id') or '')
        rec = records.setdefault(uid, {})
        rec.setdefault('first_seen', now)
        rec.update({
            'last_seen': now,
            'online_until': now + MTG_ONLINE_GRACE_SECONDS,
            'active_connections': len(real_peers),
            'identity_source': 'single_user_tcp_fallback',
            'activity_events': int(rec.get('activity_events') or 0) + 1,
        })

    # Mark disabled users as not online, but keep their historical last_seen.
    for uid, rec in records.items():
        if uid not in enabled_ids:
            rec['online_until'] = 0
            rec['active_connections'] = 0

    save_mtg_activity(activity)
    return activity


def telegram_presence_for_user(user, activity=None):
    activity = activity or load_mtg_activity()
    records = activity.get('users') if isinstance(activity, dict) else {}
    rec = records.get(str(user.get('id') or '')) if isinstance(records, dict) else None
    presence = mtg_user_presence_from_record(rec)
    presence.update({
        'activity_events': int((rec or {}).get('activity_events') or 0),
        'active_connections': int((rec or {}).get('active_connections') or 0),
        'identity_source': (rec or {}).get('identity_source') or '',
        'bytes_in': int((rec or {}).get('bytes_in') or 0),
        'bytes_out': int((rec or {}).get('bytes_out') or 0),
    })
    return presence


def mtg_status():
    users = users_safe()
    running = bool(mtg_process and mtg_process.poll() is None)
    stats = mtg_multi_stats() if running else {'users': {}}
    real_peers = list_tcp_peers_for_local_port(telegram_shared_port()) if running else []
    activity = update_mtg_activity_from_stats(stats=stats, users=load_proxy_users(), real_peers=real_peers) if running else load_mtg_activity()
    stats_users = stats.get('users') if isinstance(stats, dict) else {}
    online_count = 0
    recent_count = 0
    for u in users:
        u['telegram_port'] = telegram_shared_port()
        u['telegram_running'] = running and u.get('enabled', True) and u.get('telegram_enabled', True) and not is_user_block_active(u)
        su = stats_users.get(u.get('username')) if isinstance(stats_users, dict) else None
        if isinstance(su, dict):
            u['telegram_stats'] = su
        presence = telegram_presence_for_user(u, activity)
        # If service is stopped, never show users as online, but keep last_seen/history.
        if not running or not u.get('telegram_running'):
            if presence.get('status') == 'online':
                presence['status'] = 'offline'
                presence['online'] = False
                presence['status_text'] = 'оффлайн'
        if presence.get('status') == 'online':
            online_count += 1
        if presence.get('recent'):
            recent_count += 1
        u['telegram_presence'] = presence
    primary = users[0] if users else {}
    return {
        'enabled': bool(load_telegram_settings().get('enabled', False)),
        'running': running,
        'running_count': 1 if running else 0,
        'online_users': online_count,
        'recent_users': recent_count,
        'activity_updated_at': activity.get('updated_at') if isinstance(activity, dict) else 0,
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


def _mtg_stat_int(item, *keys):
    """Read an integer counter from mtg-multi stats with tolerant key names."""
    if not isinstance(item, dict):
        return 0
    for key in keys:
        try:
            val = item.get(key)
            if val is not None and val != '':
                return int(val)
        except Exception:
            continue
    return 0


def active_mtg_users_from_stats():
    """Return MTProto users considered online by secret activity.

    We do not rely solely on the instant connection counter because Telegram
    may reconnect/sleep and mtg-multi builds expose different stats. Activity
    is updated from stats and kept online for MTG_ONLINE_GRACE_SECONDS.
    """
    real_peers = list_tcp_peers_for_local_port(telegram_shared_port())
    stats = mtg_multi_stats()
    users = load_proxy_users()
    activity = update_mtg_activity_from_stats(stats=stats, users=users, real_peers=real_peers)
    records = activity.get('users') if isinstance(activity, dict) else {}
    result = []
    for user in users:
        if not user.get('enabled', True) or not user.get('telegram_enabled', True) or is_user_block_active(user):
            continue
        rec = records.get(str(user.get('id') or '')) if isinstance(records, dict) else None
        presence = mtg_user_presence_from_record(rec)
        if presence.get('status') != 'online':
            continue
        result.append({
            'user': user,
            'username': user.get('username') or user.get('id') or 'unknown',
            'connections': max(1, int((rec or {}).get('active_connections') or 1)),
            'bytes_in': int((rec or {}).get('bytes_in') or 0),
            'bytes_out': int((rec or {}).get('bytes_out') or 0),
            'last_seen': presence.get('last_seen') or 0,
            'raw': {'identity_source': (rec or {}).get('identity_source') or 'mtproto_activity'},
        })
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
    sources = {s.get("id"): s for s in (load_server_sources().get("sources") or []) if isinstance(s, dict)}
    def allowed(srv):
        src = sources.get(srv.get("source_id")) or {}
        return bool(src.get("enabled", True)) and bool(src.get("use_in_auto", True)) and bool(srv.get("enabled", True))
    primary = [s.get("tag") for s in normalized if s.get("tag") and int(s.get("priority", 50)) < 100 and allowed(s)]
    if primary:
        return primary
    return [s.get("tag") for s in normalized if s.get("tag") and allowed(s)]



def server_identity_keys(server):
    """Stable keys used to preserve UI metadata across subscription refreshes."""
    if not isinstance(server, dict):
        return []
    keys = []
    tag = str(server.get("tag") or "").strip()
    if tag:
        keys.append("tag:" + tag)
    server_addr = str(server.get("server") or "").strip()
    port = str(server.get("server_port") or "").strip()
    uuid = str(server.get("uuid") or "").strip()
    typ = str(server.get("type") or "").strip()
    if server_addr and port:
        keys.append("endpoint:" + "|".join([typ, server_addr, port, uuid]))
        keys.append("hostport:" + "|".join([server_addr, port]))
    return keys


def preserve_server_metadata(existing_servers, new_servers):
    """Keep manual priority/order and UI-only data after subscription update."""
    index = {}
    for srv in existing_servers or []:
        if not isinstance(srv, dict):
            continue
        for key in server_identity_keys(srv):
            index.setdefault(key, srv)
    preserved_keys = ["priority", "enabled", "note", "last_ping", "last_ping_at"]
    merged = []
    for srv in new_servers or []:
        item = dict(srv)
        old = None
        for key in server_identity_keys(item):
            if key in index:
                old = index[key]
                break
        if old:
            for k in preserved_keys:
                if k in old and old.get(k) not in [None, ""]:
                    item[k] = old.get(k)
        merged.append(item)
    return merged

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
        "source_id",
        "source_name",
        "source_type",
        "source_url",
        "source_created_at",
        "source_updated_at",
        "imported_at",
        "updated_at",
        "internal_tag",
    ]:
        item.pop(key, None)
    return item




def clean_server_for_config(server):
    """Compatibility helper used by subscription JSON export.

    Keeps subscription JSON readable and valid for sing-box by removing
    UI/backend-only management fields.
    """
    return server_to_singbox_outbound(server)

def load_server_pings():
    data = read_json(data_path("server_pings.json"), {})
    return data if isinstance(data, dict) else {}


def save_server_pings(data):
    write_json(data_path("server_pings.json"), data if isinstance(data, dict) else {})



def short_hash(value, prefix="src"):
    raw = str(value or "")
    return f"{prefix}_" + hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:12]


def mask_url_for_ui(url):
    url = str(url or "")
    if not url:
        return ""
    try:
        u = urllib.parse.urlparse(url)
        host = u.netloc or u.path.split('/')[0]
        return f"{u.scheme}://{host}/****" if u.scheme and host else url[:32] + "..."
    except Exception:
        return url[:32] + "..."


def source_name_from_url(url):
    try:
        host = urllib.parse.urlparse(str(url or "")).netloc
        return host or "VPN-подписка"
    except Exception:
        return "VPN-подписка"


def default_server_sources():
    now = time.time()
    return {"version": 1, "updated_at": now, "sources": [
        {"id": "legacy", "name": "Ранее добавленные серверы", "type": "legacy", "enabled": True, "use_in_auto": True, "created_at": now, "updated_at": now, "servers_count": 0},
        {"id": "manual", "name": "Ручные серверы", "type": "manual", "enabled": True, "use_in_auto": True, "created_at": now, "updated_at": now, "servers_count": 0},
        {"id": "json_import", "name": "JSON импорт", "type": "json", "enabled": True, "use_in_auto": True, "created_at": now, "updated_at": now, "servers_count": 0},
    ]}


def load_server_sources():
    data = read_json(SERVER_SOURCES_FILE, None)
    if not isinstance(data, dict):
        data = default_server_sources()
    sources = data.get("sources")
    if not isinstance(sources, list):
        sources = []
    base = {s["id"]: s for s in default_server_sources()["sources"]}
    for src in sources:
        if isinstance(src, dict) and src.get("id"):
            sid = str(src.get("id"))
            if sid in base:
                base[sid].update(src)
            else:
                base[sid] = dict(src)
    data["sources"] = list(base.values())
    data["version"] = int(data.get("version") or 1)
    data["updated_at"] = float(data.get("updated_at") or time.time())
    return data


def save_server_sources(data):
    if not isinstance(data, dict):
        data = default_server_sources()
    data["updated_at"] = time.time()
    write_json(SERVER_SOURCES_FILE, data)
    return data


def upsert_server_source(source_id, name=None, source_type=None, url=None, enabled=True, use_in_auto=True, extra=None):
    data = load_server_sources()
    now = time.time()
    src = None
    for item in data.get("sources", []):
        if item.get("id") == source_id:
            src = item
            break
    if src is None:
        src = {"id": source_id, "created_at": now, "servers_count": 0}
        data.setdefault("sources", []).append(src)
    src.update({
        "name": name or src.get("name") or source_id,
        "type": source_type or src.get("type") or "manual",
        "enabled": bool(src.get("enabled", enabled)),
        "use_in_auto": bool(src.get("use_in_auto", use_in_auto)),
        "updated_at": now,
    })
    if url:
        src["url"] = url
        src["url_masked"] = mask_url_for_ui(url)
    if isinstance(extra, dict):
        src.update(extra)
    save_server_sources(data)
    return src


def source_for_import(mode, url="", name=""):
    mode = str(mode or "json")
    now = time.time()
    if mode == "url":
        sid = short_hash(url, "sub")
        src = upsert_server_source(sid, name or source_name_from_url(url), "subscription", url=url, extra={"last_import_at": now})
        return src
    if mode == "json":
        return upsert_server_source("json_import", name or "JSON импорт", "json", extra={"last_import_at": now})
    if mode in {"vless", "links"}:
        return upsert_server_source("manual_links", name or "Импорт ссылок", "links", extra={"last_import_at": now})
    return upsert_server_source("manual", name or "Ручные серверы", "manual", extra={"last_import_at": now})


def annotate_servers_with_source(servers, source):
    if not isinstance(source, dict):
        source = upsert_server_source("legacy", "Ранее добавленные серверы", "legacy")
    now = time.time()
    result = []
    for srv in servers or []:
        if not isinstance(srv, dict):
            continue
        item = dict(srv)
        item["source_id"] = source.get("id") or "legacy"
        item["source_name"] = source.get("name") or "Ранее добавленные серверы"
        item["source_type"] = source.get("type") or "legacy"
        if source.get("url"):
            item["source_url"] = source.get("url")
        item.setdefault("imported_at", now)
        item["updated_at"] = now
        result.append(item)
    return result


def normalize_server_source_fields(servers):
    data = load_server_sources()
    by_id = {str(s.get("id")): s for s in data.get("sources", []) if isinstance(s, dict) and s.get("id")}
    legacy = by_id.get("legacy") or upsert_server_source("legacy", "Ранее добавленные серверы", "legacy")
    changed = False
    normalized = []
    for srv in servers or []:
        if not isinstance(srv, dict):
            continue
        item = dict(srv)
        sid = str(item.get("source_id") or "legacy")
        src = by_id.get(sid)
        if not src:
            src = legacy if sid == "legacy" else upsert_server_source(sid, item.get("source_name") or sid, item.get("source_type") or "unknown", url=item.get("source_url"))
            by_id[sid] = src
        for key, val in [("source_id", src.get("id")), ("source_name", src.get("name")), ("source_type", src.get("type"))]:
            if item.get(key) != val:
                item[key] = val
                changed = True
        if src.get("url") and item.get("source_url") != src.get("url"):
            item["source_url"] = src.get("url")
            changed = True
        normalized.append(item)
    sync_server_sources(normalized, save=True)
    return normalized, changed


def server_sources_summary(servers=None):
    servers = servers if servers is not None else read_json(data_path("servers.json"), [])
    data = load_server_sources()
    counts = {}
    tags = {}
    for srv in servers or []:
        if not isinstance(srv, dict):
            continue
        sid = str(srv.get("source_id") or "legacy")
        counts[sid] = counts.get(sid, 0) + 1
        tags.setdefault(sid, []).append(srv.get("tag"))
    out = []
    for src in data.get("sources", []):
        if not isinstance(src, dict):
            continue
        item = dict(src)
        item["servers_count"] = counts.get(src.get("id"), 0)
        item["server_tags"] = [t for t in tags.get(src.get("id"), []) if t]
        out.append(item)
    out.sort(key=lambda x: (str(x.get("type") or ""), str(x.get("name") or "")))
    return {"sources": out, "updated_at": data.get("updated_at"), "count": sum(counts.values())}


def sync_server_sources(servers=None, save=False):
    servers = servers if servers is not None else read_json(data_path("servers.json"), [])
    data = load_server_sources()
    counts = {}
    for srv in servers or []:
        if isinstance(srv, dict):
            sid = str(srv.get("source_id") or "legacy")
            counts[sid] = counts.get(sid, 0) + 1
    seen = {s.get("id"): s for s in data.get("sources", []) if isinstance(s, dict)}
    for sid in list(counts):
        if sid not in seen:
            data.setdefault("sources", []).append({"id": sid, "name": sid, "type": "unknown", "enabled": True, "use_in_auto": True, "created_at": time.time()})
    for src in data.get("sources", []):
        if isinstance(src, dict):
            src["servers_count"] = counts.get(src.get("id"), 0)
            src.setdefault("enabled", True)
            src.setdefault("use_in_auto", True)
            src.setdefault("updated_at", time.time())
    if save:
        save_server_sources(data)
    return data


def prune_server_sources():
    servers = read_json(data_path("servers.json"), [])
    sync_server_sources(servers, save=True)
    return {"ok": True, "sources": server_sources_summary(servers)}


def clean_server_related_state(removed_tags):
    removed = {str(x) for x in removed_tags if x}
    if not removed:
        return {"removed": []}
    pings = load_server_pings()
    for tag in list(pings.keys()):
        if tag in removed:
            pings.pop(tag, None)
    save_server_pings(pings)
    sub = load_subscription_servers()
    if isinstance(sub, dict) and isinstance(sub.get("servers"), list):
        before = len(sub.get("servers") or [])
        sub["servers"] = [s for s in sub.get("servers") or [] if not (isinstance(s, dict) and str(s.get("tag")) in removed)]
        if len(sub["servers"]) != before:
            sub["count"] = len(sub["servers"])
            sub["updated_at"] = time.time()
            write_json(SUBSCRIPTION_SERVERS_FILE, sub)
    return {"removed": sorted(removed)}


def delete_servers_by_tags(tags):
    remove = {str(t) for t in tags if t}
    servers = load_servers()
    kept = [s for s in servers if str(s.get("tag")) not in remove]
    removed = [s.get("tag") for s in servers if str(s.get("tag")) in remove]
    if removed:
        save_servers(kept)
        clean_server_related_state(removed)
        sync_server_sources(kept, save=True)
    return {"servers": kept, "removed": removed, "sources": server_sources_summary(kept)}

def load_servers():
    path = data_path("servers.json")
    if not path.exists():
        options = load_options()
        raw = str(options.get("servers_json", "[]")).strip()
        servers = []
        if raw and raw != "[]":
            try:
                src = upsert_server_source("config_servers", "Серверы из конфигурации add-on", "config")
                servers = annotate_servers_with_source(parse_servers_payload(raw)["servers"], src)
                log("SERVERS_INIT", "OK", f"Imported {len(servers)} servers from add-on configuration")
            except Exception as e:
                log("SERVERS_INIT", "ERROR", f"Failed to import servers_json: {e}")
        if not servers and DEFAULT_SERVERS_FILE.exists():
            src = upsert_server_source("defaults", "Серверы по умолчанию", "defaults")
            servers = annotate_servers_with_source(read_json(DEFAULT_SERVERS_FILE, []), src)
            log("SERVERS_INIT", "OK", f"Loaded {len(servers)} servers from defaults")
        write_json(path, sort_servers_for_display(servers))
    servers = read_json(path, [])
    normalized = sort_servers_for_display(normalize_subscription_tags(servers))
    normalized, source_changed = normalize_server_source_fields(normalized)
    if normalized != servers or source_changed:
        write_json(path, normalized)
    sync_server_sources(normalized, save=True)
    return normalized


def save_servers(servers):
    normalized = sort_servers_for_display(servers)
    normalized, _ = normalize_server_source_fields(normalized)
    backup_path = data_path(f"servers.backup.{int(time.time())}.json")
    current = read_json(data_path("servers.json"), None)
    if current is not None:
        write_json(backup_path, current)
        prune_server_backup_files()
    write_json(data_path("servers.json"), normalized)
    sync_server_sources(normalized, save=True)


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


def load_client_sessions():
    return read_json(data_path("client_sessions.json"), {"summary": {}, "sessions": []})


def normalize_client_sessions(items):
    if not isinstance(items, dict):
        items = {"summary": {}, "sessions": []}
    if not isinstance(items.get("summary"), dict):
        items["summary"] = {}
    if not isinstance(items.get("sessions"), list):
        items["sessions"] = []
    return items


def prune_client_sessions(items, now=None):
    """Keep client history bounded like logs: last 30 days or 2000 latest session rows.

    Active sessions are always preserved. Summary is rebuilt from the retained
    sessions so stale clients do not live forever in client_sessions.json.
    """
    now = float(now or time.time())
    items = normalize_client_sessions(items)
    sessions = [s for s in items.get("sessions", []) if isinstance(s, dict)]
    cutoff = now - CLIENT_HISTORY_RETENTION_SECONDS

    kept = []
    for s in sessions:
        started = float(s.get("started_at") or s.get("last_seen") or 0)
        ended = s.get("ended_at")
        is_active = not ended
        if is_active or started >= cutoff:
            kept.append(s)

    active_kept = [s for s in kept if not s.get("ended_at")]
    closed_kept = [s for s in kept if s.get("ended_at")]
    active_kept.sort(key=lambda x: float(x.get("last_seen") or x.get("started_at") or 0), reverse=True)
    closed_kept.sort(key=lambda x: float(x.get("started_at") or 0), reverse=True)
    remaining = max(0, CLIENT_HISTORY_MAX_SESSIONS - len(active_kept))
    kept = active_kept + closed_kept[:remaining]
    kept.sort(key=lambda x: float(x.get("started_at") or 0), reverse=True)

    rebuilt = {}
    for s in sorted(kept, key=lambda x: float(x.get("started_at") or 0)):
        key = str(s.get("key") or "")
        if not key:
            continue
        started = float(s.get("started_at") or 0)
        last_seen = float(s.get("last_seen") or s.get("ended_at") or started or 0)
        ended = s.get("ended_at")
        duration = int(s.get("duration_seconds") or max(0, last_seen - started))
        sm = rebuilt.setdefault(key, {
            "key": key,
            "first_seen": started or last_seen or now,
            "last_seen": last_seen or started or now,
            "sessions_count": 0,
            "total_online_seconds": 0,
            "last_services": [],
            "last_status": "offline",
        })
        sm["sessions_count"] = int(sm.get("sessions_count") or 0) + 1
        sm["first_seen"] = min(float(sm.get("first_seen") or started or now), started or now)
        sm["last_seen"] = max(float(sm.get("last_seen") or 0), last_seen or started or 0)
        if ended:
            sm["total_online_seconds"] = int(sm.get("total_online_seconds") or 0) + max(0, duration)
        else:
            sm["active_session_id"] = s.get("id")
            sm["last_status"] = "online"
            sm["last_session_started_at"] = started
        for field in ["ip", "display_ip", "username", "registered_user_id", "registered_name"]:
            if s.get(field):
                sm[field] = s.get(field)
        services = sorted(set((sm.get("last_services") or []) + [str(x) for x in (s.get("services") or []) if x]))
        sm["last_services"] = services
        sm["last_connections"] = max(int(sm.get("last_connections") or 0), int(s.get("connections_max") or s.get("last_connections") or 0))
        if not ended and sm.get("last_status") != "online":
            sm["last_status"] = "offline"

    items["sessions"] = kept
    items["summary"] = rebuilt
    items["retention"] = {
        "days": int(CLIENT_HISTORY_RETENTION_SECONDS // 86400),
        "max_sessions": CLIENT_HISTORY_MAX_SESSIONS,
        "pruned_at": now,
        "sessions_count": len(kept),
    }
    return items


def save_client_sessions(items):
    write_json(data_path("client_sessions.json"), prune_client_sessions(items))


def clear_client_sessions():
    data = {
        "summary": {},
        "sessions": [],
        "retention": {
            "days": int(CLIENT_HISTORY_RETENTION_SECONDS // 86400),
            "max_sessions": CLIENT_HISTORY_MAX_SESSIONS,
            "cleared_at": time.time(),
            "sessions_count": 0,
        },
    }
    write_json(data_path("client_sessions.json"), data)
    return data


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


def normalize_manual_traffic_sources(traffic):
    sources = traffic.get("manual_sources") if isinstance(traffic, dict) else []
    if not isinstance(sources, list):
        sources = []
    clean = []
    for item in sources:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        clean.append({
            "id": str(item.get("id") or secrets.token_hex(6)),
            "name": name,
            "limit_bytes": max(0, int(item.get("limit_bytes") or 0)),
            "used_bytes": max(0, int(item.get("used_bytes") or 0)),
            "note": str(item.get("note") or ""),
            "created_at": float(item.get("created_at") or time.time()),
            "updated_at": float(item.get("updated_at") or time.time()),
        })
    return clean


def save_manual_traffic_source(payload):
    traffic = load_traffic()
    sources = normalize_manual_traffic_sources(traffic)
    source_id = str(payload.get("id") or "").strip()
    name = str(payload.get("name") or "").strip()
    if not name:
        raise ValueError("Название источника трафика не указано")
    now = time.time()
    item = {
        "id": source_id or secrets.token_hex(6),
        "name": name,
        "limit_bytes": max(0, int(payload.get("limit_bytes") or 0)),
        "used_bytes": max(0, int(payload.get("used_bytes") or 0)),
        "note": str(payload.get("note") or ""),
        "created_at": now,
        "updated_at": now,
    }
    replaced = False
    for i, old in enumerate(sources):
        if source_id and str(old.get("id")) == source_id:
            item["created_at"] = float(old.get("created_at") or now)
            sources[i] = item
            replaced = True
            break
    if not replaced:
        sources.append(item)
    traffic["manual_sources"] = sources
    save_traffic(traffic)
    return sources


def delete_manual_traffic_source(source_id):
    source_id = str(source_id or "").strip()
    traffic = load_traffic()
    sources = [x for x in normalize_manual_traffic_sources(traffic) if str(x.get("id")) != source_id]
    traffic["manual_sources"] = sources
    save_traffic(traffic)
    return sources


def load_client_limits():
    return read_json(data_path("client_limits.json"), {})


def save_client_limits(items):
    write_json(data_path("client_limits.json"), items if isinstance(items, dict) else {})


def monthly_key(ts=None):
    return time.strftime("%Y-%m", time.localtime(ts or time.time()))


def client_monthly_usage(key):
    # Current implementation provides monitoring limits; historical per-client
    # accounting can be extended later without changing the public API.
    return 0


def client_limit_payload(key):
    limits = load_client_limits()
    item = limits.get(key) or {}
    limit_gb = float(item.get("monthly_limit_gb") or 0)
    used = int(item.get("used_bytes") or client_monthly_usage(key))
    limit_bytes = int(limit_gb * 1024 * 1024 * 1024) if limit_gb > 0 else 0
    return {
        "monthly_limit_gb": limit_gb,
        "limit_bytes": limit_bytes,
        "used_bytes": used,
        "left_bytes": max(0, limit_bytes - used) if limit_bytes else 0,
        "period": item.get("period") or monthly_key(),
        "updated_at": item.get("updated_at") or 0,
        "enabled": bool(limit_bytes),
    }


def sanitize_subscription_info(info):
    info = dict(info or {})
    # Older builds could store a non-critical JSON probe error even when the
    # subscription was successfully parsed later as Clash/VLESS/base64.
    if info.get("status") == "ok" and int(info.get("servers_count") or 0) > 0:
        filtered = []
        for e in info.get("errors") or []:
            s = str(e)
            if "JSON: Expecting value" in s:
                continue
            filtered.append(e)
        info["errors"] = filtered
    return info


def load_subscription_info():
    base = {
        "url": "",
        "status": "not_loaded",
        "message": "Подписка ещё не обновлялась",
        "updated_at": 0,
        "user_agent": "",
        "content_type": "",
        "source": "",
        "servers_count": 0,
        "traffic": {},
        "errors": [],
    }
    value = read_json(SUBSCRIPTION_INFO_FILE, {})
    if isinstance(value, dict):
        base.update(value)
    clean = sanitize_subscription_info(base)
    if clean != base:
        try:
            write_json(SUBSCRIPTION_INFO_FILE, clean)
        except Exception:
            pass
    return clean


def save_subscription_info(info):
    info = sanitize_subscription_info(dict(info or {}))
    info["updated_at"] = time.time()
    write_json(SUBSCRIPTION_INFO_FILE, info)
    return info


def save_subscription_servers(servers, source_url=""):
    items = []
    for srv in servers or []:
        if isinstance(srv, dict):
            items.append(clean_server_for_config(dict(srv)))
    payload = {
        "updated_at": int(time.time()),
        "source_url": source_url or "",
        "count": len(items),
        "servers": items,
    }
    write_json(SUBSCRIPTION_SERVERS_FILE, payload)
    return payload


def load_subscription_servers():
    data = read_json(SUBSCRIPTION_SERVERS_FILE, {"updated_at": 0, "source_url": "", "count": 0, "servers": []})
    # v1.19.1: old installations may have an empty subscription_servers.json,
    # while the real imported VPN servers are already stored in servers.json.
    # Do not show [] in the UI in that case; expose a readable fallback JSON.
    if not isinstance(data, dict):
        data = {"updated_at": 0, "source_url": "", "count": 0, "servers": []}
    servers = data.get("servers") if isinstance(data.get("servers"), list) else []
    if servers:
        data["count"] = int(data.get("count") or len(servers))
        return data
    fallback = []
    try:
        fallback = [clean_server_for_config(dict(s)) for s in (load_servers() or []) if isinstance(s, dict)]
    except Exception as e:
        log("SERVERS", "WARN", f"Subscription JSON fallback failed: {e}")
        fallback = []
    if fallback:
        return {
            "updated_at": int(data.get("updated_at") or 0),
            "source_url": data.get("source_url") or "fallback: current servers.json",
            "count": len(fallback),
            "servers": fallback,
            "fallback": True,
        }
    data["count"] = 0
    data["servers"] = []
    return data



def convert_subscription_url_to_json(url, save=True):
    url = str(url or "").strip()
    if not url:
        raise ValueError("URL подписки не указан")
    parsed = fetch_and_parse_subscription(url, timeout=30)
    info = save_subscription_info(parsed.get("subscription_info") or {})
    servers = parsed.get("servers") or []
    if not servers:
        return {"ok": False, "servers": [], "count": 0, "errors": parsed.get("errors", []), "subscription_info": info}
    payload = save_subscription_servers(servers, url) if save else {
        "updated_at": int(time.time()),
        "source_url": url,
        "count": len(servers),
        "servers": [clean_server_for_config(dict(s)) for s in servers if isinstance(s, dict)],
    }
    settings = load_settings()
    settings["subscription_url"] = url
    save_settings(settings)
    return {"ok": True, **payload, "errors": parsed.get("errors", []), "subscription_info": info}

def priority_profile_from_value(value):
    try:
        p = int(value)
    except Exception:
        p = 50
    if p < 70:
        return {"id": "primary", "name": "Приоритетный", "description": "участвует в auto первым", "priority": p}
    if p < 100:
        return {"id": "standard", "name": "Обычный", "description": "участвует в auto после приоритетных", "priority": p}
    if p < 190:
        return {"id": "reserve", "name": "Резервный", "description": "не участвует в auto, доступен вручную", "priority": p}
    if p < 260:
        return {"id": "ru_reserve", "name": "Российский/резервный", "description": "держать ниже зарубежных, использовать вручную/как крайний резерв", "priority": p}
    return {"id": "manual_only", "name": "Только вручную", "description": "исключён из auto", "priority": p}


def priority_value_from_profile(profile, current=50):
    profile = str(profile or "").strip().lower()
    mapping = {
        "primary": 50,
        "standard": 80,
        "reserve": 150,
        "ru_reserve": 200,
        "manual_only": 300,
    }
    if profile in mapping:
        return mapping[profile]
    try:
        return max(1, min(999, int(current)))
    except Exception:
        return 50


def parse_subscription_userinfo(value):
    value = str(value or "").strip()
    if not value:
        return {}
    # Common format: upload=123; download=456; total=789; expire=1712345678
    result = {}
    for part in re.split(r"[;,&]", value):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower().replace("-", "_")
        v = v.strip().strip('"\'')
        if k == "totl":
            k = "total"
        if k in ["upload", "download", "total", "expire"]:
            try:
                result[k] = int(float(v))
            except Exception:
                pass
    upload = int(result.get("upload") or 0)
    download = int(result.get("download") or 0)
    total = int(result.get("total") or 0)
    used = upload + download
    result["used"] = used
    if total > 0:
        result["remaining"] = max(total - used, 0)
        result["percent_used"] = round(min(100.0, used * 100.0 / total), 2)
    else:
        result["remaining"] = None
        result["percent_used"] = None
    if result.get("expire"):
        try:
            result["expire_iso"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(result["expire"])))
        except Exception:
            result["expire_iso"] = ""
    return result


def extract_subscription_userinfo_from_text(text):
    text = str(text or "")
    patterns = [
        r"(?im)^\s*#?\s*subscription-userinfo\s*[:=]\s*(.+)$",
        r"(?im)^\s*#?\s*subscription_userinfo\s*[:=]\s*(.+)$",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            parsed = parse_subscription_userinfo(m.group(1))
            if parsed:
                parsed["source"] = "body"
                return parsed
    return {}


def normalize_header_map(headers):
    result = {}
    try:
        items = headers.items()
    except Exception:
        items = []
    for k, v in items:
        result[str(k).lower()] = str(v)
    return result


def fetch_url_with_headers(url, user_agent, timeout=25):
    headers = {
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return {
                "text": raw.decode("utf-8", errors="ignore"),
                "headers": normalize_header_map(resp.headers),
                "content_type": resp.headers.get("Content-Type", ""),
                "status": getattr(resp, "status", 200),
                "user_agent": user_agent,
                "via": "direct",
            }
    except Exception as direct_error:
        # Fallback via local HTTP proxy: useful when subscription host is unavailable directly.
        try:
            options = load_options()
            http_port = int(options.get("http_proxy_port", 2081))
            proxy_url = f"http://127.0.0.1:{http_port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                return {
                    "text": raw.decode("utf-8", errors="ignore"),
                    "headers": normalize_header_map(resp.headers),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "status": getattr(resp, "status", 200),
                    "user_agent": user_agent,
                    "via": "local_proxy",
                }
        except Exception as proxy_error:
            raise RuntimeError(f"direct: {direct_error}; via local proxy: {proxy_error}")


def extract_subscription_traffic(headers, text):
    h = normalize_header_map(headers)
    for key in ["subscription-userinfo", "subscription_userinfo", "profile-update-interval"]:
        if key in h and key != "profile-update-interval":
            parsed = parse_subscription_userinfo(h.get(key))
            if parsed:
                parsed["source"] = "http_header"
                return parsed
    parsed = extract_subscription_userinfo_from_text(text)
    if parsed:
        return parsed
    return {}


def parse_yaml_scalar(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if value[0:1] in ['"', "'"] and value[-1:] == value[0]:
        return value[1:-1]
    low = value.lower()
    if low in ["true", "yes", "on"]:
        return True
    if low in ["false", "no", "off"]:
        return False
    try:
        if re.match(r"^-?\d+$", value):
            return int(value)
    except Exception:
        pass
    return value


def split_inline_map_items(s):
    parts, cur, depth, quote = [], "", 0, ""
    for ch in s:
        if quote:
            cur += ch
            if ch == quote:
                quote = ""
            continue
        if ch in ['"', "'"]:
            quote = ch; cur += ch; continue
        if ch in "[{":
            depth += 1; cur += ch; continue
        if ch in "]}":
            depth -= 1; cur += ch; continue
        if ch == "," and depth == 0:
            parts.append(cur.strip()); cur = ""; continue
        cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def parse_inline_yaml_map(value):
    value = str(value or "").strip()
    if value.startswith("{") and value.endswith("}"):
        value = value[1:-1]
    result = {}
    for part in split_inline_map_items(value):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = k.strip().strip('"\'')
        v = v.strip()
        if v.startswith("{") and v.endswith("}"):
            result[k] = parse_inline_yaml_map(v)
        else:
            result[k] = parse_yaml_scalar(v)
    return result


def parse_clash_yaml_vless(text):
    lines = str(text or "").splitlines()
    proxies_start = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*proxies\s*:\s*$", line):
            proxies_start = i + 1
            break
    if proxies_start is None:
        return []
    blocks = []
    current = None
    current_nested = None
    for raw in lines[proxies_start:]:
        if re.match(r"^\S", raw) and not raw.strip().startswith("-"):
            # next top-level section
            if current:
                blocks.append(current)
            break
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        m = re.match(r"^\s*-\s*(.*)$", raw)
        if m:
            if current:
                blocks.append(current)
            current = {}
            current_nested = None
            rest = m.group(1).strip()
            if rest.startswith("{"):
                current.update(parse_inline_yaml_map(rest))
            elif rest and ":" in rest:
                k, v = rest.split(":", 1)
                current[k.strip()] = parse_yaml_scalar(v.strip())
            continue
        if current is None:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip(); v = v.strip()
        if not v:
            current[k] = {}
            current_nested = k
        else:
            if current_nested and indent >= 6:
                if not isinstance(current.get(current_nested), dict):
                    current[current_nested] = {}
                current[current_nested][k] = parse_yaml_scalar(v)
            else:
                current[k] = parse_inline_yaml_map(v) if v.startswith("{") else parse_yaml_scalar(v)
                current_nested = None
    if current:
        blocks.append(current)
    result = []
    for i, item in enumerate(blocks):
        typ = str(item.get("type") or "").lower()
        if typ != "vless":
            continue
        server = item.get("server") or item.get("address")
        uuid = item.get("uuid") or item.get("id")
        if not server or not uuid:
            continue
        tag = safe_tag(item.get("name") or item.get("tag") or f"VLESS-{i}", f"VLESS-{i}")
        out = {"type": "vless", "tag": tag, "server": str(server), "server_port": int(item.get("port") or 443), "uuid": str(uuid), "packet_encoding": "xudp"}
        if item.get("flow"):
            out["flow"] = str(item.get("flow"))
        tls_enabled = bool(item.get("tls") is True or str(item.get("tls")).lower() == "true" or item.get("servername") or item.get("sni") or item.get("reality-opts") or item.get("reality_opts"))
        if tls_enabled:
            server_name = item.get("servername") or item.get("sni") or item.get("server_name") or server
            fp = item.get("client-fingerprint") or item.get("fingerprint") or item.get("fp") or "chrome"
            tls = {"enabled": True, "server_name": str(server_name), "utls": {"enabled": True, "fingerprint": str(fp)}}
            ro = item.get("reality-opts") or item.get("reality_opts") or {}
            if isinstance(ro, dict):
                pk = ro.get("public-key") or ro.get("public_key") or ro.get("pbk")
                sid = ro.get("short-id") or ro.get("short_id") or ro.get("sid") or ""
                if pk:
                    tls["reality"] = {"enabled": True, "public_key": str(pk), "short_id": str(sid)}
            out["tls"] = tls
        result.append(out)
    return result


def fetch_and_parse_subscription(url, timeout=25):
    user_agents = [
        "ClashMetaForAndroid/2.10",
        "clash-verge/v2.0",
        "HiddifyNext/2.0",
        "v2rayN/6.0",
        "sing-box/1.11",
        "NekoBox/1.3",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "ProxyOtBorisa/1.19",
    ]
    attempts = []
    best = None
    for ua in user_agents:
        try:
            fetched = fetch_url_with_headers(url, ua, timeout=timeout)
            text = fetched.get("text") or ""
            traffic = extract_subscription_traffic(fetched.get("headers") or {}, text)
            parsed = parse_servers_payload(text)
            attempt = {
                "user_agent": ua,
                "via": fetched.get("via"),
                "content_type": fetched.get("content_type"),
                "status": fetched.get("status"),
                "servers": len(parsed.get("servers") or []),
                "traffic_found": bool(traffic),
                "errors": parsed.get("errors") or [],
            }
            attempts.append(attempt)
            if parsed.get("servers"):
                # If a later parser (vless/base64/Clash YAML) successfully decoded the
                # subscription, earlier probe errors such as "JSON: Expecting value"
                # are not real user-facing errors. Keep them only in attempts for
                # diagnostics, but do not show them as subscription errors.
                visible_errors = []
                info = {
                    "url": url,
                    "status": "ok",
                    "message": f"Подписка загружена: {len(parsed['servers'])} сервер(ов)",
                    "user_agent": ua,
                    "via": fetched.get("via"),
                    "content_type": fetched.get("content_type"),
                    "servers_count": len(parsed["servers"]),
                    "traffic": traffic,
                    "traffic_source": traffic.get("source") if isinstance(traffic, dict) else "",
                    "attempts": attempts,
                    "errors": visible_errors,
                }
                log("SERVERS", "SUBSCRIPTION_OK", f"Subscription parsed: {len(parsed['servers'])} server(s), traffic: {'yes' if traffic else 'no'}", actor="system", action="subscription_parse", target=url, extra={"user_agent": ua, "via": fetched.get("via"), "content_type": fetched.get("content_type")})
                return {"servers": normalize_subscription_tags(parsed["servers"]), "errors": visible_errors, "subscription_info": info}
            if traffic and not best:
                best = {"traffic": traffic, "fetched": fetched, "parsed": parsed, "ua": ua}
        except Exception as e:
            attempts.append({"user_agent": ua, "error": str(e), "servers": 0})
            log_exception("SERVERS", "subscription_fetch", e, actor="system", target=url, extra={"user_agent": ua})
    traffic = best.get("traffic") if best else {}
    info = {
        "url": url,
        "status": "error",
        "message": "Серверы в подписке не найдены. Провайдер мог отдать HTML/пустой ответ/нестандартный формат.",
        "traffic": traffic or {},
        "traffic_source": traffic.get("source") if isinstance(traffic, dict) else "",
        "servers_count": 0,
        "attempts": attempts,
        "errors": [a.get("error") or "; ".join(a.get("errors") or []) for a in attempts if a.get("error") or a.get("errors")],
    }
    log("SERVERS", "SUBSCRIPTION_ERROR", "Subscription parsed with no servers", actor="system", action="subscription_parse", target=url, extra={"errors": info.get("errors"), "attempts": attempts})
    return {"servers": [], "errors": info["errors"], "subscription_info": info}

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


COUNTRY_EMOJI = {"🇩🇪":"DE","🇳🇱":"NL","🇺🇸":"US","🇷🇺":"RU","🇸🇪":"SE","🇦🇹":"AT","🇫🇮":"FI","🇫🇷":"FR","🇬🇧":"GB","🇬🇧":"GB","🇹🇷":"TR"}

def infer_country_code_from_text(*parts):
    raw = " ".join(str(x or "") for x in parts)
    for emoji, code in COUNTRY_EMOJI.items():
        if emoji in raw:
            return code
    s = raw.lower()
    rules = [
        ("DE", ["germany", "german", "deutsch", "de.", "-de", "_de", " de "]),
        ("NL", ["netherlands", "holland", "nl.", "-nl", "_nl", " nl "]),
        ("US", ["usa", "united states", "us.", "-us", "_us", " us "]),
        ("RU", ["russia", "russian", "ru.", "-ru", "_ru", " ru "]),
        ("SE", ["sweden", "se.", "-se", "_se", " se "]),
        ("AT", ["austria", "at.", "-at", "_at", " at "]),
        ("FI", ["finland", "fi.", "-fi", "_fi", " fi "]),
        ("FR", ["france", "fr.", "-fr", "_fr", " fr "]),
        ("GB", ["uk.", "gb.", "-uk", "-gb", "united kingdom", "great britain"]),
    ]
    padded = " " + s + " "
    for code, needles in rules:
        if any(n in padded or n in s for n in needles):
            return code
    # Часто подписки называют хосты коротко: de1.example.com, nl-2..., us_03...
    # Старый вариант это не всегда распознавал и оставлял Vless-1/Vless-2.
    for code in ["DE", "NL", "US", "RU", "SE", "AT", "FI", "FR", "GB", "TR"]:
        c = code.lower()
        if re.search(rf"(^|[^a-z]){c}[0-9._-]", s) or re.search(rf"[._-]{c}([._-]|$)", s):
            return code
    return "VPN"

def normalize_subscription_tags(servers):
    counts = {}
    used = set()
    out = []
    for srv in servers or []:
        if not isinstance(srv, dict):
            continue
        item = dict(srv)
        typ = str(item.get("type") or "vless").lower()
        old_tag = str(item.get("tag") or "")
        # Preserve user-friendly country tags; replace generic vless1/vless-1 tags.
        generic = bool(re.fullmatch(r"(?i)vless[-_ ]?\d+|vless|server[-_ ]?\d+", old_tag.strip()))
        if not old_tag or generic:
            code = infer_country_code_from_text(old_tag, item.get("server"), item.get("tls", {}).get("server_name") if isinstance(item.get("tls"), dict) else "")
            counts[code] = counts.get(code, 0) + 1
            tag = f"{code}{counts[code]}-{typ}"
            while tag in used:
                counts[code] += 1
                tag = f"{code}{counts[code]}-{typ}"
            item["tag"] = tag
        used.add(str(item.get("tag")))
        out.append(item)
    return out

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



def parse_trojan_uri(uri, index=0):
    uri = uri.strip()
    if not uri.lower().startswith("trojan://"):
        raise ValueError("Это не trojan:// ссылка")
    parsed = urllib.parse.urlparse(uri)
    password = urllib.parse.unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 443
    query = urllib.parse.parse_qs(parsed.query)
    q = {k: v[-1] for k, v in query.items() if v}
    tag = safe_tag(parsed.fragment or q.get("remarks") or q.get("name") or f"TROJAN-{index}", f"TROJAN-{index}")
    outbound = {"type": "trojan", "tag": tag, "server": server, "server_port": int(port), "password": password}
    security = (q.get("security") or "tls").lower()
    if security != "none":
        sni = q.get("sni") or q.get("serverName") or q.get("peer") or server
        fp = q.get("fp") or q.get("fingerprint") or "chrome"
        outbound["tls"] = {"enabled": True, "server_name": sni, "utls": {"enabled": True, "fingerprint": fp}}
    transport_type = (q.get("type") or q.get("transport") or "tcp").lower()
    if transport_type == "ws":
        transport = {"type": "ws"}
        if q.get("path"):
            transport["path"] = q.get("path")
        if q.get("host"):
            transport["headers"] = {"Host": q.get("host")}
        outbound["transport"] = transport
    elif transport_type == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName") or q.get("service_name") or ""}
    return outbound


def decode_b64_piece(value):
    value = str(value or "").strip()
    padding = "=" * (-len(value) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder((value + padding).encode()).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return ""


def parse_shadowsocks_uri(uri, index=0):
    uri = uri.strip()
    if not uri.lower().startswith(("ss://", "shadowsocks://")):
        raise ValueError("Это не ss:// ссылка")
    if uri.lower().startswith("shadowsocks://"):
        uri = "ss://" + uri.split("://", 1)[1]
    raw = uri[5:]
    frag = ""
    if "#" in raw:
        raw, frag = raw.split("#", 1)
    tag = safe_tag(urllib.parse.unquote(frag) or f"SS-{index}", f"SS-{index}")
    parsed = urllib.parse.urlparse("ss://" + raw)
    userinfo = ""
    server = parsed.hostname or ""
    port = parsed.port or 0
    if parsed.username:
        userinfo = urllib.parse.unquote(parsed.username)
        maybe = decode_b64_piece(userinfo)
        if maybe and ":" in maybe:
            userinfo = maybe
    else:
        decoded = decode_b64_piece(raw.split("?", 1)[0])
        if decoded and "@" in decoded:
            creds, endpoint = decoded.rsplit("@", 1)
            userinfo = creds
            if ":" in endpoint:
                server, port_s = endpoint.rsplit(":", 1)
                port = int(port_s)
    if not userinfo or ":" not in userinfo:
        raise ValueError("Не удалось прочитать method/password")
    method, password = userinfo.split(":", 1)
    if not server or not port:
        raise ValueError("Не удалось прочитать server/port")
    return {"type": "shadowsocks", "tag": tag, "server": server, "server_port": int(port), "method": method, "password": password}


def parse_vmess_uri(uri, index=0):
    uri = uri.strip()
    if not uri.lower().startswith("vmess://"):
        raise ValueError("Это не vmess:// ссылка")
    raw = uri.split("://", 1)[1].strip()
    decoded = decode_b64_piece(raw)
    if not decoded:
        raise ValueError("Не удалось декодировать vmess base64")
    data = json.loads(decoded)
    tag = safe_tag(data.get("ps") or data.get("name") or f"VMESS-{index}", f"VMESS-{index}")
    server = data.get("add") or data.get("server") or ""
    port = int(data.get("port") or 443)
    uuid = data.get("id") or data.get("uuid") or ""
    outbound = {"type": "vmess", "tag": tag, "server": server, "server_port": port, "uuid": uuid, "security": data.get("scy") or data.get("security") or "auto"}
    net = str(data.get("net") or data.get("type") or "tcp").lower()
    tls_mode = str(data.get("tls") or "").lower()
    sni = data.get("sni") or data.get("host") or server
    if tls_mode in ["tls", "reality"]:
        outbound["tls"] = {"enabled": True, "server_name": sni, "utls": {"enabled": True, "fingerprint": data.get("fp") or "chrome"}}
    if net == "ws":
        transport = {"type": "ws"}
        if data.get("path"):
            transport["path"] = data.get("path")
        if data.get("host"):
            transport["headers"] = {"Host": data.get("host")}
        outbound["transport"] = transport
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": data.get("path") or data.get("serviceName") or ""}
    return outbound

def try_decode_base64(text):
    stripped = re.sub(r"\s+", "", text.strip())
    if not stripped:
        return text
    # Do not try to decode YAML/JSON/HTML as base64. Python's base64 decoder
    # may otherwise ignore non-base64 chars and return garbage.
    if not re.fullmatch(r"[A-Za-z0-9_+/=-]+", stripped):
        return text
    padding = "=" * (-len(stripped) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder((stripped + padding).encode()).decode("utf-8", errors="ignore")
            if any(x in decoded.lower() for x in ["vless://", "vmess://", "trojan://", "ss://", "shadowsocks://"]) or decoded.strip().startswith(('{','[')) or re.search(r"(?m)^\s*proxies\s*:", decoded):
                return decoded
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
        return validate_servers(normalize_subscription_tags(servers))
    except Exception as e:
        errors.append(f"JSON: {e}")
    format_errors = list(errors)
    errors = []
    known_link_markers = ["vless://", "vmess://", "trojan://", "ss://", "shadowsocks://"]
    candidate = text if any(x in text.lower() for x in known_link_markers) else try_decode_base64(text)
    link_patterns = [
        (r"vless://[^\s\r\n]+", parse_vless_uri),
        (r"vmess://[^\s\r\n]+", parse_vmess_uri),
        (r"trojan://[^\s\r\n]+", parse_trojan_uri),
        (r"(?:ss|shadowsocks)://[^\s\r\n]+", parse_shadowsocks_uri),
    ]
    servers = []
    idx = 0
    for pattern, parser in link_patterns:
        for link in re.findall(pattern, candidate, flags=re.IGNORECASE):
            try:
                servers.append(parser(link, idx))
                idx += 1
            except Exception as e:
                errors.append(f"{link[:60]}...: {e}")
    if servers:
        validated = validate_servers(normalize_subscription_tags(servers))
        validated["errors"].extend(errors)
        return validated
    # Clash YAML subscriptions often return a proxies: list instead of raw links.
    try:
        clash_servers = parse_clash_yaml_vless(candidate)
        if clash_servers:
            validated = validate_servers(normalize_subscription_tags(clash_servers))
            validated["errors"].extend(errors)
            return validated
        errors.append("Clash YAML: vless proxies not found")
    except Exception as e:
        errors.append(f"Clash YAML: {e}")
    return {"servers": [], "errors": (format_errors + errors) or ["Не найден JSON, Clash YAML или vless:// ссылки"]}


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
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyOtBorisa/1.19"})
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
        try:
            tol = int(options.get("urltest_tolerance", 5))
        except Exception:
            tol = 5
        # В старых установках в options мог остаться tolerance=50. Для наших задач это слишком
        # широко: auto может держаться за средний сервер, хотя уже есть явно более быстрый.
        if tol == 50:
            tol = 5
        outbounds.append({
            "type": "urltest",
            "tag": "auto",
            "outbounds": auto_tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": options.get("urltest_interval", "2m"),
            "tolerance": max(0, tol),
            "interrupt_exist_connections": True,
        })
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
        "log": {"level": options.get("log_level", "warn"), "timestamp": True},
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


def write_config(path=None, cfg=None):
    cfg = cfg or make_singbox_config()
    target = Path(path or SINGBOX_CONFIG)
    write_json(target, cfg)
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


def validate_generated_singbox_config(cfg=None):
    cfg = cfg or make_singbox_config()
    tmp = TMP_DIR / f"sing-box.check.{os.getpid()}.{secrets.token_hex(4)}.json"
    write_json(tmp, cfg)
    try:
        proc = subprocess.run([SINGBOX_BIN, "check", "-c", str(tmp)], capture_output=True, text=True, timeout=20)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "sing-box check failed").strip()
            raise RuntimeError(err[-4000:])
        return {"ok": True, "config": str(tmp)}
    except FileNotFoundError:
        raise RuntimeError("sing-box binary not found")
    except subprocess.TimeoutExpired:
        raise RuntimeError("sing-box check timeout")
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def start_singbox(prechecked_config=None):
    global singbox_process, last_error, SINGBOX_STARTED_AT
    cfg = prechecked_config or make_singbox_config()
    write_config(SINGBOX_CONFIG, cfg)
    log("SING_BOX", "START", f"Starting sing-box with {SINGBOX_CONFIG}")
    singbox_process = subprocess.Popen([SINGBOX_BIN, "run", "-c", str(SINGBOX_CONFIG)], stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(0.8)
    if singbox_process.poll() is not None:
        last_error = f"sing-box exited with code {singbox_process.returncode}"
        log("SING_BOX", "ERROR", last_error)
        raise RuntimeError(last_error)
    last_error = ""
    SINGBOX_STARTED_AT = time.time()
    try:
        shutil.copyfile(SINGBOX_CONFIG, LAST_GOOD_SINGBOX_CONFIG)
    except Exception as e:
        log_exception("SING_BOX", "LAST_GOOD_SAVE", e, target=str(LAST_GOOD_SINGBOX_CONFIG))
    apply_power_selectors()
    start_mtg()


def validate_singbox_config():
    """Generate and validate config without replacing the running process."""
    return validate_generated_singbox_config(make_singbox_config())


def restart_singbox():
    with lock:
        new_cfg = make_singbox_config()
        validate_generated_singbox_config(new_cfg)
        old_cfg = None
        if SINGBOX_CONFIG.exists():
            old_cfg = read_json(SINGBOX_CONFIG, None)
        stop_mtg()
        stop_singbox()
        try:
            start_singbox(prechecked_config=new_cfg)
        except Exception as e:
            log_exception("SING_BOX", "ROLLBACK", e, target="new_config")
            rollback_cfg = None
            if LAST_GOOD_SINGBOX_CONFIG.exists():
                rollback_cfg = read_json(LAST_GOOD_SINGBOX_CONFIG, None)
            rollback_cfg = rollback_cfg or old_cfg
            if rollback_cfg:
                try:
                    start_singbox(prechecked_config=rollback_cfg)
                    log("SING_BOX", "ROLLBACK", "Returned to last good sing-box config", action="singbox_rollback")
                except Exception as rb:
                    log_exception("SING_BOX", "ROLLBACK_FAILED", rb)
            raise


def restart_singbox_background(reason="background apply"):
    """Apply sing-box config without blocking Home Assistant Ingress response."""
    def worker():
        try:
            log("BACKEND", "APPLY", f"Applying sing-box in background: {reason}", actor="ui", action="singbox_background_apply")
            restart_singbox()
            log("BACKEND", "APPLY", f"Background sing-box apply completed: {reason}", actor="ui", action="singbox_background_apply")
        except Exception as e:
            log_exception("BACKEND", "APPLY", e, actor="ui", action="singbox_background_apply", target=reason)
    threading.Thread(target=worker, name="singbox-background-apply", daemon=True).start()


def restart_mtg_background(reason="background mtproto apply"):
    def worker():
        try:
            log("BACKEND", "APPLY", f"Applying MTProto in background: {reason}", actor="ui", action="mtg_background_apply")
            restart_mtg()
            log("BACKEND", "APPLY", f"Background MTProto apply completed: {reason}", actor="ui", action="mtg_background_apply")
        except Exception as e:
            log_exception("BACKEND", "APPLY", e, actor="ui", action="mtg_background_apply", target=reason)
    threading.Thread(target=worker, name="mtg-background-apply", daemon=True).start()


def apply_services_background(reason="background apply", singbox=True, mtproto=False):
    def worker():
        try:
            log("BACKEND", "APPLY", f"Applying services in background: {reason}", actor="ui", action="services_background_apply", extra={"singbox": singbox, "mtproto": mtproto})
            if singbox:
                restart_singbox()
            elif mtproto:
                restart_mtg()
            log("BACKEND", "APPLY", f"Background services apply completed: {reason}", actor="ui", action="services_background_apply")
        except Exception as e:
            log_exception("BACKEND", "APPLY", e, actor="ui", action="services_background_apply", target=reason)
    threading.Thread(target=worker, name="services-background-apply", daemon=True).start()

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
    """Return Telegram MTProto clients identified by registered secret when possible.

    Important: a Telegram client can reach MTProto through another registered
    SOCKS/HTTP client, for example a router. In that case sing-box sees the
    transport connection as the router, but the real MTProto identity is the
    Telegram secret accepted by mtg-multi. Therefore /stats is authoritative;
    TCP peers are only a diagnostic fallback and must not override the secret.
    """
    real_peers = list_tcp_peers_for_local_port(telegram_shared_port())
    active_stats = active_mtg_users_from_stats()

    # Authoritative path: mtg-multi stats by configured secret/user name.
    if active_stats:
        peer_count = len(real_peers)
        result = []
        for stat in active_stats:
            user = stat.get('user') or {}
            username = stat.get('username') or user.get('username') or user.get('id') or 'unknown'
            result.append({
                'ip': 'telegram:' + str(username),
                'display_ip': 'Telegram secret: ' + str(username),
                'source': 'telegram_mtproto',
                'identity_method': 'telegram_secret',
                'user_id': user.get('id') or '',
                'username': user.get('username') or str(username),
                'user_name': user.get('name') or str(username),
                'connections': max(1, int(stat.get('connections') or 1)),
                'bytes_in': int(stat.get('bytes_in') or 0),
                'bytes_out': int(stat.get('bytes_out') or 0),
                'last_seen': stat.get('last_seen') or '',
                'telegram_port': telegram_shared_port(),
                'tcp_peer_count': peer_count,
                'unmapped': False,
            })
        return result

    # Fallback only: stats are empty/unavailable. Do not guess user by IP,
    # because mobile Internet/NAT/router transport makes that unreliable.
    result = []
    for peer in real_peers:
        peer['user_id'] = ''
        peer['username'] = ''
        peer['user_name'] = ''
        peer['connections'] = 1
        peer['bytes_in'] = 0
        peer['bytes_out'] = 0
        peer['last_seen'] = ''
        peer['telegram_port'] = telegram_shared_port()
        peer['identity_method'] = 'tcp_peer_fallback'
        peer['unmapped'] = True
        result.append(peer)
    return result


def normalize_endpoint_host(value):
    """Normalize a host or host:port value for local endpoint comparison."""
    host = str(value or '').strip().lower()
    if not host:
        return ''
    if '://' in host:
        try:
            host = urllib.parse.urlparse(host).hostname or host
        except Exception:
            pass
    if host.startswith('[') and ']' in host:
        return host[1:host.find(']')].lower()
    if ':' in host and host.count(':') == 1:
        host = host.rsplit(':', 1)[0]
    return host.strip().strip('.')


def own_mtproto_hosts():
    """Known public hosts that point to this add-on MTProto endpoint."""
    hosts = {'localhost', '127.0.0.1', '::1'}
    tg = load_telegram_settings()
    for val in [tg.get('public_host'), tg.get('host'), tg.get('server')]:
        h = normalize_endpoint_host(val)
        if h:
            hosts.add(h)
    for user in load_proxy_users():
        for key in ['public_host', 'telegram_public_host']:
            h = normalize_endpoint_host(user.get(key))
            if h:
                hosts.add(h)
    return hosts


def is_connection_to_own_mtproto(conn):
    """True when a SOCKS/HTTP client is only transporting a Telegram MTProto
    connection to this same add-on.

    Example: phone -> router SOCKS client -> this server:MTProto. The transport
    belongs to the router, but the Telegram user must be counted by secret from
    mtg-multi stats. Without this filter the UI falsely shows the router as the
    Telegram user.
    """
    meta = conn.get('metadata') or {}
    try:
        dport = int(meta.get('destinationPort') or meta.get('destination_port') or conn.get('destinationPort') or 0)
    except Exception:
        dport = 0
    if dport != int(telegram_shared_port()):
        return False
    host = normalize_endpoint_host(get_host(conn) or meta.get('destinationIP') or meta.get('destination_ip') or meta.get('host') or meta.get('domain'))
    if not host:
        return False
    return host in own_mtproto_hosts()

def geo_lookup(ip):
    if str(ip or '').startswith('telegram:'):
        return {"country": "Telegram MTProto", "region": "secret", "city": "", "isp": "mtg-multi", "org": "local add-on identity", "asn": "", "timezone": "", "lat": None, "lon": None, "source": "telegram_secret"}
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
    if len(cache) > GEO_CACHE_MAX_RECORDS:
        items = sorted(cache.items(), key=lambda kv: float((kv[1] or {}).get("ts") or 0), reverse=True)[:GEO_CACHE_MAX_RECORDS]
        cache = dict(items)
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



def _history_service_list(item):
    return sorted([str(x) for x in (item.get('services') or []) if x])


def _history_find_session(sessions, session_id):
    for sess in sessions:
        if isinstance(sess, dict) and sess.get('id') == session_id:
            return sess
    return None


def _history_connection_count(item):
    return int(item.get('connections_count') or len(item.get('connections') or []) or item.get('mtproto_connections') or 0)


def _history_destinations(item):
    out = []
    for h in item.get('hosts') or []:
        if h and h != '—':
            out.append(str(h))
    for mh in (item.get('main_hosts') or {}):
        if mh and mh != '—':
            out.append(str(mh))
    return sorted(set(out))[:20]


def _history_routes(item):
    routes = []
    for conn in item.get('connections') or []:
        chain = conn.get('chains') or conn.get('chain') or conn.get('rule') or ''
        if isinstance(chain, list):
            val = ' → '.join([str(x) for x in chain if x])
        else:
            val = str(chain or '')
        if val and val != '—':
            routes.append(val)
    if 'Telegram MTProto' in (item.get('services') or set()):
        routes.append('Telegram MTProto')
    return sorted(set(routes))[:12]


def _history_new_session(key, item, now):
    conns = _history_connection_count(item)
    return {
        'id': f"{key}:{int(now)}:{secrets.token_hex(4)}",
        'key': key,
        'started_at': now,
        'last_seen': now,
        'ended_at': None,
        'duration_seconds': 0,
        'ip': item.get('ip') or '',
        'display_ip': item.get('display_ip') or '',
        'username': item.get('username') or '',
        'registered_user_id': item.get('registered_user_id') or '',
        'registered_name': item.get('registered_name') or '',
        'services': _history_service_list(item),
        'connections_max': conns,
        'last_connections': conns,
        'upload_last': int(item.get('upload') or 0),
        'download_last': int(item.get('download') or 0),
        'status': 'online',
        'destinations': _history_destinations(item),
        'routes': _history_routes(item),
    }


def update_client_session_history(active_grouped, existing_history, now):
    """Persist client online/offline sessions for the audit/history page."""
    data = load_client_sessions()
    summary = data.setdefault('summary', {})
    sessions = data.setdefault('sessions', [])
    if not isinstance(summary, dict):
        summary = {}; data['summary'] = summary
    if not isinstance(sessions, list):
        sessions = []; data['sessions'] = sessions
    active_keys = set(active_grouped.keys())

    for key, item in active_grouped.items():
        old_client = existing_history.get(key, {}) if isinstance(existing_history, dict) else {}
        sm = summary.setdefault(key, {})
        last_seen_before = float(sm.get('last_seen') or old_client.get('last_seen') or 0)
        active_id = sm.get('active_session_id') or ''
        active_session = _history_find_session(sessions, active_id) if active_id else None
        need_new = not active_session or active_session.get('ended_at') or (last_seen_before and now - last_seen_before > SESSION_BREAK_SECONDS)

        if need_new:
            active_session = _history_new_session(key, item, now)
            sessions.append(active_session)
            sm['active_session_id'] = active_session['id']
            sm['sessions_count'] = int(sm.get('sessions_count') or 0) + 1
            sm.setdefault('first_seen', now)
            sm['last_session_started_at'] = now

        services = sorted(set((active_session.get('services') or []) + _history_service_list(item)))
        last_connections = _history_connection_count(item)
        active_session.update({
            'last_seen': now,
            'ended_at': None,
            'duration_seconds': max(0, int(now - float(active_session.get('started_at') or now))),
            'ip': item.get('ip') or active_session.get('ip') or '',
            'display_ip': item.get('display_ip') or active_session.get('display_ip') or '',
            'username': item.get('username') or active_session.get('username') or '',
            'registered_user_id': item.get('registered_user_id') or active_session.get('registered_user_id') or '',
            'registered_name': item.get('registered_name') or active_session.get('registered_name') or '',
            'services': services,
            'last_connections': last_connections,
            'connections_max': max(int(active_session.get('connections_max') or 0), last_connections),
            'upload_last': int(item.get('upload') or 0),
            'download_last': int(item.get('download') or 0),
            'status': 'online',
            'destinations': sorted(set((active_session.get('destinations') or []) + _history_destinations(item)))[:20],
            'routes': sorted(set((active_session.get('routes') or []) + _history_routes(item)))[:12],
        })

        sm.update({
            'key': key,
            'ip': item.get('ip') or sm.get('ip') or '',
            'display_ip': item.get('display_ip') or sm.get('display_ip') or '',
            'username': item.get('username') or sm.get('username') or '',
            'registered_user_id': item.get('registered_user_id') or sm.get('registered_user_id') or '',
            'registered_name': item.get('registered_name') or sm.get('registered_name') or '',
            'last_seen': now,
            'last_services': services,
            'last_status': 'online',
            'total_online_seconds': int(sm.get('total_online_seconds') or 0),
            'last_connections': last_connections,
        })

    for key, sm in list(summary.items()):
        if key in active_keys:
            continue
        active_id = sm.get('active_session_id') or ''
        if not active_id:
            continue
        sess = _history_find_session(sessions, active_id)
        if not sess or sess.get('ended_at'):
            sm.pop('active_session_id', None)
            continue
        old = existing_history.get(key, {}) if isinstance(existing_history, dict) else {}
        end_ts = float(old.get('last_seen') or sess.get('last_seen') or now)
        if end_ts > now:
            end_ts = now
        duration = max(0, int(end_ts - float(sess.get('started_at') or end_ts)))
        sess['last_seen'] = end_ts
        sess['ended_at'] = end_ts
        sess['duration_seconds'] = duration
        sess['status'] = 'offline'
        sm['last_seen'] = end_ts
        sm['last_status'] = 'offline'
        sm['total_online_seconds'] = int(sm.get('total_online_seconds') or 0) + duration
        sm.pop('active_session_id', None)

    sessions.sort(key=lambda x: float(x.get('started_at') or 0), reverse=True)
    data['sessions'] = sessions
    save_client_sessions(data)


def client_history_payload(limit=300):
    data = prune_client_sessions(load_client_sessions())
    save_client_sessions(data)
    summary = data.get('summary') if isinstance(data, dict) else {}
    sessions = data.get('sessions') if isinstance(data, dict) else []
    if not isinstance(summary, dict):
        summary = {}
    if not isinstance(sessions, list):
        sessions = []
    now = time.time()
    session_by_id = {s.get('id'): s for s in sessions if isinstance(s, dict)}
    summaries = []
    for key, sm in summary.items():
        if not isinstance(sm, dict):
            continue
        item = dict(sm)
        active_id = item.get('active_session_id') or ''
        live_extra = 0
        if active_id and active_id in session_by_id and not session_by_id[active_id].get('ended_at'):
            live_extra = max(0, int(now - float(session_by_id[active_id].get('started_at') or now)))
        item['key'] = key
        item['total_online_seconds_live'] = int(item.get('total_online_seconds') or 0) + live_extra
        item['online'] = bool(active_id)
        summaries.append(item)
    safe_sessions = [s for s in sessions if isinstance(s, dict)]
    safe_sessions.sort(key=lambda x: float(x.get('started_at') or 0), reverse=True)
    summaries.sort(key=lambda x: (0 if x.get('online') else 1, -(float(x.get('last_seen') or 0))))
    return {'summary': summaries, 'sessions': safe_sessions[:max(1, min(int(limit or 300), CLIENT_HISTORY_MAX_SESSIONS))], 'updated_at': now, 'retention': data.get('retention') or {'days': int(CLIENT_HISTORY_RETENTION_SECONDS // 86400), 'max_sessions': CLIENT_HISTORY_MAX_SESSIONS}}


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
        if is_connection_to_own_mtproto(conn):
            # Transport-only connection to this add-on's MTProto listener.
            # The real Telegram client is identified separately by secret via mtg-multi stats.
            continue
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
        if peer.get('display_ip'):
            item['display_ip'] = peer.get('display_ip')
        item['mtproto_connections'] = int(item.get('mtproto_connections') or 0) + int(peer.get('connections') or 1)
        item['upload'] += int(peer.get('bytes_in') or 0)
        item['download'] += int(peer.get('bytes_out') or 0)
        item['hosts'].add('Telegram MTProto proxy')
        item.setdefault('main_hosts', {})['telegram'] = item.setdefault('main_hosts', {}).get('telegram', 0) + 1
        item.setdefault('identities', set()).add('service:Telegram MTProto')
        if peer.get('identity_method'):
            item.setdefault('identities', set()).add('identity:' + str(peer.get('identity_method')))
        if peer.get('tcp_peer_count') is not None:
            item.setdefault('identities', set()).add('tcp_peers:' + str(peer.get('tcp_peer_count')))
        if user:
            item.setdefault('identities', set()).add('telegram_user:' + user.get('name', ''))
            item.setdefault('identities', set()).add('telegram_secret_user:' + user.get('username', ''))
            item.setdefault('identities', set()).add('auth_user:' + user.get('username', ''))
        state = peer.get('state') or ('SECRET_IDENTIFIED' if peer.get('identity_method') == 'telegram_secret' else 'UNKNOWN')
        item['tcp_states'][state] = item['tcp_states'].get(state, 0) + 1

    active_keys = set(grouped.keys())
    try:
        update_client_session_history(grouped, history, now)
    except Exception as e:
        log_exception("CLIENT", "history_update", e, actor="backend", target="client_sessions")

    for key, item in grouped.items():
        old = history.get(key, {})
        became_online = not old.get('last_seen') or (now - old.get('last_seen', 0) > SESSION_BREAK_SECONDS)
        history[key] = {
            'key': key,
            'ip': item['ip'],
            'display_ip': item.get('display_ip') or '',
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
            history.pop(key, None)
            continue
        status = 'recent' if old.get('last_seen') and now - old['last_seen'] <= RECENT_CLIENT_SECONDS else 'offline'
        user = users_by_id.get(str(old.get('registered_user_id') or '')) or users_by_name.get(str(old.get('username') or ''))
        grouped[key] = {
            'key': key,
            'ip': ip,
            'display_ip': old.get('display_ip') or '',
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
        if item.get('display_ip'):
            item['display_ip'] = item.get('display_ip')
        item['connections_count'] = len(item.get('connections') or []) + int(item.get('mtproto_connections') or 0)
        item['risk'] = risk_level(item)
        item['registered'] = bool(item.get('registered_user_id')) or bool(item.get('trusted'))
        item['traffic_limit'] = client_limit_payload(key)
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

def numeric_delay(value):
    try:
        if isinstance(value, dict):
            value = value.get("delay")
        if value is None or value == "":
            return None
        value = int(float(value))
        return value if value >= 0 else None
    except Exception:
        return None


def best_ping_tag(results, allowed_tags=None):
    allowed = set(allowed_tags or [])
    best_tag = None
    best_delay = None
    for tag, data in (results or {}).items():
        if allowed and tag not in allowed:
            continue
        delay = numeric_delay(data)
        if delay is None:
            continue
        if best_delay is None or delay < best_delay:
            best_tag = tag
            best_delay = delay
    return best_tag, best_delay


def refresh_auto_after_ping(results=None):
    """Force sing-box urltest to re-evaluate immediately after UI ping.

    Manual ping buttons previously only refreshed numbers in the web UI. sing-box
    still waited for its own urltest interval, which looked like auto ignored the
    better server for several minutes.
    """
    details = {"triggered": False, "best": "", "best_delay": None, "error": ""}
    try:
        proxies = get_proxies()
        current = current_server_info(proxies)
        if current.get("mode") != "auto":
            return details
        tags = auto_server_tags(load_servers())
        best, delay = best_ping_tag(results or load_server_pings(), tags)
        details.update({"best": best or "", "best_delay": delay})
        # Запускаем именно delay у группы auto — это заставляет urltest обновить выбор сейчас,
        # а не ждать очередные 2 минуты. Если API конкретной версии sing-box не даст выбрать
        # best вручную, delay всё равно обновит внутренний результат urltest.
        # Сначала пробуем явно подсказать группе auto лучший сервер.
        # В разных версиях sing-box Clash API это может быть не поддержано,
        # поэтому ошибки не считаем критичными.
        if best:
            try:
                clash_request("PUT", "/proxies/auto", {"name": best}, timeout=5)
            except Exception as e:
                details["error"] = str(e)
        try:
            clash_request("GET", f"/proxies/{urllib.parse.quote('auto')}/delay?timeout=5000&url={urllib.parse.quote('https://www.gstatic.com/generate_204')}", timeout=8)
        except Exception as e:
            details["error"] = (details.get("error") + " | " if details.get("error") else "") + str(e)
        try:
            clash_request("PUT", "/proxies/Proxy", {"name": "auto"}, timeout=5)
        except Exception as e:
            details["error"] = (details.get("error") + " | " if details.get("error") else "") + str(e)
        details["triggered"] = True
        return details
    except Exception as e:
        details["error"] = str(e)
        return details


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


def tcp_connect_latency(host, port=443, timeout=3.0):
    start = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"ok": True, "ms": int((time.time() - start) * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e), "ms": None}


def direct_http_latency(url="https://www.gstatic.com/generate_204", timeout=5.0):
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": server_version})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(1024)
            return {"ok": True, "status": getattr(resp, "status", 0), "ms": int((time.time() - start) * 1000), "url": url}
    except Exception as e:
        return {"ok": False, "error": str(e), "ms": None, "url": url}


def classify_latency(ms):
    try:
        ms = int(ms)
    except Exception:
        return "unknown"
    if ms <= 180:
        return "good"
    if ms <= 350:
        return "ok"
    if ms <= 700:
        return "slow"
    return "bad"


def network_quality_report(names=None, limit=12):
    """Measure real proxy path quality, not only ICMP-like ping.

    Uses sing-box Clash delay endpoint for individual outbounds. This tests the
    HTTP/TCP path through each VLESS/VMess/etc. server to a small 204 URL and is
    closer to what Nintendo/Telegram/browser traffic feel than a raw ping.
    """
    started = time.time()
    servers = load_servers()
    tags = [s.get("tag") for s in sort_servers_for_display(servers) if s.get("tag")]
    if names:
        requested = [str(x) for x in names if str(x) in tags]
    else:
        current = current_server_info(get_proxies())
        requested = []
        if current.get("server") and current.get("server") in tags:
            requested.append(current.get("server"))
        for t in auto_server_tags(servers):
            if t not in requested:
                requested.append(t)
            if len(requested) >= int(limit or 12):
                break
    requested = requested[:max(1, min(int(limit or 12), 30))]

    tests = {
        "direct_tcp_1_1_1_1_443": tcp_connect_latency("1.1.1.1", 443, 3.0),
        "direct_tcp_google_443": tcp_connect_latency("www.gstatic.com", 443, 3.0),
        "direct_http_204": direct_http_latency("https://www.gstatic.com/generate_204", 5.0),
    }
    proxy_tests = []
    for tag in requested:
        item = {"tag": tag, "ok": False, "ms": None, "quality": "unknown", "error": ""}
        try:
            res = clash_request("GET", f"/proxies/{urllib.parse.quote(tag)}/delay?timeout=7000&url={urllib.parse.quote('https://www.gstatic.com/generate_204')}", timeout=9)
            delay = numeric_delay(res)
            item.update({"ok": delay is not None, "ms": delay, "quality": classify_latency(delay), "raw": res})
        except Exception as e:
            item["error"] = str(e)
        proxy_tests.append(item)

    best = None
    for item in proxy_tests:
        if item.get("ok") and item.get("ms") is not None:
            if best is None or int(item["ms"]) < int(best["ms"]):
                best = item
    report = {
        "ok": True,
        "updated_at": time.time(),
        "duration_ms": int((time.time() - started) * 1000),
        "current": current_server_info(get_proxies()),
        "direct": tests,
        "proxy_tests": proxy_tests,
        "best": best or {},
        "note": "Это проверка TCP/HTTP задержки через outbounds sing-box. Она может отличаться от ICMP ping и лучше показывает реальную задержку браузера/Nintendo/Telegram.",
    }
    write_json(NETWORK_QUALITY_FILE, report)
    return report


def load_network_quality_report():
    data = read_json(NETWORK_QUALITY_FILE, {})
    return data if isinstance(data, dict) else {}


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
    server_version = "ProxyOtBorisa/1.22.0"

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
            if path == "/api/health":
                options = load_options()
                singbox_ok = bool(singbox_process and singbox_process.poll() is None)
                mtg = mtg_status()
                boot = get_boot_state()
                return self.send_json({
                    "ok": True,
                    "app": APP_NAME,
                    "version": APP_VERSION,
                    "backend_ready": bool(boot.get("web_ready")),
                    "app_ready": bool(boot.get("app_ready")),
                    "startup": boot,
                    "singbox_running": singbox_ok,
                    "singbox_ready": singbox_ok,
                    "telegram_running": bool(mtg.get("running")),
                    "log_level": options.get("log_level", "warn"),
                    "production_mode": options.get("production_mode", "normal"),
                    "last_error": last_error,
                    "updated_at": time.time(),
                })
            if path == "/api/status":
                boot = get_boot_state()
                options = load_options(); settings = load_settings(); servers = load_servers(); blocked = load_blocked(); proxies = get_proxies(); conns = list(connections_cache.get("items") or []); sec_summary = security_summary(options=options); ru = ((sec_summary.get("country_lists") or {}).get("RU") or {})
                tg_status = mtg_status()
                return self.send_json({"app": APP_NAME, "version": APP_VERSION, "startup": boot, "singbox_running": bool(singbox_process and singbox_process.poll() is None), "last_error": last_error, "telegram": tg_status, "settings": settings, "power": power_summary(settings, tg_status), "vpn": vpn_status(proxies), "subscription_info": load_subscription_info(), "activity": app_activity(), "options": {"http_proxy_port": options["http_proxy_port"], "socks_proxy_port": options["socks_proxy_port"], "telegram_proxy_port": options.get("telegram_proxy_port"), "socks_auth_enabled": options["socks_auth_enabled"], "http_auth_enabled": options["http_auth_enabled"], "proxy_username": options.get("proxy_username"), "log_level": options.get("log_level", "warn"), "production_mode": options.get("production_mode", "normal")}, "security": sec_summary, "security_status": {"autoban_enabled": bool(load_security().get("autoban_enabled")), "country_filter_enabled": bool(load_security().get("country_filter_enabled")), "ru_cidrs": int(ru.get("count") or 0), "http_auth_enabled": bool(options["http_auth_enabled"]), "socks_auth_enabled": bool(options["socks_auth_enabled"])}, "monitor": {"interval_seconds": MONITOR_INTERVAL_SECONDS, "autoban_interval_seconds": AUTOBAN_CHECK_INTERVAL_SECONDS, "connections_updated_at": connections_cache.get("updated_at", 0), "last_autoban_at": connections_cache.get("last_autoban_at", 0)}, "servers_count": len(servers), "blocked_count": len(blocked), "connections_count": len(conns), "current": current_server_info(proxies), "routing": routing_summary(), "proxies": proxies})
            if path == "/api/system/check":
                return self.send_json(system_check_report())
            if path == "/api/maintenance":
                return self.send_json(maintenance_status())
            if path == "/api/network/quality":
                cached = load_network_quality_report()
                if not cached:
                    cached = {"ok": True, "updated_at": 0, "proxy_tests": [], "direct": {}, "note": "Проверка ещё не запускалась."}
                return self.send_json(cached)
            if path == "/api/routing/test":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                return self.send_json(route_test_domain((q.get("q") or [""])[0]))
            if path == "/api/backup":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                include_events = str((q.get("include_events") or ["0"])[0]).lower() in ["1", "true", "yes"]
                include_secrets = str((q.get("include_secrets") or ["1"])[0]).lower() in ["1", "true", "yes"]
                return self.send_json(export_backup(include_events=include_events, include_secrets=include_secrets))
            if path == "/api/proxies":
                return self.send_json(get_proxies())
            if path == "/api/connections":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                conns = get_monitored_connections(force=(qs.get("force", ["0"])[0] == "1"), run_autoban=True); return self.send_json({"connections": conns, "updated_at": connections_cache.get("updated_at", 0)})
            if path == "/api/clients":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                conns = get_monitored_connections(force=(qs.get("force", ["0"])[0] == "1"), run_autoban=True); return self.send_json({"clients": build_clients(conns), "updated_at": connections_cache.get("updated_at", 0)})
            if path == "/api/clients/history":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                try:
                    limit = int((qs.get("limit") or ["300"])[0])
                except Exception:
                    limit = 300
                return self.send_json(client_history_payload(limit=limit))
            if path == "/api/servers":
                settings = load_settings(); servers = load_servers()
                enriched = []
                for srv in servers:
                    item = dict(srv)
                    item["priority_profile"] = priority_profile_from_value(item.get("priority", 50))
                    enriched.append(item)
                return self.send_json({"servers": enriched, "sources": server_sources_summary(servers).get("sources", []), "subscription_url": settings.get("subscription_url", ""), "subscription_info": load_subscription_info(), "subscription_json": load_subscription_servers(), "pings": load_server_pings(), "auto_tags": auto_server_tags(servers)})
            if path == "/api/server_sources":
                return self.send_json(server_sources_summary(load_servers()))
            if path == "/api/servers/subscription_json":
                data = load_subscription_servers()
                return self.send_json({"ok": True, **data, "json_text": json.dumps(data.get("servers") or [], ensure_ascii=False, indent=2)})
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
            if path == "/api/ports":
                return self.send_json(ports_summary())
            if path == "/api/traffic":
                tr = load_traffic()
                tr["manual_sources"] = normalize_manual_traffic_sources(tr)
                sub = load_subscription_info()
                tr["subscription_info"] = sub
                traffic = sub.get("traffic") or {}
                if traffic.get("total"):
                    tr["source"] = "subscription"
                    tr["limit_bytes"] = int(traffic.get("total") or 0)
                    tr["used_bytes"] = int(traffic.get("upload") or 0) + int(traffic.get("download") or 0)
                    tr["expire_at"] = traffic.get("expire") or 0
                    tr["provider_updated_at"] = sub.get("updated_at") or 0
                else:
                    tr["source"] = "local"
                return self.send_json(tr)
            if path == "/api/client_limits":
                return self.send_json({"limits": load_client_limits()})
            if path == "/api/logs":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                limit = (qs.get("limit") or [200])[-1]
                category = (qs.get("category") or ["all"])[-1]
                return self.send_json({"events": get_events(limit, category), "category": category, "limit": limit, "max_retention": EVENT_LOG_LIMIT})
            if path == "/api/audit":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                limit = (qs.get("limit") or [500])[-1]
                category = (qs.get("category") or ["all"])[-1]
                return self.send_json({"events": get_events(limit, category), "category": category, "limit": limit, "max_retention": EVENT_LOG_LIMIT})
            if path.startswith("/api/geo/"):
                ip = urllib.parse.unquote(path.split("/api/geo/", 1)[1]); return self.send_json(geo_lookup(ip))
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            log_exception("API", "GET", e, actor="ui", target=getattr(self, "path", ""), extra={"method": "GET"})
            self.send_json({"error": str(e)}, 500)

    def do_POST(self):
        try:
            path = normalize_request_path(self.path)
            body = self.read_body()
            ensure_not_safe_mode_for_mutation(path)
            if path == "/api/options/logging":
                level = normalize_log_level(body.get("log_level"))
                runtime = save_runtime_options({"log_level": level})
                applied = False
                if bool(body.get("apply", True)):
                    validate_singbox_config()
                    restart_singbox_background("log_level_change")
                    applied = True
                log("SETTINGS", "LOG_LEVEL", f"sing-box log level set to {level}", actor="ui", action="log_level", target=level, extra={"applied": applied})
                return self.send_json({"ok": True, "runtime_options": runtime, "log_level": level, "apply_background": applied})
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
                    restart_mtg_background('power_telegram')
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
                    apply_services_background('ports_save', singbox=True, mtproto=True)
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
                    restart_mtg_background('telegram_' + str(action))
                log("TELEGRAM", "CHANGE", f"Telegram proxy action={action}", actor="ui", action="telegram_" + str(action), extra={"enabled": tg.get("enabled"), "port": tg.get("port")})
                return self.send_json({"ok": True, "telegram": mtg_status(), "power": power_summary(settings, mtg_status()), "apply_background": True})
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
                    restart_singbox_background('user_create')
                    return self.send_json({'ok': True, 'users': users_safe(), 'apply_background': True})
                if action == 'update':
                    uid = str(body.get('id') or body.get('username') or '')
                    changed = False
                    for u in users:
                        if str(u.get('id')) == uid or str(u.get('username')) == uid:
                            for key in ['name','username','password','enabled','trusted','socks_enabled','http_enabled','telegram_enabled','telegram_port','telegram_secret','telegram_front_domain','public_host','notes','group','expires_at']:
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
                    restart_singbox_background('user_update')
                    return self.send_json({'ok': True, 'users': users_safe(), 'apply_background': True})
                if action == 'regenerate_password':
                    uid = str(body.get('id') or '')
                    for u in users:
                        if str(u.get('id')) == uid:
                            u['password'] = random_token(20)
                            u['updated_at'] = time.time()
                            break
                    users = save_proxy_users(users)
                    log('USERS', 'PASSWORD', 'Regenerated proxy client password', actor='ui', action='user_password', target=uid)
                    restart_singbox_background('user_password')
                    return self.send_json({'ok': True, 'users': users_safe(), 'apply_background': True})
                if action == 'regenerate_secret':
                    uid = str(body.get('id') or '')
                    return self.send_json(rotate_user_access(uid, rotate_telegram=True))
                if action == 'rotate_access':
                    uid = str(body.get('id') or '')
                    return self.send_json(rotate_user_access(uid, rotate_password=bool(body.get('password', True)), rotate_telegram=bool(body.get('telegram', True)), rotate_username=bool(body.get('username', False))))
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
                    close_all_connections()
                    restart_singbox_background('user_'+action)
                    return self.send_json({'ok': True, 'users': users_safe(), 'apply_background': True})
                raise ValueError('Неизвестное действие users')
            if path == "/api/routing/test":
                return self.send_json(route_test_domain(body.get("q") or body.get("domain") or body.get("value") or ""))
            if path == "/api/network/quality":
                return self.send_json(network_quality_report(names=body.get("names") or None, limit=body.get("limit") or 12))
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
                auto_refresh = refresh_auto_after_ping(results) if body.get("auto_apply", True) else {"triggered": False}
                log("PING", "OK", f"Ping test completed for {len(names)} server(s)", actor="ui", action="ping", extra={"count": len(names), "auto_refresh": auto_refresh})
                return self.send_json({"ok": True, "results": results, "checked_at": checked_at, "auto_refresh": auto_refresh})
            if path == "/api/connections/close_all":
                return self.send_json({"ok": close_all_connections()})
            if path == "/api/clients/disconnect":
                ip = body.get("ip")
                conns = get_connections_raw(); closed = 0
                for c in conns:
                    if get_source_ip(c) == ip and close_connection(get_conn_id(c)):
                        closed += 1
                return self.send_json({"ok": True, "closed": closed})
            if path == "/api/clients/history/clear":
                data = clear_client_sessions()
                log("CLIENT", "HISTORY_CLEAR", "Client connection history cleared", actor="ui", action="client_history_clear")
                return self.send_json({"ok": True, "history": data, "message": "История подключений очищена."})
            if path == "/api/audit/clear":
                result = clear_audit_events()
                log("AUDIT", "CLEAR", "Audit journal cleared", actor="ui", action="audit_clear")
                return self.send_json({"ok": True, "message": "Аудит-журнал очищен.", **result})
            if path == "/api/maintenance/prune":
                cleanup_results = prune_all_data_files()
                log("MAINTENANCE", "PRUNE", "Maintenance pruning completed", actor="ui", action="maintenance_prune", extra={"results": cleanup_results})
                return self.send_json({"ok": True, "cleanup": cleanup_results, "maintenance": maintenance_status(), "message": "Очистка по правилам хранения выполнена."})
            if path == "/api/maintenance/clear_file":
                key = str(body.get("key") or "")
                meta = DATA_REGISTRY.get(key)
                if not meta or not meta.get("maintenance"):
                    raise ValueError("Неизвестный файл обслуживания")
                if key in {"users", "settings", "runtime_options", "runtime_ports", "servers", "routing", "security", "telegram", "migrations"}:
                    raise ValueError("Этот файл нельзя очищать вручную из обслуживания")
                path_to_clear = Path(meta["path"])
                default = {} if key in {"mtproto_activity", "client_sessions", "network_quality"} else []
                if key == "mtproto_activity":
                    default = {"version": 1, "updated_at": time.time(), "users": {}, "retention": {"cleared_at": time.time()}}
                elif key == "client_sessions":
                    default = clear_client_sessions()
                    log("MAINTENANCE", "CLEAR_FILE", f"Maintenance file cleared: {key}", actor="ui", action="maintenance_clear_file", target=key)
                    return self.send_json({"ok": True, "maintenance": maintenance_status(), "message": "Файл очищен."})
                write_json(path_to_clear, default)
                log("MAINTENANCE", "CLEAR_FILE", f"Maintenance file cleared: {key}", actor="ui", action="maintenance_clear_file", target=key)
                return self.send_json({"ok": True, "maintenance": maintenance_status(), "message": "Файл очищен."})
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
                        restart_mtg_background('client_delete_mtproto'); mtg_restarted = True
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
                    restart_singbox_background('blocklist_add')
                return self.send_json({"ok": True, "blocked": items, "apply_background": True})
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
                restart_singbox_background('client_block')
                close_all_connections()
                return self.send_json({"ok": True, "blocked": items, "apply_background": True})
            if path == "/api/trusted":
                ip = body.get("ip"); name = body.get("name") or "Моё устройство"
                trusted = load_trusted(); trusted[ip] = {"name": name, "trusted_at": time.time()}; save_trusted(trusted)
                removed_autobans = purge_exempt_autobans(load_security())
                if removed_autobans:
                    restart_singbox_background('trusted_purge_autobans')
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
                restart_singbox_background('security_apply')
                log("SECURITY", "APPLY", "Security rules apply scheduled", actor="ui", action="security_apply")
                return self.send_json({"ok": True, "summary": security_summary(), "apply_background": True, "message": "Правила безопасности проверены и применяются в фоне."})
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
                restart_singbox_background('routing_save')
                return self.send_json({"ok": True, "routing": routing, "summary": routing_summary(routing), "apply_background": True})
            if path == "/api/routing/update_sources":
                result = update_routing_sources(body.get("tags") or None)
                restart_singbox_background('routing_update_sources')
                return self.send_json({"ok": True, **result, "summary": routing_summary(result.get("routing")), "apply_background": True})
            if path == "/api/servers/subscription_json":
                url = body.get("url") or load_settings().get("subscription_url")
                result = convert_subscription_url_to_json(url, save=True)
                if not result.get("ok"):
                    return self.send_json({"ok": False, **result}, 400)
                return self.send_json({"ok": True, **result, "json_text": json.dumps(result.get("servers") or [], ensure_ascii=False, indent=2)})
            if path == "/api/servers/import":
                mode = body.get("mode", "json")
                append = bool(body.get("append", False))
                text = body.get("text", "")
                url = body.get("url", "")
                settings = load_settings()
                subscription_info = load_subscription_info()
                source_name = str(body.get("source_name") or "").strip()
                if mode == "url":
                    if not url:
                        raise ValueError("URL подписки не указан")
                    parsed = fetch_and_parse_subscription(url, timeout=30)
                    subscription_info = save_subscription_info(parsed.get("subscription_info") or {})
                    settings["subscription_url"] = url
                    save_settings(settings)
                else:
                    parsed = parse_servers_payload(text)
                source = source_for_import(mode, url=url, name=source_name)
                new_servers = annotate_servers_with_source(parsed["servers"], source)
                if mode == "url" and new_servers:
                    save_subscription_servers(new_servers, url)
                if not new_servers:
                    if mode == "url":
                        return self.send_json({"ok": False, "errors": parsed.get("errors", []), "subscription_info": subscription_info}, 400)
                    return self.send_json({"ok": False, "errors": parsed.get("errors", [])}, 400)
                existing_servers = load_servers()
                if append:
                    final = existing_servers + new_servers
                else:
                    # При обновлении подписки сохраняем ручные приоритеты/порядок уже известных серверов.
                    final = preserve_server_metadata(existing_servers, new_servers)
                final = validate_servers(final)["servers"]
                save_servers(final)
                if mode == "url":
                    subscription_info["servers_count"] = len(new_servers)
                    subscription_info = save_subscription_info(subscription_info)
                log("SERVERS", "IMPORT", f"Imported {len(new_servers)} server(s), total {len(final)}", actor="ui", action="servers_import", extra={"mode": mode, "append": append, "subscription": subscription_info})
                restart_singbox_background('servers_import')
                return self.send_json({"ok": True, "count": len(final), "imported": len(new_servers), "errors": parsed.get("errors", []), "subscription_info": subscription_info, "apply_background": True})
            if path == "/api/servers/refresh":
                settings = load_settings(); url = body.get("url") or settings.get("subscription_url")
                if not url:
                    raise ValueError("Ссылка подписки не сохранена")
                parsed = fetch_and_parse_subscription(url, timeout=30)
                subscription_info = save_subscription_info(parsed.get("subscription_info") or {})
                if not parsed["servers"]:
                    return self.send_json({"ok": False, "errors": parsed.get("errors", []), "subscription_info": subscription_info}, 400)
                settings["subscription_url"] = url; save_settings(settings)
                source = source_for_import("url", url=url, name=body.get("source_name") or source_name_from_url(url))
                tagged_servers = annotate_servers_with_source(parsed["servers"], source)
                save_subscription_servers(tagged_servers, url)
                merged_servers = preserve_server_metadata(load_servers(), tagged_servers)
                save_servers(merged_servers); log("SERVERS", "REFRESH", f"Subscription refreshed, {len(parsed['servers'])} server(s), priorities preserved", actor="ui", action="servers_refresh", target=url, extra={"subscription": subscription_info}); restart_singbox_background('servers_refresh')
                return self.send_json({"ok": True, "count": len(merged_servers), "imported": len(parsed["servers"]), "priorities_preserved": True, "errors": parsed.get("errors", []), "subscription_info": subscription_info, "apply_background": True})
            if path == "/api/servers/priority":
                tag = str(body.get("tag") or "")
                profile = body.get("profile")
                priority = priority_value_from_profile(profile, body.get("priority") or 50)
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
                log("SERVERS", "PRIORITY", f"Priority saved for {tag}: {priority}", actor="ui", action="server_priority", target=tag, extra={"priority": priority, "applied": False})
                return self.send_json({"ok": True, "servers": load_servers(), "auto_tags": auto_server_tags(load_servers()), "needs_apply": True, "message": "Профиль сохранён. Чтобы изменить auto-пул без задержек по одному серверу, нажмите «Сохранить всё и применить»."})
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
                restart_singbox_background('servers_reorder')
                return self.send_json({"ok": True, "servers": load_servers(), "auto_tags": auto_server_tags(load_servers()), "apply_background": True})
            if path == "/api/servers/priorities":
                updates = body.get("updates") or []
                apply = bool(body.get("apply", True))
                if not isinstance(updates, list):
                    raise ValueError("updates должен быть списком")
                servers = load_servers()
                by_tag = {str(s.get("tag")): s for s in servers}
                changed = []
                for upd in updates:
                    if not isinstance(upd, dict):
                        continue
                    tag = str(upd.get("tag") or "")
                    if not tag or tag not in by_tag:
                        continue
                    priority = priority_value_from_profile(upd.get("profile"), upd.get("priority") or by_tag[tag].get("priority") or 50)
                    by_tag[tag]["priority"] = max(1, min(999, priority))
                    changed.append({"tag": tag, "priority": by_tag[tag]["priority"], "profile": priority_profile_from_value(by_tag[tag]["priority"])})
                save_servers(servers)
                applied = False
                if apply and changed:
                    # Priority changes cannot corrupt server credentials. Do not block HA Ingress
                    # on full sing-box restart; apply it in the background.
                    restart_singbox_background('server_priorities')
                    applied = True
                log("SERVERS", "PRIORITIES", f"Saved server priority profiles: {len(changed)}", actor="ui", action="server_priorities", extra={"count": len(changed), "applied": applied})
                return self.send_json({"ok": True, "changed": changed, "applied": applied, "apply_background": bool(applied), "servers": load_servers(), "auto_tags": auto_server_tags(load_servers()), "message": "Профили сохранены" + (" и применяются в фоне." if applied else ".")})
            if path == "/api/server_sources/toggle_auto":
                sid = str(body.get("source_id") or "")
                if not sid:
                    raise ValueError("Источник не указан")
                data = load_server_sources()
                changed = False
                for src in data.get("sources", []):
                    if src.get("id") == sid:
                        src["use_in_auto"] = bool(body.get("use_in_auto"))
                        src["updated_at"] = time.time()
                        changed = True
                        break
                if not changed:
                    raise ValueError("Источник не найден")
                save_server_sources(data)
                log("SERVERS", "SOURCE_AUTO", f"Source auto changed: {sid}", actor="ui", action="server_source_auto", target=sid, extra={"use_in_auto": bool(body.get("use_in_auto"))})
                restart_singbox_background('server_source_auto')
                return self.send_json({"ok": True, "sources": server_sources_summary(load_servers()).get("sources", []), "auto_tags": auto_server_tags(load_servers()), "apply_background": True})
            if path == "/api/server_sources/delete":
                sid = str(body.get("source_id") or "")
                if not sid:
                    raise ValueError("Источник не указан")
                servers = load_servers()
                tags = [s.get("tag") for s in servers if s.get("source_id") == sid]
                result = delete_servers_by_tags(tags)
                data = load_server_sources()
                data["sources"] = [s for s in data.get("sources", []) if s.get("id") != sid or sid in {"manual", "legacy", "json_import"}]
                save_server_sources(data)
                log("SERVERS", "SOURCE_DELETE", f"Deleted source servers: {sid}", actor="ui", action="server_source_delete", target=sid, extra={"removed": result.get("removed")})
                restart_singbox_background('server_source_delete')
                return self.send_json({"ok": True, **result, "auto_tags": auto_server_tags(load_servers()), "apply_background": True})
            if path == "/api/servers/delete":
                tag = str(body.get("tag") or "")
                if not tag:
                    raise ValueError("Сервер не указан")
                result = delete_servers_by_tags([tag])
                log("SERVERS", "DELETE", f"Deleted server {tag}", actor="ui", action="server_delete", target=tag)
                restart_singbox_background('server_delete')
                return self.send_json({"ok": True, **result, "auto_tags": auto_server_tags(load_servers()), "apply_background": True})
            if path == "/api/subscription/refresh_traffic":
                settings = load_settings(); url = body.get("url") or settings.get("subscription_url") or load_subscription_info().get("url")
                if not url:
                    raise ValueError("Ссылка подписки не сохранена")
                parsed = fetch_and_parse_subscription(url, timeout=30)
                info = save_subscription_info(parsed.get("subscription_info") or {})
                return self.send_json({"ok": True, "subscription_info": info})
            if path == "/api/client_limits":
                key = str(body.get("key") or "")
                if not key:
                    raise ValueError("Ключ клиента не указан")
                limits = load_client_limits()
                gb = float(body.get("monthly_limit_gb") or 0)
                if gb <= 0:
                    limits.pop(key, None)
                else:
                    limits[key] = {"monthly_limit_gb": gb, "period": monthly_key(), "updated_at": time.time()}
                save_client_limits(limits)
                log("CLIENT", "LIMIT", f"Client traffic limit changed: {key} = {gb} GB", actor="ui", action="client_limit", target=key)
                return self.send_json({"ok": True, "limits": limits})
            if path == "/api/traffic":
                traffic = load_traffic()
                if "limit_bytes" in body:
                    traffic["limit_bytes"] = int(body.get("limit_bytes") or 0)
                if "used_bytes" in body:
                    traffic["used_bytes"] = int(body.get("used_bytes") or 0)
                traffic["manual_sources"] = normalize_manual_traffic_sources(traffic)
                save_traffic(traffic); log("TRAFFIC", "SAVE", "Traffic settings saved", actor="ui", action="traffic_save", extra={"limit_bytes": traffic.get("limit_bytes"), "used_bytes": traffic.get("used_bytes")}); return self.send_json({"ok": True, "traffic": traffic})
            if path == "/api/traffic/manual":
                sources = save_manual_traffic_source(body)
                log("TRAFFIC", "MANUAL", "Manual traffic source saved", actor="ui", action="traffic_manual_save", target=body.get("name") or body.get("id"))
                return self.send_json({"ok": True, "manual_sources": sources})
            if path == "/api/traffic/manual/delete":
                sources = delete_manual_traffic_source(body.get("id"))
                log("TRAFFIC", "MANUAL", "Manual traffic source deleted", actor="ui", action="traffic_manual_delete", target=body.get("id"))
                return self.send_json({"ok": True, "manual_sources": sources})
            if path == "/api/traffic/reset":
                traffic = load_traffic(); traffic["used_bytes"] = 0; traffic["connection_bytes"] = {}; traffic["started_at"] = time.time(); save_traffic(traffic); log("TRAFFIC", "RESET", "Traffic counter reset", actor="ui", action="traffic_reset"); return self.send_json({"ok": True, "traffic": traffic})
            if path == "/api/backup/import":
                payload = body.get("backup") if isinstance(body, dict) and "backup" in body else body
                mode = body.get("mode", "replace") if isinstance(body, dict) else "replace"
                restored = import_backup(payload, mode=mode)
                validate_singbox_config()
                restart_singbox_background('backup_import')
                return self.send_json({"ok": True, "restored": restored, "apply_background": True, "message": "Резервная копия восстановлена. sing-box проверен и применяется в фоне."})
            if path == "/api/options/mode":
                options = apply_production_mode(body.get("mode"))
                log("SETTINGS", "MODE", "Production mode changed", actor="ui", action="settings_mode", target=options.get("production_mode"), extra={"log_level": options.get("log_level")})
                restart_singbox_background('production_mode')
                return self.send_json({"ok": True, "options": {"production_mode": options.get("production_mode"), "log_level": options.get("log_level")}, "apply_background": True})
            if path == "/api/wizard/complete":
                settings = mark_wizard_completed(bool(body.get("completed", True)))
                log("WIZARD", "SAVE", "Wizard state changed", actor="ui", action="wizard_complete", extra={"completed": settings.get("wizard_completed")})
                return self.send_json({"ok": True, "settings": settings, "check": system_check_report()})
            if path == "/api/restart":
                restart_singbox_background('manual_restart'); return self.send_json({"ok": True, "apply_background": True})
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            log_exception("API", "POST", e, actor="ui", target=getattr(self, "path", ""), extra={"method": "POST", "body_keys": list(body.keys()) if isinstance(locals().get("body"), dict) else []})
            self.send_json({"error": str(e)}, 500)

    def do_DELETE(self):
        try:
            path = normalize_request_path(self.path)
            ensure_not_safe_mode_for_mutation(path)
            if path.startswith("/api/blocklist/"):
                cidr_or_ip = urllib.parse.unquote(path.split("/api/blocklist/", 1)[1])
                items = [x for x in load_blocked(include_expired=True) if x.get("cidr") != cidr_or_ip and x.get("ip") != cidr_or_ip]
                save_blocked(items); log("BLOCK", "DELETE", f"Unblocked {cidr_or_ip}", actor="ui", action="block_delete", target=cidr_or_ip); restart_singbox_background('blocklist_delete'); return self.send_json({"ok": True, "blocked": items, "apply_background": True})
            if path.startswith("/api/users/"):
                uid = urllib.parse.unquote(path.split("/api/users/", 1)[1])
                users = [u for u in load_proxy_users() if str(u.get("id")) != uid]
                save_proxy_users(users)
                log("USERS", "DELETE", f"Deleted proxy client {uid}", actor="ui", action="user_delete", target=uid)
                restart_singbox_background('user_delete')
                return self.send_json({"ok": True, "users": users_safe(), "apply_background": True})
            if path.startswith("/api/trusted/"):
                ip = urllib.parse.unquote(path.split("/api/trusted/", 1)[1])
                trusted = load_trusted(); trusted.pop(ip, None); save_trusted(trusted); log("TRUSTED", "DELETE", f"Untrusted client {ip}", actor="ui", action="trusted_delete", target=ip); return self.send_json({"ok": True, "trusted": trusted})
            if path.startswith("/api/servers/"):
                tag = urllib.parse.unquote(path.split("/api/servers/", 1)[1])
                result = delete_servers_by_tags([tag])
                log("SERVERS", "DELETE", f"Deleted server {tag}", actor="ui", action="server_delete", target=tag)
                restart_singbox_background('server_delete')
                return self.send_json({"ok": True, **result, "auto_tags": auto_server_tags(load_servers()), "apply_background": True})
            self.send_json({"error": "not found"}, 404)
        except Exception as e:
            log_exception("API", "DELETE", e, actor="ui", target=getattr(self, "path", ""), extra={"method": "DELETE"})
            self.send_json({"error": str(e)}, 500)


def shutdown_handler(signum, frame):
    stop_mtg()
    stop_singbox()
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    set_boot_state("boot", "Создаю web-интерфейс add-on", state_value="starting", web_ready=False, app_ready=False)

    # Start the management UI as early as possible. After an update Home Assistant
    # may try to open Ingress immediately; if the HTTP server is already listening,
    # the UI can show a startup state instead of a generic loading error.
    server = ThreadingHTTPServer(("0.0.0.0", BACKEND_PORT), Handler)
    set_boot_state("web_ready", "Веб-интерфейс готов, продолжаю запуск сервисов", state_value="starting", web_ready=True, app_ready=False)
    log("BACKEND", "READY", f"Management UI listening on 0.0.0.0:{BACKEND_PORT}")

    def bootstrap_proxy():
        global last_error
        try:
            set_boot_state("data_init", "Инициализирую файлы и настройки", state_value="starting", web_ready=True, app_ready=False)
            load_servers()
            migrate_data()
            settings = load_settings(); settings = update_proxy_lifecycle(settings, load_telegram_settings().get("enabled", False)); save_settings(settings)
            set_boot_state("proxy_boot", "Запускаю прокси-сервисы", state_value="starting", web_ready=True, app_ready=False)
            start_singbox()
            set_boot_state("app_ready", "Сервисы готовы к работе", state_value="ready", web_ready=True, app_ready=True)
        except Exception as e:
            last_error = str(e)
            set_boot_state("error", f"Ошибка запуска: {last_error}", state_value="error", web_ready=True, app_ready=False)
            log_exception("SING_BOX", "singbox_boot_error", e, actor="system")

    threading.Thread(target=bootstrap_proxy, name="bootstrap-sing-box", daemon=True).start()

    try:
        server.serve_forever()
    finally:
        stop_mtg()
        stop_singbox()


if __name__ == "__main__":
    main()
