#!/usr/bin/env python3
"""Smoke and contract checks for Proxy от Бориса add-on sources.
Run from proxy-ot-borisa/ before packaging.
"""
import ast
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import socket
import threading
import time
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend.py"
UI = ROOT / "ui" / "index.html"
CONFIG = ROOT / "config.yaml"

subprocess.check_call([sys.executable, "-m", "py_compile", str(BACKEND)])

backend_text = BACKEND.read_text(encoding="utf-8")
tree = ast.parse(backend_text)
seen = {}
dups = []
for n in tree.body:
    if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
        if n.name in seen:
            dups.append((n.name, seen[n.name], n.lineno))
        seen[n.name] = n.lineno
assert not dups, "Duplicate top-level definitions: " + repr(dups)

spec = importlib.util.spec_from_file_location("backend", BACKEND)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
assert backend.APP_VERSION
opts = backend.load_options()
assert opts
assert opts.get("production_mode") in {"normal", "diagnostic", "debug", "safe"}
assert backend.load_telegram_settings()
assert isinstance(backend.system_check_report(), dict)
# Data registry consistency: every persistent file must declare how it participates
# in backup/maintenance/cleanup, so new files cannot be silently forgotten.
assert isinstance(backend.DATA_REGISTRY, dict) and backend.DATA_REGISTRY
for key, meta in backend.DATA_REGISTRY.items():
    assert "path" in meta, key
    assert "backup" in meta, key
    assert "maintenance" in meta, key
    assert "contains_secrets" in meta, key
    if meta.get("maintenance"):
        assert "description" in meta, key
    if meta.get("cleanup"):
        assert callable(getattr(backend, meta["cleanup"], None)), (key, meta.get("cleanup"))
    info = backend.registry_product_info(key, meta)
    assert info.get("purpose"), key
    assert info.get("backup_policy"), key
    assert info.get("cleanup_policy"), key
    assert info.get("user_action"), key
    # Potentially growing files must either have cleanup or be explicit current-state files.
    growing = {"events", "audit", "client_sessions", "mtproto_activity", "geo_cache", "security_autoban_events", "server_backups", "clients", "server_pings"}
    if key in growing:
        assert meta.get("cleanup"), f"{key} can grow but has no cleanup"
maint = backend.maintenance_status()
assert isinstance(maint, dict)
assert "proxy_users.json" in maint["files"]["users"]["path"], maint["files"]["users"]
assert "audit" in maint["files"], maint["files"]
assert "mtproto_activity" in maint["files"], maint["files"]
assert maint["files"]["mtproto_activity"]["cleanup"] is True
assert "manual_traffic" in maint["files"], maint["files"]
assert "server_sources" in maint["files"], maint["files"]
assert maint["files"]["server_sources"]["backup"] is True
assert "addon_options_file" in maint["files"], maint["files"]
assert "rules_cache" in maint["files"], maint["files"]
assert "client_activity" in maint["files"], maint["files"]
for key, fmeta in maint["files"].items():
    assert fmeta.get("purpose"), key
    assert fmeta.get("backup_policy"), key
    assert fmeta.get("cleanup_policy"), key
    assert fmeta.get("user_action"), key
assert maint["files"]["server_backups"]["max_records"] == backend.SERVER_BACKUP_KEEP
assert backend.route_test_domain("chatgpt.com")["normalized"] == "chatgpt.com"
backup = backend.export_backup(include_events=True, include_secrets=False)
assert backup["include_secrets"] is False
assert "audit" in backup["files"]
assert "users" in backup["files"] or backend.registry_path("users").exists() is False
assert "mtproto_activity" in backend.DATA_REGISTRY
assert "server_sources" in backend.DATA_REGISTRY
assert callable(getattr(backend, "prune_server_sources"))
assert backend.normalize_request_path('/api/routing/test?x=1') == '/api/routing/test'
assert callable(getattr(backend, "get_audit_events"))
assert callable(getattr(backend, "apply_production_mode"))

# Minimal route dispatch test without starting the real server or services.
def call_handler(method, path, body=None):
    backend.restart_singbox_background = lambda *a, **k: None
    backend.restart_mtg_background = lambda *a, **k: None
    backend.apply_services_background = lambda *a, **k: None
    h = backend.Handler.__new__(backend.Handler)
    h.path = path
    h.headers = {}
    out = {}
    h.send_json = lambda data, code=200: out.update({"code": code, "data": data}) or data
    h.serve_file = lambda p: h.send_json({"file": p}, 200)
    h.read_body = lambda: body or {}
    if method == "GET":
        h.do_GET()
    elif method == "POST":
        h.do_POST()
    elif method == "DELETE":
        h.do_DELETE()
    return out

assert call_handler("GET", "/api/audit?limit=2")["code"] == 200
assert call_handler("GET", "/api/server_sources")["code"] == 200
assert call_handler("GET", "/api/logs?limit=2&category=all")["code"] == 200
route_resp = call_handler("POST", "/api/routing/test", {"q": "chatgpt.com"})
assert route_resp["code"] == 200, route_resp
assert route_resp["data"]["normalized"] == "chatgpt.com"
maintenance_resp = call_handler("GET", "/api/maintenance")
assert maintenance_resp["data"]["files"]["users"]["path"].endswith("proxy_users.json")
assert "mtproto_activity" in maintenance_resp["data"]["files"]
assert maintenance_resp["data"]["files"]["mtproto_activity"]["cleanup"] is True
mode_resp = call_handler("POST", "/api/options/mode", {"mode": "normal"})
assert mode_resp["code"] == 200, mode_resp
assert mode_resp["data"]["options"]["production_mode"] == "normal"
assert backend.sanitize_sensitive({"url":"https://example.com/secret-token/path?token=abc", "password":"mypassword"})["url"].endswith("/****")
assert "mypassword" not in json.dumps(backend.sanitize_sensitive({"password":"mypassword"}), ensure_ascii=False)

# Regression: application-only server metadata must never leak into sing-box outbounds.
_meta_server = {
    "tag": "meta-test-vless",
    "type": "vless",
    "server": "example.test",
    "server_port": 443,
    "uuid": "00000000-0000-0000-0000-000000000000",
    "flow": "xtls-rprx-vision",
    "enabled": True,
    "use_in_auto": False,
    "source_id": "sub_test",
    "source_name": "Test Source",
    "source_type": "subscription",
    "source_url": "https://example.test/sub",
    "priority": 10,
    "manual": False,
    "traffic": {"used": 1},
    "ui": {"expanded": True},
    "description": "metadata only",
    "created_at": 1,
    "updated_at": 2,
    "imported_at": 3,
}
_clean = backend.server_to_singbox_outbound(_meta_server)
_forbidden_meta = set(getattr(backend, "APP_SERVER_META_KEYS", set()))
assert _forbidden_meta, "APP_SERVER_META_KEYS must not be empty"
_leaked = sorted(k for k in _clean if k in _forbidden_meta)
assert not _leaked, "App metadata leaked into sing-box outbound: " + repr(_leaked)
assert _clean.get("tag") == "meta-test-vless" and _clean.get("type") == "vless"


html = UI.read_text(encoding="utf-8")
script = html.split("<script>", 1)[1].split("</script>", 1)[0]
tmp = ROOT / ".ui-smoke-check.js"
tmp.write_text(script, encoding="utf-8")
try:
    subprocess.check_call(["node", "--check", str(tmp)])
finally:
    tmp.unlink(missing_ok=True)

ids = set(re.findall(r'id="([^"]+)"', html))
refs = set(re.findall(r"\$\('([^']+)'\)", html))
missing = sorted(refs - ids)
assert not missing, "Missing HTML ids: " + ", ".join(missing)

# Frontend/backend API contract: every literal /api path in UI must have a matching handler.
def normalize_ui_path(path):
    path = path.split('?', 1)[0]
    if path.endswith('/'):
        return path
    return path

ui_paths = sorted(set(re.findall(r"['\"](/api/[^'\"]+)['\"]", html)))
missing_routes = []
for raw in ui_paths:
    path = normalize_ui_path(raw)
    if path.endswith('/'):
        ok = (f'path.startswith("{path}")' in backend_text or f"path.startswith('{path}')" in backend_text)
    else:
        ok = (f'path == "{path}"' in backend_text or f"path == '{path}'" in backend_text or f'path.startswith("{path}/")' in backend_text or f"path.startswith('{path}/')" in backend_text)
        # Dynamic API paths may include a value in the UI string, e.g. /api/security/country/RU.
        parts = path.strip('/').split('/')
        for i in range(len(parts), 1, -1):
            prefix = '/' + '/'.join(parts[:i-1]) + '/'
            ok = ok or (f'path.startswith("{prefix}")' in backend_text or f"path.startswith('{prefix}')" in backend_text)
    if not ok:
        missing_routes.append(raw)
assert not missing_routes, "Frontend calls missing backend routes: " + ", ".join(missing_routes)

# Regression checks for endpoints that previously caused 404 or UI breaks.
assert 'if path == "/api/audit"' in backend_text
assert 'if path == "/api/audit/clear"' in backend_text
assert 'if path == "/api/routing/test"' in backend_text
assert 'if path == "/api/options/mode"' in backend_text
assert "post('/api/routing/test'" in html
assert "api('/api/audit" in html
assert "function secretText" in html and "function toggleSecretValue" in html
assert "productionMode" in html and "saveProductionMode" in html
assert "headerSystemStatus" in html and "system-status" in html and "systemStatusInfo" in html
assert "MTProto activity" in html
assert 'class="instruction-group"' in html
assert "Хранение данных, журналы и очистка" in html
assert "Автобэкапы servers.json" in html
assert "maintenance-table" in html and "backup_policy" in html and "cleanup_policy" in html

# Functional check for server source lifecycle in an isolated data dir.
import tempfile, shutil
_tmp_data = pathlib.Path(tempfile.mkdtemp())
_old_data_dir = backend.DATA_DIR
_old_sources_file = backend.SERVER_SOURCES_FILE
_old_subscription_file = backend.SUBSCRIPTION_SERVERS_FILE
try:
    backend.DATA_DIR = _tmp_data
    backend.SERVER_SOURCES_FILE = _tmp_data / "server_sources.json"
    backend.SUBSCRIPTION_SERVERS_FILE = _tmp_data / "subscription_servers.json"
    backend.DATA_REGISTRY["server_sources"]["path"] = backend.SERVER_SOURCES_FILE
    backend.DATA_REGISTRY["servers"]["path"] = _tmp_data / "servers.json"
    _src = backend.upsert_server_source("sub_test", "Test Sub", "subscription", url="https://example.test/sub")
    _servers = backend.annotate_servers_with_source([{"tag":"DE1-vless","type":"vless","server":"example.test","server_port":443,"uuid":"u"}], _src)
    backend.save_servers(_servers)
    _loaded = backend.load_servers()
    assert _loaded and _loaded[0]["source_id"] == "sub_test", _loaded
    assert _loaded[0].get("enabled") is True and _loaded[0].get("use_in_auto") is True
    _summary = backend.server_sources_summary(_loaded)
    assert any(s.get("id") == "sub_test" and s.get("servers_count") == 1 for s in _summary.get("sources", [])), _summary
    assert "DE1-vless" in backend.auto_server_tags(_loaded)
    _config = backend.make_singbox_config()
    _runtime_leaks = []
    for _outbound in _config.get("outbounds", []):
        if isinstance(_outbound, dict):
            _runtime_leaks.extend([_k for _k in _outbound.keys() if _k in backend.APP_SERVER_META_KEYS])
    assert not _runtime_leaks, "App metadata leaked into generated sing-box config: " + repr(sorted(set(_runtime_leaks)))
    _loaded[0]["enabled"] = False
    backend.save_servers(_loaded)
    assert "DE1-vless" not in backend.auto_server_tags(backend.load_servers())
    _loaded = backend.load_servers(); _loaded[0]["enabled"] = True; _loaded[0]["use_in_auto"] = False; backend.save_servers(_loaded)
    assert "DE1-vless" not in backend.auto_server_tags(backend.load_servers())
    _del = backend.delete_servers_by_tags(["DE1-vless"])
    assert _del.get("removed") == ["DE1-vless"], _del
    assert backend.load_servers() == []
finally:
    backend.DATA_DIR = _old_data_dir
    backend.SERVER_SOURCES_FILE = _old_sources_file
    backend.SUBSCRIPTION_SERVERS_FILE = _old_subscription_file
    shutil.rmtree(_tmp_data, ignore_errors=True)


# Trusted auth bypass regression checks. Trusted access must be implemented on
# the standard HTTP/SOCKS ports through the local auth gateway. sing-box itself
# must listen only on internal localhost ports and must not receive application-
# only trusted_* settings or extra trusted external ports.
_tmp_data2 = pathlib.Path(tempfile.mkdtemp())
_old_data_dir2 = backend.DATA_DIR
_old_sources_file2 = backend.SERVER_SOURCES_FILE
_old_subscription_file2 = backend.SUBSCRIPTION_SERVERS_FILE
_old_runtime_ports_file = backend.RUNTIME_PORTS_FILE
_old_options_file = backend.OPTIONS_FILE
try:
    backend.DATA_DIR = _tmp_data2
    backend.SERVER_SOURCES_FILE = _tmp_data2 / "server_sources.json"
    backend.SUBSCRIPTION_SERVERS_FILE = _tmp_data2 / "subscription_servers.json"
    backend.RUNTIME_PORTS_FILE = _tmp_data2 / "runtime_ports.json"
    backend.OPTIONS_FILE = _tmp_data2 / "options.json"
    backend.write_json(backend.OPTIONS_FILE, {
        "secret": "test",
        "http_proxy_port": 2081,
        "socks_proxy_port": 2080,
        "telegram_proxy_port": 2083,
        "http_auth_enabled": True,
        "socks_auth_enabled": True,
        "proxy_username": "u",
        "proxy_password": "p",
    })
    sec = backend.load_security()
    sec["trusted_auth_bypass_enabled"] = True
    sec["trusted_auth_bypass_http"] = True
    sec["trusted_auth_bypass_socks"] = True
    sec["trusted_auth_bypass_cidrs"] = ["192.168.1.35/32"]
    backend.save_security(sec)
    _src = backend.upsert_server_source("manual", "Manual", "manual")
    _servers = backend.annotate_servers_with_source([{
        "tag":"trusted-test-vless",
        "type":"vless",
        "server":"example.test",
        "server_port":443,
        "uuid":"00000000-0000-0000-0000-000000000000"
    }], _src)
    backend.save_servers(_servers)
    cfg = backend.make_singbox_config()
    inbound_tags = {i.get("tag"): i for i in cfg.get("inbounds", []) if isinstance(i, dict)}
    assert "IN-HTTP-TRUSTED-2085" not in inbound_tags, inbound_tags
    assert "IN-SOCKS5-TRUSTED-2086" not in inbound_tags, inbound_tags
    assert inbound_tags["IN-HTTP-2081"].get("listen") == "127.0.0.1"
    assert inbound_tags["IN-HTTP-2081"].get("listen_port") == backend.INTERNAL_HTTP_PROXY_PORT
    assert inbound_tags["IN-SOCKS5-2080"].get("listen") == "127.0.0.1"
    assert inbound_tags["IN-SOCKS5-2080"].get("listen_port") == backend.INTERNAL_SOCKS_PROXY_PORT
    assert "users" not in inbound_tags["IN-HTTP-2081"], inbound_tags["IN-HTTP-2081"]
    assert "users" not in inbound_tags["IN-SOCKS5-2080"], inbound_tags["IN-SOCKS5-2080"]
    dumped = json.dumps(cfg, ensure_ascii=False)
    for forbidden in ["trusted_auth_bypass_enabled", "trusted_auth_bypass_cidrs", "trusted_auth_bypass_http", "trusted_auth_bypass_socks", "trusted_http_proxy_port", "trusted_socks_proxy_port"]:
        assert forbidden not in dumped, forbidden
finally:
    backend.DATA_DIR = _old_data_dir2
    backend.SERVER_SOURCES_FILE = _old_sources_file2
    backend.SUBSCRIPTION_SERVERS_FILE = _old_subscription_file2
    backend.RUNTIME_PORTS_FILE = _old_runtime_ports_file
    backend.OPTIONS_FILE = _old_options_file
    shutil.rmtree(_tmp_data2, ignore_errors=True)


# HTTP gateway end-to-end regression: trusted HTTP proxy CONNECT and GET must
# be forwarded to the internal SOCKS listener instead of resetting connection.
def _dummy_socks_server(port_holder, seen, ready):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(5)
    port_holder.append(srv.getsockname()[1])
    ready.set()
    deadline = time.time() + 5
    try:
        while time.time() < deadline and len(seen) < 3:
            srv.settimeout(0.5)
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            with c:
                greeting = c.recv(3)
                assert greeting == b'\x05\x01\x00', greeting
                c.sendall(b'\x05\x00')
                head = c.recv(4)
                assert head[:3] == b'\x05\x01\x00', head
                atyp = head[3]
                if atyp == 3:
                    ln = c.recv(1)[0]
                    host = c.recv(ln).decode('idna')
                elif atyp == 1:
                    host = socket.inet_ntoa(c.recv(4))
                else:
                    raise AssertionError('unexpected atyp ' + repr(atyp))
                port = int.from_bytes(c.recv(2), 'big')
                seen.append((host, port))
                c.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                c.settimeout(0.7)
                try:
                    req = c.recv(4096)
                except socket.timeout:
                    req = b''
                if req:
                    seen.append(('request', req.split(b'\r\n', 1)[0].decode('iso-8859-1', errors='ignore')))
                    c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
    finally:
        srv.close()

_old_internal_socks = backend.INTERNAL_SOCKS_PROXY_PORT
_old_load_security = backend.load_security
_old_load_options = backend.load_options
try:
    port_holder, seen = [], []
    ready = threading.Event()
    th = threading.Thread(target=_dummy_socks_server, args=(port_holder, seen, ready), daemon=True)
    th.start(); assert ready.wait(2), 'dummy socks not ready'
    backend.INTERNAL_SOCKS_PROXY_PORT = port_holder[0]
    backend.load_security = lambda: {
        'trusted_auth_bypass_enabled': True,
        'trusted_auth_bypass_http': True,
        'trusted_auth_bypass_socks': True,
        'trusted_auth_bypass_cidrs': ['127.0.0.1/32'],
        'trusted_auth_bypass_unknown_mode': 'auth',
    }
    backend.load_options = lambda: {'http_auth_enabled': True, 'socks_auth_enabled': True}
    client, server = socket.socketpair()
    tconn = threading.Thread(target=backend.handle_http_gateway, args=(server, ('127.0.0.1', 5555)), daemon=True)
    tconn.start()
    client.sendall(b'CONNECT ifconfig.me:443 HTTP/1.1\r\nHost: ifconfig.me:443\r\n\r\n')
    resp = client.recv(4096)
    assert b'200 Connection Established' in resp, resp
    client.close(); tconn.join(1)
    assert ('ifconfig.me', 443) in seen, seen
    client, server = socket.socketpair()
    tget = threading.Thread(target=backend.handle_http_gateway, args=(server, ('127.0.0.1', 5555)), daemon=True)
    tget.start()
    client.sendall(b'GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n')
    resp = client.recv(4096)
    assert b'200 OK' in resp, resp
    client.close(); tget.join(1)
    assert ('example.com', 80) in seen, seen
    assert ('request', 'GET /path?q=1 HTTP/1.1') in seen, seen
finally:
    backend.INTERNAL_SOCKS_PROXY_PORT = _old_internal_socks
    backend.load_security = _old_load_security
    backend.load_options = _old_load_options

assert "secTrustedBypassEnabled" in html
assert "portTrustedHttpInput" not in html and "portTrustedSocksInput" not in html
assert "Доверенный доступ без авторизации" in html
assert "trusted_http_proxy_port" not in backend_text and "trusted_socks_proxy_port" not in backend_text
assert "/api/clients/bulk" in backend_text and "btnApplyClientBulk" in html


# v1.25.0 product checks: Security is a top-level tab, not hidden only under settings.
assert 'data-tab="security"' in html
assert 'data-security-panel="trusted"' in html and 'data-security-panel="geo"' in html and 'data-security-panel="autoban"' in html
assert 'data-security-panel="blocks"' in html and 'data-security-panel="events"' in html
assert 'Раздел безопасности вынесен' not in html
assert 'Настройки → Безопасность' not in html
assert 'trafficSourcesBox' in html and 'renderTrafficSources' in html
assert 'traffic_sources' in backend_text and callable(getattr(backend, 'build_traffic_sources'))
assert callable(getattr(backend, 'connections_for_ui')) and callable(getattr(backend, 'gateway_connections_for_ui'))
# Synthetic gateway connections must expose the real external client, not only 127.0.0.1.
_old_snapshot = backend.gateway_active_snapshot
try:
    backend.gateway_active_snapshot = lambda: [{"key":"gw1","ip":"5.17.17.147","service":"HTTP proxy","trusted":True,"destination":"ifconfig.me","started_at":1,"last_seen":2}]
    _ui_conns = backend.connections_for_ui([])
    assert _ui_conns and _ui_conns[0]["metadata"]["sourceIP"] == "5.17.17.147", _ui_conns
    assert _ui_conns[0]["metadata"]["access"] == "trusted_ip_bypass", _ui_conns
finally:
    backend.gateway_active_snapshot = _old_snapshot
# Traffic by source must not collapse all providers into one unexplained bar.
_ts = backend.build_traffic_sources(
    {"manual_sources":[{"id":"m1","name":"Manual VPS","limit_bytes":100,"used_bytes":40}]},
    [],
    [{"id":"sub1","name":"Main sub","type":"subscription","servers_count":14,"enabled":True,"use_in_auto":True}],
    {"traffic":{"total":1000,"upload":100,"download":200},"updated_at":123},
)
assert _ts["summary"]["auto_sources"] == 1 and _ts["summary"]["manual_sources"] == 1, _ts

# v1.25.2: provider traffic must survive old/legacy source metadata.
_old_load_settings_ts = backend.load_settings
_old_load_subscription_servers_ts = backend.load_subscription_servers
try:
    backend.load_settings = lambda: {"subscription_url": "https://example.test/sub"}
    backend.load_subscription_servers = lambda: {"servers": [{"tag": f"s{i}"} for i in range(14)]}
    _legacy_ts = backend.build_traffic_sources(
        {"manual_sources": []},
        [{"tag": f"s{i}", "source_id": "legacy", "source_type": "legacy"} for i in range(14)],
        [
            {"id":"legacy","name":"Ранее добавленные серверы","type":"legacy","servers_count":14,"enabled":True,"use_in_auto":True},
            {"id":"manual","name":"Ручные серверы","type":"manual","servers_count":0,"enabled":True,"use_in_auto":True},
        ],
        {"url":"https://example.test/sub","servers_count":14,"traffic":{"total":1000,"upload":100,"download":200},"updated_at":123},
    )
    assert _legacy_ts["summary"]["auto_sources"] == 1, _legacy_ts
    assert any(x.get("id") == "legacy" and x.get("traffic_mode") == "subscription_auto" for x in _legacy_ts["items"]), _legacy_ts
    _fallback_ts = backend.build_traffic_sources(
        {"manual_sources": []}, [],
        [{"id":"json_import","name":"JSON","type":"json","servers_count":2,"enabled":True,"use_in_auto":True}],
        {"url":"https://different.test/sub","servers_count":14,"traffic":{"total":1000,"upload":100,"download":200},"updated_at":123},
    )
    assert _fallback_ts["summary"]["auto_sources"] == 1, _fallback_ts
finally:
    backend.load_settings = _old_load_settings_ts
    backend.load_subscription_servers = _old_load_subscription_servers_ts


# v1.25.3-v1.25.5: auth-gateway routes must show final VPN/DIRECT leg and trusted tag.
_old_current_server_info = backend.current_server_info
_old_get_proxies = backend.get_proxies
try:
    backend.get_proxies = lambda: {"Proxy": {"now": "auto"}, "auto": {"now": "node-1"}, "node-1": {"delay": 123}}
    _route_chain = backend.route_chain_for_destination("example.com")
    assert _route_chain["chains"][0:2] == ["auth-gateway", "Proxy"], _route_chain
    assert _route_chain["chains"][-1].startswith("VPN:") or _route_chain["chains"][-1] == "DIRECT", _route_chain
    backend.gateway_active_snapshot = lambda: [{"key":"gw2","ip":"188.143.204.77","service":"HTTP proxy","trusted":True,"destination":"example.com","upload":55,"download":77,"started_at":1,"last_seen":2}]
    _gw_rows = backend.gateway_connections_for_ui()
    assert _gw_rows[0]["metadata"]["access"] == "trusted_ip_bypass", _gw_rows
    assert len(_gw_rows[0]["chains"]) >= 3, _gw_rows
    assert _gw_rows[0]["upload"] == 55 and _gw_rows[0]["download"] == 77, _gw_rows
finally:
    backend.current_server_info = _old_current_server_info
    backend.get_proxies = _old_get_proxies
    backend.gateway_active_snapshot = _old_snapshot

assert "/api/route/diagnostics" in backend_text
assert "/api/diagnostics/stream_test" in backend_text
assert "Диагностика Proxy/VPN" in html
assert "Ручная проверка стабильности загрузки" in html
assert "trusted_ip без auth" in html
assert "function runStreamDiagnostic" in html

assert 'subscriptionSourcesMiniHtml' in html and 'Трафик по источникам серверов:' in html
assert '"traffic": traffic' in backend_text and 'subscription_traffic_refresh' in backend_text

# Dockerfile build sanity. For Home Assistant local builds we intentionally
# use the upstream prebuilt :latest images for sing-box and mtg-multi.
# Building mtg-multi from source inside HA proved fragile because upstream
# Go requirements can move faster than available builder images.
dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
assert "ghcr.io/sagernet/sing-box:latest" in dockerfile
assert "ghcr.io/dolonet/mtg-multi:latest" in dockerfile
assert "go build" not in dockerfile
assert "golang:" not in dockerfile

cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
assert cfg["version"] == backend.APP_VERSION
assert cfg.get("panel_admin") is True
assert cfg["options"].get("http_auth_enabled") is True
assert "production_mode" in cfg["schema"]
print(json.dumps({"ok": True, "version": backend.APP_VERSION, "api_paths": len(ui_paths)}, ensure_ascii=False))

# Server sources regression checks
assert "serverSourcesBox" in html
assert "function renderServerSources" in html
assert "function deleteServerSource" in html
assert "function routeDisplay" in html
assert "post('/api/server_sources/delete'" in html
assert "post('/api/server_sources/toggle_auto'" in html
assert "post('/api/server_sources/toggle'" in html
assert "post('/api/servers/delete'" in html
assert "post('/api/servers/toggle'" in html
assert "post('/api/servers/toggle_auto'" in html
assert "function serverEnabledToggle" in html and "function sourceEnabledToggle" in html
assert "Активность клиентов по доменам/IP" in html
assert "Кэш rule-set маршрутизации" in html
assert "SERVER_SOURCES_FILE" in backend_text
assert "source_id" in backend_text and "source_name" in backend_text
print(json.dumps({"server_sources_checks": True}, ensure_ascii=False))

# v1.25.5: no product UI/function preset for a service-specific console/game preset.
assert "nintendo" not in backend_text.lower()
assert "nintendo" not in html.lower()
