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
