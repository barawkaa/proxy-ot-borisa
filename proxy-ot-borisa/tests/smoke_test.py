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
maint = backend.maintenance_status()
assert isinstance(maint, dict)
assert "proxy_users.json" in maint["files"]["users"]["path"], maint["files"]["users"]
assert "audit" in maint["files"], maint["files"]
assert backend.route_test_domain("chatgpt.com")["normalized"] == "chatgpt.com"
backup = backend.export_backup(include_events=True, include_secrets=False)
assert backup["include_secrets"] is False
assert "audit" in backup["files"]
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
assert call_handler("GET", "/api/logs?limit=2&category=all")["code"] == 200
route_resp = call_handler("POST", "/api/routing/test", {"q": "chatgpt.com"})
assert route_resp["code"] == 200, route_resp
assert route_resp["data"]["normalized"] == "chatgpt.com"
assert call_handler("GET", "/api/maintenance")["data"]["files"]["users"]["path"].endswith("proxy_users.json")
mode_resp = call_handler("POST", "/api/options/mode", {"mode": "normal"})
assert mode_resp["code"] == 200, mode_resp
assert mode_resp["data"]["options"]["production_mode"] == "normal"

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

# Dockerfile hardening: avoid mutable :latest for core proxy binaries.
dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
assert "ghcr.io/sagernet/sing-box:v" in dockerfile
assert "MTG_MULTI_VERSION=v" in dockerfile
assert "ghcr.io/dolonet/mtg-multi:latest" not in dockerfile
mtg_builder = re.search(r"FROM\s+golang:(\d+)\.(\d+)(?:\.\d+)?-alpine\s+AS\s+mtg", dockerfile)
assert mtg_builder, "Dockerfile must pin golang:<version>-alpine AS mtg"
assert tuple(map(int, mtg_builder.groups())) >= (1, 26), "mtg-multi v1.10.0 requires Go >= 1.26"

cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
assert cfg["version"] == backend.APP_VERSION
assert cfg.get("panel_admin") is True
assert cfg["options"].get("http_auth_enabled") is True
assert "production_mode" in cfg["schema"]
print(json.dumps({"ok": True, "version": backend.APP_VERSION, "api_paths": len(ui_paths)}, ensure_ascii=False))
