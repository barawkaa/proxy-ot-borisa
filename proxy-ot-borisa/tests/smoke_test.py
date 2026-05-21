#!/usr/bin/env python3
"""Smoke checks for Proxy от Бориса add-on sources.
Run from proxy-ot-borisa/ before packaging.
"""
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
spec = importlib.util.spec_from_file_location("backend", BACKEND)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
assert backend.APP_VERSION
assert backend.load_options()
assert backend.load_telegram_settings()
assert isinstance(backend.system_check_report(), dict)
maint = backend.maintenance_status()
assert isinstance(maint, dict)
assert "proxy_users.json" in maint["files"]["users"]["path"], maint["files"]["users"]
assert backend.route_test_domain("chatgpt.com")["normalized"] == "chatgpt.com"
assert backend.export_backup(include_events=False, include_secrets=False)["include_secrets"] is False
assert backend.normalize_request_path('/api/routing/test?x=1') == '/api/routing/test'

# Minimal route dispatch test without starting the real server.
def call_handler(method, path, body=None):
    h = backend.Handler.__new__(backend.Handler)
    h.path = path
    out = {}
    h.send_json = lambda data, code=200: out.update({"code": code, "data": data}) or data
    h.serve_file = lambda p: h.send_json({"file": p}, 200)
    h.read_body = lambda: body or {}
    if method == "GET":
        h.do_GET()
    else:
        h.do_POST()
    return out

assert call_handler("GET", "/api/audit?limit=2")["code"] == 200
route_resp = call_handler("POST", "/api/routing/test", {"q": "chatgpt.com"})
assert route_resp["code"] == 200, route_resp
assert route_resp["data"]["normalized"] == "chatgpt.com"
assert call_handler("GET", "/api/maintenance")["data"]["files"]["users"]["path"].endswith("proxy_users.json")

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

backend_text = BACKEND.read_text(encoding="utf-8")
# API/frontend contract checks for endpoints that caused regressions.
assert 'if path == "/api/audit"' in backend_text
assert 'if path == "/api/audit/clear"' in backend_text
assert 'if path == "/api/routing/test"' in backend_text
assert "post('/api/routing/test'" in html
assert "api('/api/audit" in html
assert "function secretText" in html and "function toggleSecretValue" in html
assert ".settings-menu button b{display:block" in html

cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
assert cfg["version"] == backend.APP_VERSION
print(json.dumps({"ok": True, "version": backend.APP_VERSION}, ensure_ascii=False))
