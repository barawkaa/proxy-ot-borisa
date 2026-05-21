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
assert isinstance(backend.maintenance_status(), dict)
assert backend.route_test_domain("chatgpt.com")["normalized"] == "chatgpt.com"
assert backend.export_backup(include_events=False, include_secrets=False)["include_secrets"] is False

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

cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
assert cfg["version"] == backend.APP_VERSION
print(json.dumps({"ok": True, "version": backend.APP_VERSION}, ensure_ascii=False))
