#!/usr/bin/env python3
"""Product checks for v4.0.2 sing-box-first transport.

These tests verify the architecture and the regression that broke v4.0.0-v4.0.1:
- public HTTP/SOCKS ports are sing-box inbounds on 0.0.0.0;
- Python auth gateway does not bind or relay those ports;
- generated route rules do NOT contain broad source-IP invert block rules for real
  HTTP/SOCKS direct-transport ports, because those rules blocked the trusted router
  (188.143.204.77) and sent every destination to outbound/block;
- manual source blocklist still works for explicit blocked CIDRs.
"""
import json
import pathlib
import shutil
import tempfile
import importlib.util

ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend.py"
spec = importlib.util.spec_from_file_location("backend", BACKEND)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)

tmp = pathlib.Path(tempfile.mkdtemp())
old = {
    "DATA_DIR": backend.DATA_DIR,
    "OPTIONS_FILE": backend.OPTIONS_FILE,
    "RUNTIME_PORTS_FILE": backend.RUNTIME_PORTS_FILE,
    "SERVER_SOURCES_FILE": backend.SERVER_SOURCES_FILE,
    "SUBSCRIPTION_SERVERS_FILE": backend.SUBSCRIPTION_SERVERS_FILE,
}
try:
    backend.DATA_DIR = tmp
    backend.OPTIONS_FILE = tmp / "options.json"
    backend.RUNTIME_PORTS_FILE = tmp / "runtime_ports.json"
    backend.SERVER_SOURCES_FILE = tmp / "server_sources.json"
    backend.SUBSCRIPTION_SERVERS_FILE = tmp / "subscription_servers.json"
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
    sec["trusted_auth_bypass_cidrs"] = []
    sec["country_filter_enabled"] = True
    sec["allowed_countries"] = ["RU"]
    sec["custom_allowed_cidrs"] = []
    sec["custom_denied_cidrs"] = []
    backend.save_security(sec)
    backend.save_trusted({"188.143.204.77": {"name": "Keenetic", "trusted": True}})
    # Regression: previous test runs / broken builds could leave an autoban for
    # the router in /data/blocked_ips.json. make_singbox_config must purge
    # autobans for trusted clients before converting blocklist into route rules.
    backend.save_blocked([{"cidr": "188.143.204.77/32", "ip": "188.143.204.77", "source": "autoban", "created_at": 1}])

    src = backend.upsert_server_source("manual", "Manual", "manual")
    servers = backend.annotate_servers_with_source([{
        "tag": "T",
        "type": "vless",
        "server": "example.test",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
    }], src)
    backend.save_servers(servers)
    cfg = backend.make_singbox_config()
    inbounds = {i.get("tag"): i for i in cfg.get("inbounds", []) if isinstance(i, dict)}

    assert inbounds["IN-SOCKS5-2080"]["listen"] == "0.0.0.0", inbounds
    assert inbounds["IN-SOCKS5-2080"]["listen_port"] == 2080, inbounds
    assert inbounds["IN-HTTP-2081"]["listen"] == "0.0.0.0", inbounds
    assert inbounds["IN-HTTP-2081"]["listen_port"] == 2081, inbounds
    assert inbounds["IN-SOCKS5-INTERNAL-12081"]["listen"] == "127.0.0.1", inbounds
    assert inbounds["IN-HTTP-INTERNAL-12080"]["listen"] == "127.0.0.1", inbounds
    assert "users" not in inbounds["IN-SOCKS5-2080"], inbounds["IN-SOCKS5-2080"]
    assert "users" not in inbounds["IN-HTTP-2081"], inbounds["IN-HTTP-2081"]
    assert inbounds["IN-SOCKS5-2080"].get("sniff") is True, inbounds["IN-SOCKS5-2080"]

    rules = cfg.get("route", {}).get("rules", [])
    rules_text = json.dumps(rules, ensure_ascii=False)

    # v4.0.2 regression: no broad source-IP invert block may exist for HTTP/SOCKS.
    # v4.0.0-v4.0.1 produced such a rule and blocked every request from 188.143.204.77.
    broad_source_blocks = [
        r for r in rules
        if r.get("source_ip_cidr") and r.get("invert") is True and r.get("outbound") == "block"
    ]
    assert not broad_source_blocks, rules_text
    assert "188.143.204.77/32" not in rules_text, rules_text

    # Explicit manual blocklist must still produce a source block.
    backend.save_blocked([{"cidr": "203.0.113.9/32", "source": "manual", "created_at": 1}])
    cfg_block = backend.make_singbox_config()
    rules_block = cfg_block.get("route", {}).get("rules", [])
    assert any(r.get("source_ip_cidr") == ["203.0.113.9/32"] and r.get("outbound") == "block" for r in rules_block), rules_block

    # The new start_auth_gateways must not create listener sockets or relay threads.
    backend.AUTH_GATEWAY_SOCKETS.clear()
    backend.AUTH_GATEWAY_THREADS.clear()
    backend.start_auth_gateways()
    assert backend.AUTH_GATEWAY_SOCKETS == [], backend.AUTH_GATEWAY_SOCKETS
    assert backend.AUTH_GATEWAY_THREADS == [], backend.AUTH_GATEWAY_THREADS

    text = BACKEND.read_text(encoding="utf-8")
    assert "DIRECT_TRANSPORT" in text
    assert "country/trusted source guard" in text
    print({"ok": True, "direct_transport": True, "version": backend.APP_VERSION})
finally:
    backend.stop_auth_gateways()
    for key, value in old.items():
        setattr(backend, key, value)
    shutil.rmtree(tmp, ignore_errors=True)
