#!/usr/bin/env python3
import importlib.util, pathlib, socket, threading, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('backend', ROOT / 'backend.py')
backend = importlib.util.module_from_spec(spec); spec.loader.exec_module(backend)

seen = []
ready = threading.Event()
port_holder = []

def read_exact(c, n):
    data=b''
    while len(data)<n:
        chunk=c.recv(n-len(data))
        if not chunk:
            raise EOFError('short read')
        data += chunk
    return data

def dummy_internal_socks():
    srv=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1',0)); srv.listen(1)
    port_holder.append(srv.getsockname()[1]); ready.set()
    c,_=srv.accept()
    with c:
        # greeting from external client, passed through by gateway
        g=read_exact(c,2); assert g == b'\x05\x01', g
        methods=read_exact(c,g[1]); assert methods == b'\x00', methods
        c.sendall(b'\x05\x00')
        head=read_exact(c,4); assert head[:4] == b'\x05\x01\x00\x03', head
        ln=read_exact(c,1)[0]
        host=read_exact(c,ln).decode('ascii')
        port=int.from_bytes(read_exact(c,2),'big')
        seen.append((host,port))
        c.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        payload=read_exact(c,4)
        seen.append(('payload', payload))
        c.sendall(b'PONG')
        time.sleep(0.1)
    srv.close()

old_port=backend.INTERNAL_SOCKS_PROXY_PORT
old_sec=backend.load_security
old_opts=backend.load_options
try:
    th=threading.Thread(target=dummy_internal_socks, daemon=True); th.start(); assert ready.wait(2)
    backend.INTERNAL_SOCKS_PROXY_PORT = port_holder[0]
    backend.load_security = lambda: {
        'trusted_auth_bypass_enabled': True,
        'trusted_auth_bypass_socks': True,
        'trusted_auth_bypass_http': True,
        'trusted_auth_bypass_cidrs': ['127.0.0.1/32'],
        'trusted_auth_bypass_unknown_mode': 'auth',
    }
    backend.load_options = lambda: {'socks_auth_enabled': True, 'http_auth_enabled': True}
    client, server = socket.socketpair()
    gt=threading.Thread(target=backend.handle_socks_gateway, args=(server, ('127.0.0.1', 33333)), daemon=True)
    gt.start()
    client.settimeout(2)
    client.sendall(b'\x05\x01\x00')
    assert read_exact(client,2) == b'\x05\x00'
    host=b'chatgpt.com'
    client.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + (443).to_bytes(2,'big'))
    rep=read_exact(client,10); assert rep[:2] == b'\x05\x00', rep
    client.sendall(b'PING')
    assert read_exact(client,4) == b'PONG'
    client.close(); gt.join(1); th.join(1)
    assert ('chatgpt.com',443) in seen, seen
    assert ('payload', b'PING') in seen, seen
    print({'ok': True, 'trusted_socks_passthrough': True})
finally:
    backend.INTERNAL_SOCKS_PROXY_PORT = old_port
    backend.load_security = old_sec
    backend.load_options = old_opts
