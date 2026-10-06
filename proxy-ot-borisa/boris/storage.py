"""Atomic configuration and bounded SQLite history. No request writes JSON files."""
import copy
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from .model import defaults


def atomic_json(path, value):
    path = Path(path)
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        os.chmod(tmp, 0o600)
        json.dump(value, f, ensure_ascii=False, separators=(',',':'))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.path = self.root / 'config-v5.json'
        self.config = json.loads(self.path.read_text()) if self.path.exists() else defaults()
        self.db = sqlite3.connect(self.root / 'history-v5.sqlite', check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA auto_vacuum=INCREMENTAL')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, kind TEXT, message TEXT, count INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, client_id TEXT, name TEXT, protocol TEXT, ip TEXT, destination TEXT, started REAL, ended REAL, upload INTEGER, download INTEGER, result TEXT);
        CREATE TABLE IF NOT EXISTS usage(month TEXT, client_id TEXT, upload INTEGER, download INTEGER, PRIMARY KEY(month,client_id));''')
        self.db.commit()

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.config)

    def save(self, config):
        with self.lock:
            if self.path.exists():
                atomic_json(self.root / 'config-v5.previous.json', self.config)
            atomic_json(self.path, config)
            self.config = copy.deepcopy(config)

    def event(self, kind, message):
        # Messages are controlled templates, never raw exceptions/URLs/credentials.
        with self.lock:
            row = self.db.execute('SELECT id FROM events WHERE kind=? AND message=? AND ts>? ORDER BY id DESC LIMIT 1', (kind, message[:500], time.time()-300)).fetchone()
            if row:
                self.db.execute('UPDATE events SET count=count+1,ts=? WHERE id=?', (time.time(), row[0]))
            else:
                self.db.execute('INSERT INTO events(ts,kind,message) VALUES(?,?,?)', (time.time(), kind, message[:500]))
            self.db.commit()

    def sessions(self, records):
        with self.lock:
            self.db.executemany('INSERT OR REPLACE INTO sessions VALUES(:id,:client_id,:name,:protocol,:ip,:destination,:started,:ended,:upload,:download,:result)', records)
            self.db.commit()

    def add_usage(self, records):
        with self.lock:
            month = time.strftime('%Y-%m', time.gmtime())
            for uid, up, down in records:
                self.db.execute('INSERT INTO usage VALUES(?,?,?,?) ON CONFLICT(month,client_id) DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download', (month,uid,up,down))
            self.db.commit()

    def usage(self):
        with self.lock:
            return {r[0]: {'upload':r[1], 'download':r[2]} for r in self.db.execute('SELECT client_id,upload,download FROM usage WHERE month=?', (time.strftime('%Y-%m', time.gmtime()),))}

    def list(self, table, limit=200):
        if table not in ('events','sessions'):
            raise ValueError('Неизвестная таблица')
        with self.lock:
            cursor = self.db.execute(f'SELECT * FROM {table} ORDER BY {"ts" if table=="events" else "started"} DESC LIMIT ?', (min(1000,int(limit)),))
            keys = [c[0] for c in cursor.description]
            return [dict(zip(keys,row)) for row in cursor]

    def cleanup(self, clear=False):
        with self.lock:
            settings = self.config['settings']
            for table, col, count in [('sessions','started',settings['history_records']),('events','ts',settings['event_records'])]:
                if clear:
                    self.db.execute(f'DELETE FROM {table}')
                else:
                    self.db.execute(f'DELETE FROM {table} WHERE {col}<?', (time.time()-settings['history_days']*86400,))
                    self.db.execute(f'DELETE FROM {table} WHERE rowid NOT IN (SELECT rowid FROM {table} ORDER BY {col} DESC LIMIT ?)', (count,))
            self.db.execute('DELETE FROM usage WHERE month != ?', (time.strftime('%Y-%m', time.gmtime()),))
            self.db.commit()
            cap = settings['history_mb']*1024*1024
            size = self.db.execute('PRAGMA page_count').fetchone()[0]*self.db.execute('PRAGMA page_size').fetchone()[0]
            if size > cap or clear:
                for table in ('events','sessions'):
                    self.db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY rowid LIMIT (SELECT COUNT(*)/2 FROM {table}))')
                self.db.commit()
                self.db.execute('VACUUM')
            return {'bytes': (self.root/'history-v5.sqlite').stat().st_size, 'limit':cap}
