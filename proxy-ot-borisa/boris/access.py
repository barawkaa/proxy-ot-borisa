"""Persistent IP grants; pending requests and invitations have hard size/time bounds."""
import hashlib
import ipaddress
import secrets
import time
from .model import MODES


def canonical(ip):
    address=ipaddress.ip_address(ip)
    return str(address.ipv4_mapped or address) if isinstance(address,ipaddress.IPv6Address) else str(address)


class Access:
    def __init__(self,store):
        self.store=store;self.last_cleanup=0
        store.db.executescript('''
        CREATE TABLE IF NOT EXISTS ip_access(ip TEXT PRIMARY KEY, id TEXT UNIQUE, name TEXT,
          status TEXT, first_seen REAL, last_seen REAL, expires REAL, route_mode TEXT,
          invited INTEGER, notified INTEGER, revision TEXT);
        CREATE TABLE IF NOT EXISTS invitations(hash TEXT PRIMARY KEY, name TEXT, expires REAL, ip TEXT);
        ''')
        store.db.commit()

    def rows(self):
        cur=self.store.db.execute('SELECT * FROM ip_access ORDER BY last_seen DESC')
        keys=[x[0] for x in cur.description]
        return [dict(zip(keys,x)) for x in cur]

    def get(self,ip):
        cur=self.store.db.execute('SELECT * FROM ip_access WHERE ip=?',(canonical(ip),))
        row=cur.fetchone()
        return dict(zip([x[0] for x in cur.description],row)) if row else None

    def lan(self,ip):
        address=ipaddress.ip_address(canonical(ip))
        return any(address in ipaddress.ip_network(x,strict=False) for x in self.store.config['access']['lan_cidrs'])

    def observe(self,ip,request=True):
        ip=canonical(ip);now=time.time();self.cleanup();row=self.get(ip)
        if not row:
            pending=self.store.db.execute("SELECT COUNT(*) FROM ip_access WHERE status='pending'").fetchone()[0]
            total=self.store.db.execute('SELECT COUNT(*) FROM ip_access').fetchone()[0]
            local=self.lan(ip)
            if total>=3000 or (not local and pending>=self.store.config['access']['pending_limit']):return None
            status='lan' if local else 'pending'
            self.store.db.execute('INSERT INTO ip_access VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                (ip,'ip_'+secrets.token_hex(8),ip,status,now,now,0,'default',0,0,secrets.token_hex(12)))
            self.store.db.commit();row=self.get(ip)
        elif now-row['last_seen']>=30:
            self.store.db.execute('UPDATE ip_access SET last_seen=? WHERE ip=?',(now,ip));self.store.db.commit()
        if request and row['invited']==1:
            self.store.db.execute('UPDATE ip_access SET invited=2 WHERE ip=?',(ip,));self.store.db.commit()
            row['invited']=2
        return row

    def allowed(self,row):
        if not row or row['status'] not in ('lan','approved'):return False
        if row['status']=='lan' and not self.lan(row['ip']):return False
        return not row['expires'] or row['expires']>time.time()

    def user(self,ip):
        row=self.observe(ip)
        if not self.allowed(row):return None
        mode=row['route_mode']
        if mode=='default':mode=self.store.config['access']['route_mode']
        return {**row,'enabled':True,'http_ip':True,'username':'__access_'+mode,
                'password':self.store.config['access']['internal_password'],'expires_at':row['expires']}

    def update(self,ip,body,revision=None):
        row=self.get(ip)
        if not row:raise ValueError('Запрос больше не существует')
        if revision and row['revision']!=revision:raise ValueError('Это уведомление уже устарело')
        status=body.get('status',row['status']);mode=body.get('route_mode',row['route_mode'])
        if status not in ('approved','paused','blocked','pending','lan'):raise ValueError('Неизвестный статус доступа')
        if status=='lan' and not self.lan(ip):raise ValueError('Адрес не входит в домашнюю сеть')
        if mode not in (*MODES,'default'):raise ValueError('Неизвестный маршрут')
        expires=float(body.get('expires',row['expires']) or 0)
        if 'expires' in body and expires and not time.time()<expires<time.time()+86400*3650:raise ValueError('Укажите будущий срок доступа')
        name=str(body.get('name',row['name'])).strip()[:80] or row['ip']
        self.store.db.execute('UPDATE ip_access SET name=?,status=?,expires=?,route_mode=?,revision=? WHERE ip=?',
            (name,status,expires,mode,secrets.token_hex(12),row['ip']))
        self.store.db.commit()
        labels={'approved':'разрешён','paused':'приостановлен','blocked':'запрещён','pending':'ожидает одобрения','lan':'локальная сеть'}
        self.store.event('access','HTTP по IP: '+row['ip']+' — '+labels[status])
        return self.get(ip)

    def invite(self,name):
        self.cleanup()
        if self.store.db.execute('SELECT COUNT(*) FROM invitations').fetchone()[0]>=100:raise ValueError('Слишком много действующих приглашений')
        token=secrets.token_urlsafe(24);expires=time.time()+self.store.config['access']['invite_minutes']*60
        self.store.db.execute('INSERT INTO invitations VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),str(name)[:80],expires,''))
        self.store.db.commit();return token,expires

    def redeem(self,token,ip):
        ip=canonical(ip);self.cleanup();digest=hashlib.sha256(token.encode()).hexdigest()
        item=self.store.db.execute('SELECT name,ip FROM invitations WHERE hash=? AND expires> ?',(digest,time.time())).fetchone()
        if not item or (item[1] and item[1]!=ip):return False
        row=self.observe(ip,request=False)
        if not row or row['status']=='blocked':return False
        self.store.db.execute('UPDATE invitations SET ip=? WHERE hash=?',(ip,digest))
        self.store.db.execute('UPDATE ip_access SET invited=1,name=? WHERE ip=?',(item[0] or row['name'],ip))
        self.store.db.commit();return True

    def cleanup(self):
        now=time.time()
        if now-self.last_cleanup<60:return
        self.last_cleanup=now
        cutoff=now-self.store.config['access']['pending_hours']*3600
        self.store.db.execute('DELETE FROM invitations WHERE expires<?',(now,))
        self.store.db.execute("DELETE FROM ip_access WHERE status='pending' AND first_seen<?",(cutoff,))
        # Expired grants stay visible; they never become silently approved again.
        self.store.db.commit()
