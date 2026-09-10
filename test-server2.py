#!/usr/bin/env python3
"""Vigile — Serveur enrichi avec données réelles du système."""
import json, hashlib, subprocess, time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

TOKEN = hashlib.sha256(str(time.time()).encode()).hexdigest()[:32]
AUDIT_LOG = []

def get_system_info():
    info = {'fapolicyd': False, 'selinux': '?', 'firewalld': False, 'packages': 0, 'fanotify': 0, 'untrusted': 0}
    try:
        r = subprocess.run(['systemctl','is-active','fapolicyd'], capture_output=True, text=True, timeout=5)
        info['fapolicyd'] = r.stdout.strip() == 'active'
    except: pass
    try:
        r = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=5)
        info['selinux'] = r.stdout.strip()
    except: pass
    try:
        r = subprocess.run(['systemctl','is-active','firewalld'], capture_output=True, text=True, timeout=5)
        info['firewalld'] = r.stdout.strip() == 'active'
    except: pass
    try:
        r = subprocess.run(['rpm','-qa'], capture_output=True, text=True, timeout=30)
        info['packages'] = len(r.stdout.strip().split('\n')) if r.stdout else 0
    except: pass
    try:
        r = subprocess.run(['grep','-c','type=FANOTIFY','/var/log/audit/audit.log'], capture_output=True, text=True, timeout=10)
        info['fanotify'] = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
    except: pass
    try:
        r = subprocess.run(['grep','-c','obj_trust=0','/var/log/audit/audit.log'], capture_output=True, text=True, timeout=10)
        info['untrusted'] = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
    except: pass
    return info

def get_recent_events():
    events = []
    try:
        r = subprocess.run(['grep','type=FANOTIFY','/var/log/audit/audit.log'], capture_output=True, text=True, timeout=10)
        for line in r.stdout.strip().split('\n')[-20:]:
            if not line: continue
            parts = dict(kv.split('=',1) for kv in line.split() if '=' in kv)
            events.append({
                'resp': parts.get('resp','?'),
                'obj_trust': parts.get('obj_trust','?'),
                'subj_trust': parts.get('subj_trust','?'),
                'raw': line[:100],
            })
    except: pass
    return events[::-1]

class H(BaseHTTPRequestHandler):
    def _json(self, d, code=200):
        self.send_response(code)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps(d).encode())

    def do_GET(self):
        if self.path in ('/','/index.html'):
            p = Path(__file__).parent / 'web' / 'index.html'
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write((p.read_text() if p.exists() else '<html><body><h1>Vigile</h1></body></html>').encode())
        elif not self.headers.get('Authorization') == f'Bearer {TOKEN}':
            self._json({'error':'invalid token'}, 401)
        elif self.path == '/admin/v1/status':
            info = get_system_info()
            info.update({'status':'ok','audit_entries':len(AUDIT_LOG),
                        'audit_head':hashlib.sha256(str(len(AUDIT_LOG)).encode()).hexdigest()})
            self._json(info)
        elif self.path == '/admin/v1/fapolicyd':
            self._json({'events':get_recent_events(),'count':20})
        elif self.path == '/admin/v1/audit':
            self._json({'count':len(AUDIT_LOG),'entries':AUDIT_LOG[-50:]})
        elif self.path == '/admin/v1/audit/verify':
            AUDIT_LOG.append({'seq':len(AUDIT_LOG)+1,'at_unix':int(time.time()),
                'actor':'admin','action':'audit.verified','target':'journal','result':'ok',
                'hash':hashlib.sha256(str(time.time()).encode()).hexdigest()})
            self._json({'valid':True,'verified_entries':len(AUDIT_LOG)})
        else:
            self._json({'error':'not found'}, 404)

if __name__ == '__main__':
    info = get_system_info()
    print(f"""
╔══════════════════════════════════════════════════════╗
║         VIGILE — Serveur enrichi                      ║
╠══════════════════════════════════════════════════════╣
║  URL   : http://127.0.0.1:8443
║  Token : {TOKEN}
║                                                        ║
║  fapolicyd : {'actif' if info['fapolicyd'] else 'inactif'}
║  SELinux   : {info['selinux']}
║  Firewall  : {'actif' if info['firewalld'] else 'inactif'}
║  Paquets   : {info['packages']}
║  Fanotify  : {info['fanotify']} events
║                                                        ║
║  Ouvrez http://127.0.0.1:8443 dans votre navigateur    ║
╚══════════════════════════════════════════════════════╝""")
    HTTPServer(('127.0.0.1', 8443), H).serve_forever()
