#!/usr/bin/env python3
"""Serveur Vigile simplifié pour tester l'interface web.
Sert le portail HTML + une API admin minimale."""

import json
import hashlib
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

# Générer un token admin simple
TOKEN = hashlib.sha256(str(time.time()).encode()).hexdigest()[:32]
AUDIT_LOG = []

class VigileHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _check_auth(self):
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return False
        token = auth[7:]
        return token == TOKEN

    def do_GET(self):
        # Portail web
        if self.path in ('/', '/index.html'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            try:
                with open('web/index.html') as f:
                    self.wfile.write(f.read().encode())
            except FileNotFoundError:
                self.wfile.write(b'<html><body><h1>Vigile</h1><p>web/index.html non trouve</p></body></html>')

        # API admin
        elif self.path == '/admin/v1/status':
            if not self._check_auth():
                self._send_json({'error': 'invalid token'}, 401)
                return
            self._send_json({
                'status': 'ok',
                'audit_entries': len(AUDIT_LOG),
                'audit_head': hashlib.sha256(str(len(AUDIT_LOG)).encode()).hexdigest(),
            })

        elif self.path == '/admin/v1/audit':
            if not self._check_auth():
                self._send_json({'error': 'invalid token'}, 401)
                return
            self._send_json({
                'count': len(AUDIT_LOG),
                'head_hash': hashlib.sha256(str(len(AUDIT_LOG)).encode()).hexdigest(),
                'entries': AUDIT_LOG[-50:],
            })

        elif self.path == '/admin/v1/audit/verify':
            if not self._check_auth():
                self._send_json({'error': 'invalid token'}, 401)
                return
            AUDIT_LOG.append({
                'seq': len(AUDIT_LOG) + 1,
                'at_unix': int(time.time()),
                'actor': 'test-admin',
                'action': 'audit.verified',
                'target': 'audit-journal',
                'result': 'ok',
                'hash': hashlib.sha256(str(time.time()).encode()).hexdigest(),
            })
            self._send_json({'valid': True, 'verified_entries': len(AUDIT_LOG)})

        else:
            self._send_json({'error': f'not found: {self.path}'}, 404)

    def do_POST(self):
        if not self._check_auth():
            self._send_json({'error': 'invalid token'}, 401)
            return

        if self.path == '/admin/v1/enrollment-tokens':
            token = hashlib.sha256(str(time.time()).encode()).hexdigest()
            AUDIT_LOG.append({
                'seq': len(AUDIT_LOG) + 1,
                'at_unix': int(time.time()),
                'actor': 'test-admin',
                'action': 'enrollment-token.issued',
                'target': 'default',
                'result': 'ok',
                'hash': hashlib.sha256(str(time.time()).encode()).hexdigest(),
            })
            self._send_json({'token': token, 'ttl_secs': 3600, 'tenant': 'default'}, 201)
        else:
            self._send_json({'error': f'not found: {self.path}'}, 404)

if __name__ == '__main__':
    print("╔══════════════════════════════════════════════════════╗")
    print("║           VIGILE — Serveur de test                     ║")
    print("╠══════════════════════════════════════════════════════╣")
    print(f"║  URL   : http://127.0.0.1:8443")
    print(f"║  Token : {TOKEN}")
    print("║                                                        ║")
    print("║  Ouvrez http://127.0.0.1:8443 dans votre navigateur    ║")
    print("║  Collez le token ci-dessus dans le champ de login.      ║")
    print("╚══════════════════════════════════════════════════════╝")
    HTTPServer(('127.0.0.1', 8443), VigileHandler).serve_forever()
