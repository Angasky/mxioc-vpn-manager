"""Opt-in real HY2/QUIC data plane test on loopback; never touches production."""
import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import core_adapter
import remote_manager as remote
import server


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(all(os.environ.get(k) for k in ('MXIOC_XRAY_BIN', 'MXIOC_SING_BOX_BIN', 'MXIOC_MIHOMO_BIN')), 'set three native core binary paths')
class HY2ConnectivityTests(unittest.TestCase):
    def test_generated_servers_transfer_data_and_reject_wrong_password(self):
        proof = b'mxioc-real-hy2-proof'
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(proof)
            def log_message(self, *args):
                pass
        target = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        try:
            for kind in ('xray', 'sing-box'):
                with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
                    now = datetime.now(timezone.utc)
                    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1))
                            .not_valid_after(now+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False).sign(key, hashes.SHA256()))
                    (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
                    (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                    row = remote.build_inbound(SimpleNamespace(kind=kind), {'template':'hysteria2', 'port':port(socket.SOCK_DGRAM), 'remark':'HY2 proof', 'serverName':'example.com', 'certFile':'/cert.pem', 'keyFile':'/key.pem'})
                    stream = json.loads(row['streamSettings'])
                    stream['tlsSettings']['certificates'][0] = {'certificateFile':str(root/'cert.pem'), 'keyFile':str(root/'key.pem')}
                    row.update(streamSettings=json.dumps(stream), listen='127.0.0.1', id=1, tag='test-hy2')
                    adapter = core_adapter.CoreAPI.__new__(core_adapter.CoreAPI)
                    adapter.kind, adapter.path, adapter.binary = kind, '/test/config.json', '/test/core'
                    adapter.record, adapter.ssh = {'id':'test'}, Mock()
                    adapter.state = {'inbounds':[], 'outbounds':[], 'routing':{'rules':[]}}
                    adapter.native = {'inbounds':[], 'outbounds':[]}
                    adapter.manager = Mock(); adapter.manager.lock = threading.RLock(); captured = []
                    adapter.manager.record.return_value = {}
                    def execute(ssh, record, script, **kwargs):
                        captured.append(json.loads(base64.b64decode(re.search(r"printf '%s' '([A-Za-z0-9+/=]+)'", script)[1])))
                        return 0, ''
                    adapter.manager.execute.side_effect = execute
                    adapter.apply({'inbounds':[row], 'outbounds':[], 'routing':{'rules':[]}})
                    captured[-1]['log'] = {'loglevel':'debug'} if kind == 'xray' else {'level':'debug'}
                    if kind == 'xray':
                        # Latest Xray blocks loopback destinations by default. Allow only
                        # the disposable HTTP proof endpoint in this test configuration.
                        captured[-1]['outbounds'][0]['settings'] = {'finalRules':[{'action':'allow', 'network':'tcp', 'ip':['127.0.0.1/32'], 'port':str(target.server_port)}]}
                    config = root/'server.json'; config.write_text(json.dumps(captured[-1]), encoding='utf-8')
                    binary = os.environ['MXIOC_XRAY_BIN' if kind == 'xray' else 'MXIOC_SING_BOX_BIN']
                    command = [binary, 'run', '-config' if kind == 'xray' else '-c', str(config)]
                    with (root/'server.log').open('w+') as log:
                        process = subprocess.Popen(command, stdout=log, stderr=log)
                        try:
                            time.sleep(.6)
                            self.assertIsNone(process.poll(), (log.seek(0), log.read()))
                            node = server.parse_node_link(server.node_to_uri(remote.inbound_nodes(row, {'host':'198.51.100.10'})[0]))
                            node['server'] = '127.0.0.1'
                            # Test-only self-signed loopback certificate; not exported to users.
                            node.update(name='test', **{'skip-cert-verify':True})
                            for wrong in (False, True):
                                mixed = port(); value = dict(node)
                                if wrong: value['password'] = 'wrong-password'
                                client = root/'client.yaml'
                                client.write_text(server.yaml_dump({'mixed-port':mixed, 'bind-address':'127.0.0.1', 'mode':'rule', 'log-level':'warning', 'proxies':[value], 'rules':['MATCH,test']}), encoding='utf-8')
                                with (root/'client.log').open('w+') as client_log:
                                    proxy_process = subprocess.Popen([os.environ['MXIOC_MIHOMO_BIN'], '-d', directory, '-f', str(client)], stdout=client_log, stderr=client_log)
                                    try:
                                        deadline = time.monotonic()+8
                                        while True:
                                            try:
                                                proxy = socket.create_connection(('127.0.0.1', mixed), timeout=.2); break
                                            except OSError:
                                                if time.monotonic()>deadline: self.fail('Mihomo client did not start')
                                                time.sleep(.1)
                                        response = b''
                                        with proxy:
                                            proxy.settimeout(10)
                                            authority = '127.0.0.1:'+str(target.server_port)
                                            proxy.sendall(('CONNECT '+authority+' HTTP/1.1\r\nHost: '+authority+'\r\n\r\n').encode())
                                            try:
                                                while b'\r\n\r\n' not in response:
                                                    data=proxy.recv(4096)
                                                    if not data: break
                                                    response+=data
                                                if b'200' in response.split(b'\r\n',1)[0]:
                                                    proxy.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
                                                    while True:
                                                        data=proxy.recv(4096)
                                                        if not data: break
                                                        response+=data
                                            except (OSError, TimeoutError):
                                                pass
                                        if wrong: self.assertNotIn(proof, response)
                                        else:
                                            log.seek(0); client_log.seek(0)
                                            self.assertIn(proof, response, log.read()+client_log.read())
                                    finally:
                                        proxy_process.terminate(); proxy_process.wait(timeout=8)
                        finally:
                            process.terminate(); process.wait(timeout=8)
        finally:
            target.shutdown(); target.server_close()
