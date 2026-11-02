"""Opt-in real Xray HY2 users with the sing-box engine used by v2rayN."""
import json,os,socket,subprocess,tempfile,threading,time,unittest
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import remote_manager as remote
import server
from test_hy2_connectivity import port

@unittest.skipUnless(all(os.environ.get(k) for k in ('MXIOC_XRAY_BIN','MXIOC_SING_BOX_BIN')),'set native Xray and sing-box paths')
class V2RayNHY2CoreTests(unittest.TestCase):
    def test_new_runtime_user_connects_and_revocation_preserves_peer(self):
        proof=b'v2rayn-singbox-hy2-proof'
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(proof)
            def log_message(self,*args):pass
        target=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=target.serve_forever,daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);now=datetime.now(timezone.utc);key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'example.com')])
                cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('example.com')]),False).sign(key,hashes.SHA256())
                (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM));(root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
                row=remote.build_inbound(SimpleNamespace(kind='xray'),{'template':'hysteria2','port':port(socket.SOCK_DGRAM),'serverName':'example.com','certFile':'/cert','keyFile':'/key'})
                for field in ('settings','streamSettings','sniffing'):row[field]=json.loads(row[field])
                row.update(listen='127.0.0.1',tag='test-hy2',id=1);row['streamSettings']['tlsSettings']['certificates']=[{'certificateFile':str(root/'cert.pem'),'keyFile':str(root/'key.pem')}]
                original=row['settings']['clients'][0]
                api='127.0.0.1:'+str(port());config={'log':{'loglevel':'warning'},'api':{'tag':'api','listen':api,'services':['HandlerService']},'inbounds':[row],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','network':'tcp','ip':['127.0.0.1/32'],'port':str(target.server_port)}]}}]}
                (root/'server.json').write_text(json.dumps(config),encoding='utf-8')
                with (root/'server.log').open('w+') as log:
                    process=subprocess.Popen([os.environ['MXIOC_XRAY_BIN'],'run','-config',str(root/'server.json')],stdout=log,stderr=log)
                    try:
                        time.sleep(.6)
                        if process.poll() is not None:log.seek(0);self.fail(log.read())
                        def cli(*args):
                            result=subprocess.run([os.environ['MXIOC_XRAY_BIN'],'api',args[0],'--server='+api,*args[1:]],capture_output=True,text=True,timeout=8)
                            self.assertEqual(result.returncode,0,result.stderr);return result.stdout
                        def transfers(user):
                            selected={**row,'settings':{**row['settings'],'clients':[user]}}
                            node=server.parse_node_link(server.node_to_uri(remote.inbound_nodes(selected,{'host':'198.51.100.10'})[0]))
                            listen=port();client={'log':{'level':'error'},'inbounds':[{'type':'mixed','tag':'local','listen':'127.0.0.1','listen_port':listen}],'outbounds':[{'type':'hysteria2','tag':'proxy','server':'127.0.0.1','server_port':node['port'],'password':node['password'],'tls':{'enabled':True,'server_name':node.get('sni') or node.get('servername'),'certificate_path':str(root/'cert.pem')}}],'route':{'final':'proxy'}}
                            (root/'client.json').write_text(json.dumps(client),encoding='utf-8')
                            with (root/'client.log').open('w+') as client_log:
                                proxy=subprocess.Popen([os.environ['MXIOC_SING_BOX_BIN'],'run','-c',str(root/'client.json')],stdout=client_log,stderr=client_log)
                                try:
                                    deadline=time.monotonic()+5
                                    while True:
                                        try:sock=socket.create_connection(('127.0.0.1',listen),timeout=.1);break
                                        except OSError:
                                            if time.monotonic()>deadline:client_log.seek(0);self.fail(client_log.read())
                                            time.sleep(.05)
                                    response=b''
                                    with sock:
                                        sock.settimeout(3);authority='127.0.0.1:'+str(target.server_port)
                                        sock.sendall(('CONNECT '+authority+' HTTP/1.1\r\nHost: '+authority+'\r\n\r\n').encode())
                                        try:
                                            while b'\r\n\r\n' not in response:
                                                chunk=sock.recv(4096)
                                                if not chunk:break
                                                response+=chunk
                                            if b'200' in response.split(b'\r\n',1)[0]:
                                                sock.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
                                                while True:
                                                    chunk=sock.recv(4096)
                                                    if not chunk:break
                                                    response+=chunk
                                        except OSError:pass
                                    client_log.seek(0);log.seek(0);self.last_logs=client_log.read()+log.read()+repr(response)
                                    return proof in response
                                finally:proxy.terminate();proxy.wait(timeout=8)
                        added={'email':'new-subscription','auth':'new:+@ example-password','enable':True}
                        self.assertTrue(transfers(original),getattr(self,'last_logs','original HY2 user cannot connect'))
                        self.assertFalse(transfers(added),'unregistered user unexpectedly connected')
                        single={**row,'settings':{**row['settings'],'clients':[added]}};(root/'add.json').write_text(json.dumps({'inbounds':[single]}),encoding='utf-8')
                        cli('adu',str(root/'add.json'))
                        users=json.loads(cli('inbounduser','-tag=test-hy2','-email=new-subscription'))['users'];self.assertEqual(users[0]['account']['auth'],added['auth'])
                        self.assertTrue(transfers(added),'registered HY2 user fails in v2rayN sing-box engine')
                        cli('rmu','-tag=test-hy2','new-subscription')
                        self.assertFalse(transfers(added),'revoked HY2 user can reconnect')
                        self.assertTrue(transfers(original),'revocation broke peer user')
                    finally:process.terminate();process.wait(timeout=8)
        finally:target.shutdown();target.server_close()
