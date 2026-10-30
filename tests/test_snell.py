"""Snell node management and native Mihomo config checks; no production access."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import server
import test_subscription_enforcement as fixture
import test_public_subscriptions as public_fixture


def node(**changes):
    value = dict(name='Snell 测试', type='snell', server='example.com', port=24443,
                 psk='example-psk', version=4, udp=True, reuse=True)
    value.update(changes)
    return value


class SnellTests(unittest.TestCase):
    setUp = fixture.EnforcementTests.setUp

    def test_link_roundtrip_reserved_psk_unicode_and_ipv6(self):
        original = node(server='2001:db8::12', psk='用户+%2F@: /?#&',
                        **{'obfs-opts': {'mode':'http','host':'bing.com'}})
        link = server.node_to_uri(original)
        payload=base64.b64decode(link.split('://',1)[1].split('?',1)[0]+'='*(-len(link.split('://',1)[1].split('?',1)[0])%4)).decode()
        self.assertEqual(payload,'chacha20-ietf-poly1305:'+original['psk']+'@[2001:db8::12]:24443')
        self.assertEqual(server.parse_node_link(link), original)
        self.assertNotIn('用户', link)

    def test_defaults_do_not_silently_upgrade_legacy_server(self):
        value = server.parse_node_link('snell://example-psk@example.com:24443#legacy')
        self.assertEqual(value['version'], 1)
        self.assertFalse(value.get('udp', False))
        self.assertEqual(server.parse_node_link('snell://example.com:24443?psk=test&version=3')['psk'], 'test')

    def test_all_five_versions_and_supported_udp_reuse_settings(self):
        for version in range(1,6):
            value = node(version=version, udp=version>=3, reuse=version>=4)
            self.assertEqual(server.validate_node_config(value), value)
        for changes in ({'version':0},{'version':6},{'version':True},{'version':3.0},
                        {'version':2,'udp':True},{'version':3,'reuse':True},
                        {'psk':''},{'psk':'x\nsecret'},{'udp':'true'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                server.validate_node_config(node(**changes))

    def test_surge_policy_and_batch_import_keep_parameters_and_names(self):
        policy='Snell policy = snell, example.com, 24443, psk=test, version=3, obfs=http, obfs-host=bing.com'
        value=server.parse_node_link(policy)
        self.assertEqual(value['name'],'Snell policy')
        self.assertEqual(value['version'],3)
        self.assertEqual(value['obfs-opts'],{'mode':'http','host':'bing.com'})
        result=server.import_node_links({'links':policy+'\n'+server.node_to_uri(node())+'\n'+policy})
        self.assertEqual(result['added'],3)
        self.assertEqual(len(result['renamed']),1)
        self.assertFalse(result['failed'])
        self.assertEqual(self.manager.mock_calls,[])

    def test_yaml_base64_and_surge_subscriptions_import(self):
        text=server.yaml_dump({'proxies':[node()]})
        self.assertEqual(server.parse_subscription_text(text),([node()],[]))
        text=base64.b64encode(server.node_to_uri(node()).encode()).decode()
        self.assertEqual(server.parse_subscription_text(text),([node()],[]))
        policy='[Proxy]\nSnell = snell, example.com, 24443, psk=test, version=3'
        nodes,skipped=server.parse_subscription_text(policy)
        self.assertEqual(len(nodes),1);self.assertFalse(skipped)

    def test_invalid_links_do_not_echo_credentials(self):
        for suffix in ('?version=6','?version=3&version=4','?version=1&udp=true',
                       '?version=4&unknown=secret','?version=4&reuse=bad'):
            with self.subTest(suffix=suffix),self.assertRaises(ValueError) as caught:
                server.parse_node_link('snell://TOP-SECRET@example.com:24443'+suffix)
            self.assertNotIn('TOP-SECRET',str(caught.exception))
        with self.assertRaises(ValueError):server.parse_node_link('snell://TOP-SECRET@example.com:99999')

    def test_advanced_obfs_preserved_but_never_silently_lost_in_share_uri(self):
        for obfs in ({'mode':'shadow-tls','host':'example.com','password':'extra-secret','version':3,'alpn':['h2']},
                     {'mode':'restls','host':'example.com','password':'extra-secret','version-hint':'tls13','restls-script':'1,100,100'},
                     {'mode':'jls','host':'example.com','username':'test','password':'extra-secret'}):
            value=node(**{'obfs-opts':obfs})
            self.assertEqual(server.validate_node_config(value),value)
            with self.assertRaisesRegex(ValueError,'完整 Mihomo'):server.node_to_uri(value)
        for extra in ({'mptcp':True},{'dialer-proxy':'entry'},{'client-fingerprint':'firefox'}):
            with self.assertRaisesRegex(ValueError,'完整 Mihomo'):server.node_to_uri(node(**extra))

    def test_bad_obfs_rejected_in_raw_yaml_and_partial_subscription_import(self):
        value=node(**{'obfs-opts':{'mode':'invalid'}})
        with self.assertRaises(ValueError):server.validate_config({**server.minimal_profile_config(),'proxies':[value]})
        nodes,skipped=server.parse_subscription_text(server.yaml_dump({'proxies':[value,node()]}))
        self.assertEqual(nodes,[node()]);self.assertEqual(len(skipped),1)

    def test_other_client_exports_skip_snell_without_breaking_other_nodes(self):
        server.import_node_links({'links':server.node_to_uri(node())+'\nss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:443#ss-test'})
        self.assertEqual(server.read_config()['proxies'][0]['type'],'snell')
        for client in ('v2rayn','v2rayng','v2ray'):
            body,skipped=server.converted_subscription('clash',client)
            self.assertNotIn('snell://',base64.b64decode(body).decode())
            self.assertIn('Snell 测试',skipped)

    def test_shadowrocket_subscription_and_qr_share_export_contain_actual_psk(self):
        value=node(psk=' p@ss:?#%+& 密钥 ',tfo=True,**{'obfs-opts':{'mode':'http','host':'bing.com'}})
        server.mutate_node('POST',{'config':value})
        uri=server.exported_node_link(value['name'])['uri']
        body,skipped=server.converted_subscription('clash','shadowrocket')
        self.assertFalse(skipped)
        self.assertEqual(base64.b64decode(body).decode(),uri)
        encoded,query=uri.split('://',1)[1].split('?',1)
        decoded=base64.b64decode(encoded+'='*(-len(encoded)%4)).decode('utf-8')
        self.assertEqual(decoded,'chacha20-ietf-poly1305:'+value['psk']+'@example.com:24443')
        params=parse_qs(query.split('#',1)[0])
        self.assertEqual(params['version'],['4']);self.assertEqual(params['tfo'],['1'])
        self.assertEqual(params['obfs-host'],['bing.com'])
        self.assertEqual(server.parse_node_link(uri),value)
        report=next(row for row in server.conversion_report() if row['id']=='shadowrocket')
        self.assertEqual(report['supported'],1)

    def test_new_shadowrocket_fixture_and_legacy_urls_import_same_psk(self):
        payload='chacha20-ietf-poly1305:fixture-psk@example.com:24443'
        encoded=base64.b64encode(payload.encode()).decode().rstrip('=')
        value=server.parse_node_link('snell://'+encoded+'?version=3&tfo=0#fixture')
        self.assertEqual(value['psk'],'fixture-psk');self.assertFalse(value['tfo'])
        legacy=server.parse_node_link('snell://fixture-psk@example.com:24443?version=3#fixture')
        self.assertEqual(legacy['psk'],value['psk'])
        for bad in ('not-valid-base64',base64.b64encode(b'wrong-method:SECRET@example.com:24443').decode()):
            with self.assertRaises(ValueError) as caught:server.parse_node_link('snell://'+bad+'?version=3')
            self.assertNotIn('SECRET',str(caught.exception))

    def test_edit_preserves_unknown_yaml_options_and_source_is_not_mutated(self):
        original=node(**{'client-fingerprint':'chrome','tfo':True})
        before=copy.deepcopy(original)
        server.mutate_node('POST',{'config':original})
        self.assertEqual(original,before)
        saved=server.read_config()['proxies'][0]
        server.mutate_node('PUT',{'oldName':saved['name'],'config':{**saved,'psk':'new-psk'}})
        self.assertTrue(server.read_config()['proxies'][0]['tfo'])


class SnellHTTPExportTests(unittest.TestCase):
    setUp=public_fixture.PublicSubscriptionTests.setUp
    tearDown=public_fixture.PublicSubscriptionTests.tearDown

    def test_public_subscription_and_qrcode_use_same_password_complete_link(self):
        value=node(psk='http-fixture:PSK@with%reserved?#')
        doc=server.minimal_profile_config();doc['proxies']=[value]
        server.FILES[0].write_text(server.yaml_dump(doc),encoding='utf-8')
        profile=server.list_profiles()[0]
        base='http://127.0.0.1:'+str(self.httpd.server_address[1])
        with urlopen(base+'/convert/'+profile['slug']+'/shadowrocket',timeout=5) as response:
            subscription=base64.b64decode(response.read()).decode()
        query=urlencode({'name':value['name']})
        with patch.object(server.Handler,'authorized',return_value=True):
            with urlopen(Request(base+'/admin/api/nodes/share?'+query,headers={'X-Profile':'clash'}),timeout=5) as response:
                shared=json.load(response)
            self.assertEqual(subscription,shared['uri'])
            with patch.object(server,'subscription_qr_svg',wraps=server.subscription_qr_svg) as qr:
                with urlopen(Request(base+'/admin/api/nodes/qrcode?'+query,headers={'X-Profile':'clash'}),timeout=5) as response:
                    self.assertIn(b'<svg',response.read())
                self.assertEqual(qr.call_args.args[0],shared['uri'])
        encoded=shared['uri'].split('://',1)[1].split('?',1)[0]
        self.assertEqual(base64.b64decode(encoded+'='*(-len(encoded)%4)).decode(),
                         'chacha20-ietf-poly1305:'+value['psk']+'@example.com:24443')


@unittest.skipUnless(os.environ.get('MXIOC_MIHOMO_BIN'),'set MXIOC_MIHOMO_BIN for native Snell checks')
class NativeSnellConfigTests(unittest.TestCase):
    def test_versions_and_basic_obfuscation_compile(self):
        for version in range(1,6):
            for mode in ('','http','tls'):
                with self.subTest(version=version,mode=mode),tempfile.TemporaryDirectory() as directory:
                    value=node(version=version,udp=version>=3,reuse=version>=4)
                    if mode:value['obfs-opts']={'mode':mode,'host':'example.com'}
                    doc={'mixed-port':0,'mode':'rule','proxies':[value],'rules':['MATCH,'+value['name']]}
                    path=Path(directory)/'config.yaml';path.write_text(server.yaml_dump(doc),encoding='utf-8')
                    result=subprocess.run([os.environ['MXIOC_MIHOMO_BIN'],'-t','-d',directory,'-f',str(path)],capture_output=True,text=True,timeout=15)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_authenticated_local_http_roundtrip(self):
        import secrets
        import socket
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        proof=b'mxioc-snell-native-proof\n'
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Length',str(len(proof)));self.end_headers();self.wfile.write(proof)
            def log_message(self,*args):pass
        target=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=target.serve_forever,daemon=True).start()
        self.addCleanup(target.server_close);self.addCleanup(target.shutdown)
        def free_port():
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
        for version in range(1,6):
            with self.subTest(version=version),tempfile.TemporaryDirectory() as directory:
                snell_port,mixed=free_port(),free_port()
                psk=secrets.token_urlsafe(24)
                value=node(server='127.0.0.1',port=snell_port,psk=psk,version=version,udp=version>=3,reuse=version>=4)
                value=server.parse_node_link(server.node_to_uri(value))
                listener={'name':'local-snell','type':'snell','listen':'127.0.0.1','port':snell_port,
                          'psk':psk,'version':version,'udp':version>=3,'proxy':'DIRECT'}
                doc={'mixed-port':mixed,'bind-address':'127.0.0.1','allow-lan':False,'log-level':'silent',
                     'mode':'rule','listeners':[listener],'proxies':[value],'rules':['MATCH,'+value['name']]}
                path=Path(directory)/'config.yaml';path.write_text(server.yaml_dump(doc),encoding='utf-8')
                with (Path(directory)/'core.log').open('w+') as log:
                    process=subprocess.Popen([os.environ['MXIOC_MIHOMO_BIN'],'-d',directory,'-f',str(path)],stdout=log,stderr=log)
                    try:
                        deadline=time.monotonic()+8
                        while True:
                            if process.poll() is not None:
                                log.seek(0);self.fail(log.read())
                            try:
                                proxy=socket.create_connection(('127.0.0.1',mixed),timeout=0.2);break
                            except OSError:
                                if time.monotonic()>deadline:self.fail('Local Snell proxy did not start')
                                time.sleep(0.05)
                        with proxy:
                            proxy.settimeout(5)
                            authority='127.0.0.1:'+str(target.server_port)
                            proxy.sendall(('CONNECT '+authority+' HTTP/1.1\r\nHost: '+authority+'\r\n\r\n').encode())
                            header=b''
                            while b'\r\n\r\n' not in header:header+=proxy.recv(4096)
                            self.assertIn(b'200',header.split(b'\r\n',1)[0])
                            proxy.sendall(b'GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n')
                            response=b''
                            while True:
                                chunk=proxy.recv(4096)
                                if not chunk:break
                                response+=chunk
                            self.assertEqual(response.split(b'\r\n\r\n',1)[1],proof)
                    finally:
                        process.terminate()
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


if __name__=='__main__':unittest.main()
