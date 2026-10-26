"""Mieru URL/profile interoperability without production accounts or servers."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlencode

import server
import test_subscription_enforcement as fixture

PATTERN = 'CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3'


def link(**changes):
    query = {'profile':'测试 Mieru','port':'2999','protocol':'TCP'}
    query.update(changes)
    return 'mierus://user:example-password@example.com?' + urlencode(query, doseq=True)


class MieruTests(unittest.TestCase):
    setUp = fixture.EnforcementTests.setUp

    def test_simple_link_roundtrip_reserved_credentials_and_ipv6(self):
        value = link(multiplexing='MULTIPLEXING_HIGH', **{'handshake-mode':'HANDSHAKE_NO_WAIT','traffic-pattern':PATTERN})
        node = server.parse_node_link(value)
        self.assertEqual(node['type'],'mieru'); self.assertEqual(node['transport'],'TCP')
        self.assertEqual(node['port'],2999); self.assertEqual(node['traffic-pattern'],PATTERN)
        node.update(server='2001:db8::123',username='用户+%2F@: /',password='p@ss:/?#%+& 空')
        node['name'] = 'Mieru + %2F & test'
        self.assertEqual(server.parse_node_link(server.node_to_uri(node)),node)

    def test_official_multi_binding_link_expands_without_dropping_transport(self):
        nodes = server.parse_node_links(link(port=['6666','9998-9999','6489','4896'],protocol=['TCP','TCP','UDP','UDP'],mtu='1400'))
        self.assertEqual(len(nodes),4)
        self.assertEqual([n['transport'] for n in nodes],['TCP','TCP','UDP','UDP'])
        self.assertEqual(nodes[1]['port-range'],'9998-9999'); self.assertNotIn('port',nodes[1])
        with self.assertRaisesRegex(ValueError,'批量导入'):server.parse_node_link(link(port=['2999','3000'],protocol=['TCP','UDP']))

    def test_batch_mixed_links_partial_errors_rename_and_group_membership(self):
        value = link(port=['2999','3000-3002'],protocol=['TCP','UDP'])
        result = server.import_node_links({'links':value+'\n'+link(protocol='QUIC')+'\n'+value})
        self.assertEqual((result['total'],result['added'],len(result['failed'])),(3,4,1))
        self.assertEqual(len(result['renamed']),2)
        nodes = server.read_config()['proxies']
        self.assertEqual(len({n['name'] for n in nodes}),4)
        self.assertEqual(server.snapshot()['nodes'][1]['port'],'3000-3002')
        self.assertEqual(self.manager.mock_calls,[])

    def test_yaml_and_base64_subscription_import_keep_mieru(self):
        nodes = server.parse_node_links(link(port='2090-2099',protocol='UDP'))
        parsed, skipped = server.parse_subscription_text(server.yaml_dump({'proxies':nodes}))
        self.assertEqual(parsed,nodes); self.assertFalse(skipped)
        encoded = base64.b64encode((link()+'\n'+link(protocol='UDP')).encode()).decode()
        parsed, skipped = server.parse_subscription_text(encoded)
        self.assertEqual(len(parsed),2); self.assertFalse(skipped)

    def test_native_export_incompatible_clients_do_not_receive_mieru(self):
        server.import_node_links({'links':link()+'\nss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:443#ss-test'})
        self.assertEqual(server.read_config()['proxies'][0]['type'],'mieru')
        for client in ('v2rayn','v2rayng','v2ray','shadowrocket'):
            body, skipped = server.converted_subscription('clash',client)
            self.assertNotIn('mierus://',base64.b64decode(body).decode())
            self.assertIn('测试 Mieru',skipped)

    def test_bad_options_never_add_nodes_or_echo_passwords(self):
        variants = [link(profile=''),link(protocol='QUIC'),link(port=['2999','3000'],protocol=['TCP']),
                    link(port='65536'),link(port='9000-8000'),link(mtu='1200'),link(multiplexing='wrong'),
                    link(**{'handshake-mode':'wrong'}),link(**{'traffic-pattern':'not base64'}),
                    link().replace('user:example-password','user:'),link().replace('example-password','x'*65), 'mieru://not-a-simple-link']
        for value in variants:
            with self.subTest(value=value),self.assertRaises(ValueError) as caught:server.parse_node_links(value)
            self.assertNotIn('example-password',str(caught.exception))
        self.assertEqual(server.read_config()['proxies'],[])

    def test_range_edit_and_udp_disabled_share_validation(self):
        node = server.parse_node_link(link())
        node['port-range']='2999-3002'
        with self.assertRaises(ValueError):server.validate_node_config(node)
        del node['port']
        original = copy.deepcopy(node)
        self.assertEqual(server.validate_node_config(node),node)
        self.assertEqual(node,original)
        node['udp']=False
        with self.assertRaisesRegex(ValueError,'完整订阅'):server.node_to_uri(node)


@unittest.skipUnless(os.environ.get('MXIOC_MIHOMO_BIN'),'set MXIOC_MIHOMO_BIN for real Mieru config validation')
class NativeMieruConfigTests(unittest.TestCase):
    def test_tcp_udp_and_port_ranges_compile_in_native_mihomo(self):
        for transport in ('TCP','UDP'):
            for port in ('2999','2999-3002'):
                with self.subTest(transport=transport,port=port),tempfile.TemporaryDirectory() as root:
                    node = server.parse_node_link(link(port=port,protocol=transport,**{'traffic-pattern':PATTERN,'handshake-mode':'HANDSHAKE_STANDARD'}))
                    doc={'mixed-port':0,'mode':'rule','proxies':[node],'rules':['MATCH,'+node['name']]}
                    path=Path(root)/'config.yaml';path.write_text(server.yaml_dump(doc))
                    result=subprocess.run([os.environ['MXIOC_MIHOMO_BIN'],'-t','-d',root,'-f',str(path)],capture_output=True,text=True,timeout=15)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        print('PASS native Mihomo Mieru: TCP/UDP single ports and ranges, handshake and traffic-pattern')


@unittest.skipUnless(os.environ.get('MXIOC_MIHOMO_BIN') and os.environ.get('MXIOC_MITA_BIN'),
                     'set MXIOC_MIHOMO_BIN and MXIOC_MITA_BIN for local authenticated traffic')
class NativeMieruTrafficTests(unittest.TestCase):
    def test_authenticated_tcp_and_udp_underlays_reach_local_http_target(self):
        import secrets
        import socket
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        if os.geteuid() == 0:
            self.skipTest('Run unprivileged: mita must not write host system metrics')
        def free_port(kind=socket.SOCK_STREAM):
            with socket.socket(type=kind) as sock:
                sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                body=b'mxioc-mieru-authenticated\n'
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        target=ThreadingHTTPServer(('127.0.0.1',0),Target)
        threading.Thread(target=target.serve_forever,daemon=True).start()
        self.addCleanup(target.server_close);self.addCleanup(target.shutdown)
        tcp,udp=free_port(),free_port(socket.SOCK_DGRAM);password=secrets.token_urlsafe(24)
        processes=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            config={'listenIPAddress':'127.0.0.1','portBindings':[{'port':tcp,'protocol':'TCP'},{'port':udp,'protocol':'UDP'}],
                    'users':[{'name':'local-test','password':password,'allowPrivateIP':True,'allowLoopbackIP':True}], 'loggingLevel':'INFO'}
            path=root/'mita.json';path.write_text(json.dumps(config));path.chmod(0o600)
            with (root/'mita.log').open('w+') as server_log:
                mita=subprocess.Popen([os.environ['MXIOC_MITA_BIN'],'run'],stdout=server_log,stderr=server_log,
                    env={**os.environ,'MITA_CONFIG_JSON_FILE':str(path),'MITA_UDS_PATH':str(root/'mita.sock'),'MITA_INSECURE_UDS':'1'})
                processes.append(mita)
                try:
                    deadline=time.monotonic()+8
                    while True:
                        try:
                            with socket.create_connection(('127.0.0.1',tcp),timeout=.2):break
                        except OSError:
                            if time.monotonic()>deadline:
                                server_log.seek(0);self.fail('local mita did not start: '+server_log.read())
                            time.sleep(.05)
                    passed = 0
                    for transport,port in [('TCP',tcp),('UDP',udp)]:
                        with self.subTest(transport=transport):
                            node=server.parse_node_link('mierus://local-test:'+password+'@127.0.0.1?'+urlencode({'profile':'local-test','port':port,'protocol':transport}))
                            mixed=free_port();proxy=root/(transport+'.yaml')
                            proxy.write_text(server.yaml_dump({'mixed-port':mixed,'mode':'rule','log-level':'info','proxies':[node],'rules':['MATCH,local-test']}))
                            with (root/(transport+'.log')).open('w+') as client_log:
                                process=subprocess.Popen([os.environ['MXIOC_MIHOMO_BIN'],'-d',directory,'-f',str(proxy)],stdout=client_log,stderr=client_log)
                                processes.append(process)
                                deadline=time.monotonic()+8
                                while True:
                                    try:
                                        client=socket.create_connection(('127.0.0.1',mixed),timeout=.2);break
                                    except OSError:
                                        if time.monotonic()>deadline:raise
                                        time.sleep(.05)
                                with client:
                                    client.settimeout(12)
                                    request=f'GET http://127.0.0.1:{target.server_address[1]}/test HTTP/1.1\r\nHost: 127.0.0.1:{target.server_address[1]}\r\nConnection: close\r\n\r\n'
                                    client.sendall(request.encode());response=b''
                                    while True:
                                        data=client.recv(8192)
                                        if not data:break
                                        response+=data
                                    if b'mxioc-mieru-authenticated\n' not in response:
                                        client_log.flush();client_log.seek(0);server_log.flush();server_log.seek(0)
                                        self.fail('Local proxy response '+repr(response)+'\n'+client_log.read()+'\n'+server_log.read())
                                process.terminate();process.wait(5);processes.remove(process)
                                passed += 1
                    if passed == 2:
                        print('PASS native Mieru: Mihomo -> authenticated local mita -> local HTTP target, TCP and UDP underlays')
                finally:
                    for process in reversed(processes):
                        process.terminate()
                        try:process.wait(5)
                        except subprocess.TimeoutExpired:process.kill();process.wait(5)
