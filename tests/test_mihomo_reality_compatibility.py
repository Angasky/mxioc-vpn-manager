"""Preserve manually imported Reality handshakes; never probe production nodes."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

import core_adapter
import remote_manager
import server
import test_subscription_enforcement as fixture


FLAG = 'support-x25519mlkem768'
UUID = '22453845-ff1a-471d-8214-25952a9348a6'


def node(flag=None):
    value = {'name':'manual','type':'vless','server':'example.com','port':443,'uuid':UUID,
             'tls':True,'servername':'www.microsoft.com','client-fingerprint':'chrome',
             'reality-opts':{'public-key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','short-id':'abcd'}}
    if flag is not None:
        value['reality-opts'][FLAG] = flag
    return value


class RealityCompatibilityTests(unittest.TestCase):
    setUp = fixture.EnforcementTests.setUp

    def test_existing_yaml_and_subscription_read_preserve_original_handshake(self):
        doc = server.minimal_profile_config()
        doc['proxies'] = [node(), {**node(False), 'name':'disabled'}, {**node(True), 'name':'enabled'}]
        original = server.yaml_dump(doc)
        server.FILES[0].write_text(original)
        cached, text = server.get_cached_config(server.FILES[0])
        self.assertEqual(text, original)
        self.assertEqual(cached, doc)
        server.snapshot_json()
        self.assertEqual(server.FILES[0].read_text(), original)

    def test_batch_import_does_not_opt_old_links_into_a_new_handshake(self):
        url = f'vless://{UUID}@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&fp=chrome#manual'
        result = server.import_node_links({'links': url+'\n'+url.replace('#manual','#manual2')})
        self.assertEqual(result['added'], 2)
        for item in server.read_config()['proxies']:
            self.assertNotIn(FLAG, item['reality-opts'])
        self.manager.inbounds.assert_not_called()
        self.manager.set_bandwidth.assert_not_called()

    def test_explicit_flag_roundtrip_and_validation(self):
        for flag in (True, False):
            source = node(flag)
            result = server.parse_node_link(server.node_to_uri(source))
            self.assertIs(result['reality-opts'][FLAG], flag)
        for value in ('false', 1, None):
            source = node(); source['reality-opts'][FLAG] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                server.validate_node_config(source)

    def test_controller_created_node_retains_modern_handshake_through_import(self):
        row = {'id':1,'remark':'managed','port':24443,'protocol':'vless',
               'settings':{'clients':[{'id':UUID,'email':'test','flow':'xtls-rprx-vision'}]},
               'streamSettings':{'network':'tcp','security':'reality','realitySettings':{
                   'serverNames':['www.microsoft.com'],'shortIds':['abcd'],
                   'settings':{'publicKey':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}}}}
        managed = remote_manager.inbound_nodes(row, {'host':'198.51.100.10'})[0]
        imported = server.parse_node_link(server.node_to_uri(managed))
        self.assertIs(imported['reality-opts'][FLAG], True)


@unittest.skipUnless(os.environ.get('MXIOC_MIHOMO_BIN'), 'set MXIOC_MIHOMO_BIN for isolated ClientHello capture')
class NativeRealityHandshakeTests(unittest.TestCase):
    def capture(self, flag):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(2); listener.settimeout(5)
        captured, failures = [], []
        def receive():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3); raw = b''
                    while len(raw) < 5:
                        chunk = connection.recv(4096)
                        if not chunk: raise ValueError('short TLS header')
                        raw += chunk
                    length = int.from_bytes(raw[3:5], 'big') + 5
                    while len(raw) < length:
                        chunk = connection.recv(4096)
                        if not chunk: raise ValueError('short TLS record')
                        raw += chunk
                    captured.append(raw[:length])
            except Exception as exc:
                failures.append(str(exc))
        thread = threading.Thread(target=receive, daemon=True); thread.start()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0)); proxy_port = reservation.getsockname()[1]
        item = node(flag)
        item.update(server='127.0.0.1', port=listener.getsockname()[1])
        item['reality-opts']['public-key'] = core_adapter.key_pair()['publicKey']
        doc = {'mixed-port':proxy_port,'mode':'rule','log-level':'error','proxies':[item],'rules':['MATCH,manual']}
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'config.yaml'; path.write_text(server.yaml_dump(doc))
                # Exercise the actual subscription reader, including any compatibility rewrite.
                _, subscription = server.get_cached_config(path); path.write_text(subscription)
                with (Path(directory)/'mihomo.log').open('w+') as log:
                    process = subprocess.Popen([os.environ['MXIOC_MIHOMO_BIN'],'-d',directory,'-f',str(path)],stdout=log,stderr=log)
                    try:
                        deadline = time.monotonic()+5
                        while True:
                            try:
                                client = socket.create_connection(('127.0.0.1',proxy_port),timeout=.2)
                                break
                            except OSError:
                                if time.monotonic()>deadline: raise
                                time.sleep(.03)
                        with client:
                            client.sendall(b'GET http://handshake.test.invalid/ HTTP/1.1\r\nHost: handshake.test.invalid\r\n\r\n')
                            thread.join(5)
                        self.assertTrue(captured, failures)
                    finally:
                        process.terminate()
                        try: process.wait(5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait(5)
        finally:
            listener.close(); thread.join(1)
        raw = captured[0]; position = 9+2+32
        position += 1+raw[position]
        position += 2+int.from_bytes(raw[position:position+2],'big')
        position += 1+raw[position]
        end = position+2+int.from_bytes(raw[position:position+2],'big'); position += 2
        groups = []
        while position+4 <= end:
            kind = int.from_bytes(raw[position:position+2],'big')
            size = int.from_bytes(raw[position+2:position+4],'big')
            body = raw[position+4:position+4+size]; position += 4+size
            if kind == 51:
                offset = 2
                while offset+4 <= len(body):
                    group = int.from_bytes(body[offset:offset+2],'big')
                    length = int.from_bytes(body[offset+2:offset+4],'big')
                    groups.append(group); offset += 4+length
        return len(raw), groups

    def test_manual_default_and_explicit_modes_reach_wire_unchanged(self):
        default, disabled, enabled = (self.capture(flag) for flag in (None,False,True))
        self.assertNotIn(0x11ec, default[1]); self.assertNotIn(0x11ec, disabled[1])
        self.assertIn(0x11ec, enabled[1])
        self.assertGreater(enabled[0], default[0]+1000)
        print('PASS isolated Mihomo ClientHello bytes: default=%d disabled=%d hybrid=%d' % (default[0],disabled[0],enabled[0]))
