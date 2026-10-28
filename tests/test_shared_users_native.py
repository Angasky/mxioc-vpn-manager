"""Optional real local Xray authentication/stats test; no production endpoints."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPResponse
from unittest.mock import Mock

import core_adapter
import test_core_adapter as fixture


class SharedUsersNativeTests(unittest.TestCase):
    setUp = fixture.CoreAdapterTests.setUp
    initialize = fixture.CoreAdapterTests.initialize

    def port(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    def wait_port(self, port, proc):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.assertIsNone(proc.poll(), 'local native process exited before becoming ready')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2): return
            except OSError: time.sleep(.05)
        self.fail('local native process did not open its loopback port')

    def start(self, binary, config, name):
        path = Path(self.temp.name) / (name+'.json'); path.write_text(json.dumps(config))
        log = open(Path(self.temp.name)/(name+'.log'), 'w'); self.addCleanup(log.close)
        process = subprocess.Popen([binary, 'run', '-config', str(path)], stdout=log, stderr=log)
        def stop():
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        self.addCleanup(stop)
        return process

    def fetch(self, proxy_port, target_port):
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall((f'GET http://127.0.0.1:{target_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nConnection: close\r\n\r\n').encode())
            response = HTTPResponse(sock)
            response.begin()
            return response.read()

    @unittest.skipUnless(os.environ.get('MXIOC_XRAY_BIN'), 'set MXIOC_XRAY_BIN for real UUID/stats verification')
    def test_real_vless_shared_port_user_stats_and_revocation(self):
        binary = str(Path(os.environ['MXIOC_XRAY_BIN']).resolve())
        record = self.initialize('xray')
        api = core_adapter.CoreAPI(self.manager, Mock(), record)
        inbound, stats_port, first_proxy, second_proxy = [self.port() for _ in range(4)]
        import uuid
        clients = [{'id':str(uuid.uuid4()),'email':name,'enable':True} for name in ('owned-one','owned-two')]
        row = {'id':1,'tag':'shared-inbound','listen':'127.0.0.1','port':inbound,'protocol':'vless',
               'settings':{'clients':clients,'decryption':'none'},'streamSettings':{'network':'tcp','security':'none'}}
        state = {'inbounds':[row],'outbounds':[],'routing':{'rules':[]},
                 'userStats':{'listen':f'127.0.0.1:{stats_port}','binary':binary,'users':['owned-one','owned-two']}}
        api.apply(copy.deepcopy(state))
        native = copy.deepcopy(self.native)
        native['outbounds'][0]['settings'] = {'finalRules':[{'action':'allow','ip':['127.0.0.0/8']}]}
        # Real binary validates the exact configuration emitted by CoreAPI.
        check = Path(self.temp.name)/'check.json'; check.write_text(json.dumps(native))
        valid = subprocess.run([binary,'run','-test','-config',str(check)], capture_output=True, timeout=5)
        self.assertEqual(valid.returncode, 0, 'generated shared-user native config failed validation')
        server_proc = self.start(binary, native, 'server'); self.wait_port(inbound, server_proc)
        class Target(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                body = b'mxioc-shared-authentication-ok'*300
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        target = ThreadingHTTPServer(('127.0.0.1',0),Target)
        threading.Thread(target=target.serve_forever,daemon=True).start()
        self.addCleanup(target.server_close);self.addCleanup(target.shutdown)
        client = {'inbounds':[], 'outbounds':[], 'routing':{'rules':[]}}
        for n, (user, port) in enumerate(zip(clients,[first_proxy,second_proxy])):
            tag = 'user-'+str(n)
            client['inbounds'].append({'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'http','settings':{}})
            client['outbounds'].append({'tag':tag,'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':inbound,
                'users':[{'id':user['id'],'encryption':'none'}]}]}})
            client['routing']['rules'].append({'type':'field','inboundTag':[tag],'outboundTag':tag})
        client_proc = self.start(binary,client,'client');self.wait_port(first_proxy,client_proc);self.wait_port(second_proxy,client_proc)
        self.assertIn(b'mxioc-shared-authentication-ok',self.fetch(first_proxy,target.server_port))
        deadline = time.monotonic()+5
        while True:
            reading = subprocess.run([binary,'api','statsquery',f'--server=127.0.0.1:{stats_port}','--pattern=user>>>'],capture_output=True,text=True,timeout=5)
            self.assertEqual(reading.returncode,0)
            entries={r['name']:int(r.get('value',0)) for r in json.loads(reading.stdout).get('stat',[])}
            if entries.get('user>>>owned-one>>>traffic>>>downlink',0)>0:break
            if time.monotonic()>deadline:self.fail('authenticated user stats were not reported')
            time.sleep(.05)
        self.assertGreater(entries['user>>>owned-one>>>traffic>>>uplink'],0)
        self.assertEqual(entries.get('user>>>owned-two>>>traffic>>>uplink',0),0)
        self.assertEqual(entries.get('user>>>owned-two>>>traffic>>>downlink',0),0)
        # Apply the adapter's user-disable conversion. Peer keeps the same port
        # and UUID; the old user's new authentication attempts must fail.
        state['inbounds'][0]['settings']['clients'][0]['enable']=False
        api.apply(state)
        server_proc.terminate();server_proc.wait(timeout=5)
        self.native['outbounds'][0]['settings'] = {'finalRules':[{'action':'allow','ip':['127.0.0.0/8']}]}
        replacement = self.start(binary,self.native,'server-disabled');self.wait_port(inbound,replacement)
        try: denied=self.fetch(first_proxy,target.server_port)
        except (OSError,TimeoutError): denied=b''
        self.assertNotIn(b'mxioc-shared-authentication-ok',denied)
        self.assertIn(b'mxioc-shared-authentication-ok',self.fetch(second_proxy,target.server_port))

    @unittest.skipUnless(os.environ.get('MXIOC_SING_BOX_BIN'), 'set MXIOC_SING_BOX_BIN for build capability verification')
    def test_official_sing_box_build_capability_checked_before_mutation(self):
        binary = str(Path(os.environ['MXIOC_SING_BOX_BIN']).resolve())
        version = subprocess.run([binary,'version'],capture_output=True,text=True,timeout=5)
        record = self.initialize('sing-box')
        api = core_adapter.CoreAPI(self.manager,Mock(),record)
        before = copy.deepcopy(self.native)
        original = self.manager.execute.side_effect
        def execute(ssh, record, command, **kwargs):
            if command.endswith(' version'): return version.returncode,version.stdout
            return original(ssh,record,command,**kwargs)
        self.manager.execute.side_effect=execute
        if 'with_v2ray_api' not in version.stdout:
            with self.assertRaisesRegex(ValueError,'with_v2ray_api'): api.enable_user_stats('owned')
            self.assertEqual(self.native,before)
            self.assertNotIn('coreState',self.manager.record(self.identity))
        else:
            self.assertTrue(api.check_user_stats_support())
