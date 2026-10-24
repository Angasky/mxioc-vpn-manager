"""Real HTTP/cookie workflows with isolated data and a simulated remote panel.

Only the SSH/panel transport is replaced. Authentication, routes, ownership,
configuration persistence, metering, quotas and subscription exports run normally.
"""
import base64
import copy
import json
import os
import subprocess
from http.cookiejar import CookieJar
from pathlib import Path
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener

import remote_manager
import server
import test_remote_manager as remote_fixture
import test_subscription_enforcement as subscription_fixture


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        subscription_fixture.EnforcementTests.setUp(self)
        root = server.ROOT
        for name, value in dict(AUTH=root/'auth.json', SESSIONS_FILE=root/'sessions.json',
                                SESSIONS=None, LOGIN_FAILURES={}).items():
            old = getattr(server, name)
            setattr(server, name, value)
            self.addCleanup(setattr, server, name, old)
        salt, digest = server.password_hash('workflow-test-password')
        server.save_auth('admin', salt, digest)
        self.manager = remote_manager.RemoteManager(root, server.parse_node_link, server.node_to_uri)
        self.patcher.stop()
        patched = patch('server.remote_manager', return_value=self.manager)
        patched.start(); self.addCleanup(patched.stop)
        self.api = remote_fixture.FakeAPI(); self.api.ssh = Mock()
        self.manager.connect = Mock(return_value=self.api.ssh)
        self.manager.panel = Mock(return_value=self.api)
        self.manager.execute = Mock(return_value=(0, ''))
        class LocalHTTPHandler(server.Handler):
            def secure_request(self):
                return False  # Loopback-only HTTP fixture; production uses HTTPS/Nginx.
        self.httpd = server.ThreadingHTTPServer(('127.0.0.1', 0), LocalHTTPHandler)
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True); thread.start()
        self.addCleanup(self.httpd.server_close); self.addCleanup(self.httpd.shutdown)
        self.base = 'http://127.0.0.1:' + str(self.httpd.server_address[1])
        self.client = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
        self.request('POST', '/login', {'username':'admin', 'password':'workflow-test-password'})

    def request(self, method, path, data=None, profile='clash', status=200, public=False, origin=None):
        headers = {'Origin':origin or self.base, 'X-Forwarded-Proto':'http', 'X-Profile':profile}
        if data is not None: headers['Content-Type'] = 'application/json'
        request = Request(self.base + ('' if public else '/admin/api') + path,
                          data=None if data is None else json.dumps(data).encode(), headers=headers, method=method)
        try:
            response = self.client.open(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            self.assertEqual(response.code, status, response.read().decode() if response.code != status else '')
            raw = response.read()
            body = json.loads(raw) if 'application/json' in response.headers.get('Content-Type', '') and raw else raw
            return body, dict(response.headers)

    def add_server_and_node(self):
        payload = {'name':'workflow X-Panel','host':'198.51.100.20','sshPort':22,'sshUser':'root',
                   'sshPassword':'ssh-test-password','fingerprint':remote_fixture.PIN,'domain':'',
                   'connectionMode':'existing','installType':'x-panel',
                   'panelAddress':'https://panel.example.com:13145/riben/','panelUser':'admin','panelPassword':'panel-test-password'}
        saved, _ = self.request('POST', '/servers', payload)
        identity = saved['server']['id']
        attached, _ = self.request('POST', '/servers/attach', {'id':identity})
        self.assertIn('验证成功', attached['message'])
        created, _ = self.request('POST', '/servers/inbounds', {'serverId':identity, 'template':'shadowsocks', 'port':24443,'remark':'专属测试节点'})
        inbound = created['inbound']['id']
        self.request('POST', '/servers/import', {'serverId':identity,'inboundId':inbound,'indices':[0]})
        snapshot, _ = self.request('GET', '/snapshot')
        self.assertEqual(len(snapshot['nodes']), 1)
        return identity, inbound

    def test_creation_import_multiplier_bandwidth_exhaustion_and_renewal(self):
        identity, inbound = self.add_server_and_node()
        self.request('PUT', '/traffic', {'enforce':True,'upload':0,'download':0,'total':1000,'multiplier':2})
        self.request('PUT', '/servers/multiplier', {'serverId':identity,'inboundId':inbound,'multiplier':2})
        self.request('PUT', '/servers/bandwidth', {'serverId':identity,'inboundId':inbound,'uploadMbps':1,'downloadMbps':2})
        self.assertEqual(self.manager.record(identity)['bandwidths'][str(inbound)]['downloadKbps'], 2000)
        self.api.rows[0].update(up=100, down=200)
        sync, _ = self.request('POST', '/traffic/sync', {})
        self.assertEqual(sync['traffic']['used'],600); self.assertEqual(sync['traffic']['rawUsed'],300)
        self.assertEqual(sync['traffic']['remaining'],400)
        slug = server.profile_record()['slug']
        for path in ('/sub/'+slug, '/convert/'+slug+'/v2rayn', '/convert/'+slug+'/v2rayng', '/convert/'+slug+'/shadowrocket'):
            for method in ('GET','HEAD'):
                body, headers = self.request(method, path, public=True)
                self.assertEqual(headers['Subscription-Userinfo'], 'upload=200; download=400; total=1000')
                if method == 'HEAD': self.assertEqual(body,b'')
        # A different subscription cannot apply a limit to this owned inbound.
        other, _ = self.request('POST', '/profiles', {'name':'other'})
        self.request('PUT','/servers/bandwidth',{'serverId':identity,'inboundId':inbound,'uploadMbps':10},profile=other['profile']['id'],status=400)
        self.api.rows[0]['down'] = 400
        exhausted, _ = self.request('POST', '/traffic/sync', {})
        self.assertEqual(exhausted['traffic']['used'],1000)
        self.assertFalse(self.api.rows); self.assertFalse(self.manager.record(identity)['bandwidths'])
        for path in ('/sub/'+slug, '/convert/'+slug+'/v2rayn', '/convert/'+slug+'/v2rayng', '/convert/'+slug+'/shadowrocket'):
            for method in ('GET','HEAD'): self.request(method,path,public=True,status=403)
        self.request('PUT','/traffic',{'enforce':True,'total':2000,'upload':1000,'download':0,'multiplier':2})
        self.assertFalse(self.api.rows, 'renewal must not recreate credentials silently')

    def test_recreated_dedicated_endpoint_refreshes_old_named_node(self):
        identity,inbound=self.add_server_and_node()
        original=copy.deepcopy(server.read_config())
        # A newly owned inbound replaces an expired instance on the same endpoint.
        server.profile_record()['remoteNodes'][0]['status']='revoked'
        self.api.rows[0]['enable']=False
        created,_=self.request('POST','/servers/inbounds',{'serverId':identity,'template':'shadowsocks','port':24443,'remark':'专属测试节点'})
        result,_=self.request('POST','/servers/import',{'serverId':identity,'inboundId':created['inbound']['id'],'indices':[0]})
        self.assertEqual(result['updated'],1)
        doc=server.read_config()
        self.assertEqual(len(doc['proxies']),1)
        self.assertEqual(doc['proxies'][0]['name'],original['proxies'][0]['name'])
        self.assertNotEqual(doc['proxies'][0]['password'],original['proxies'][0]['password'])
        self.assertEqual(doc['proxy-groups'],original['proxy-groups'])

    def test_expiry_removes_remote_node_and_bandwidth(self):
        identity, inbound = self.add_server_and_node()
        self.request('PUT','/servers/bandwidth',{'serverId':identity,'inboundId':inbound,'downloadMbps':3})
        result, _ = self.request('PUT','/traffic',{'enforce':True,'total':1000,'expire':1})
        self.assertTrue(result['traffic']['expired'])
        server.enforce_profile('clash')  # Background worker processes the saved policy.
        self.assertFalse(self.api.rows); self.assertFalse(self.manager.record(identity)['bandwidths'])

    def test_manual_binding_remove_keeps_remote_inbound_and_subscription_node(self):
        identity, inbound = self.add_server_and_node()
        snapshot, _ = self.request('GET','/snapshot')
        binding = snapshot['profile']['traffic']['bindings'][0]
        self.manager.connect.reset_mock()
        result, _ = self.request('PUT','/traffic/bindings/remove', {
            'recordIndex':binding['recordIndex'],'recordToken':binding['recordToken'],'confirmed':True})
        self.assertEqual(result['removed'],1)
        self.assertFalse(result['traffic']['bindings'])
        self.assertEqual(len(self.api.rows),1)
        self.assertEqual(self.api.rows[0]['id'],inbound)
        snapshot, _ = self.request('GET','/snapshot')
        self.assertEqual(len(snapshot['nodes']),1)
        self.manager.connect.assert_not_called()

    def test_csrf_validation_logout_and_persisted_cookie(self):
        self.request('POST','/profiles',{'name':'bad-origin'},origin='http://untrusted.example',status=403)
        server.SESSIONS = None
        self.request('GET','/snapshot')
        self.request('POST','/logout',{})
        self.request('GET','/snapshot',status=401)

    @unittest.skipUnless(os.environ.get('MXIOC_BROWSER_TEST'), 'set MXIOC_BROWSER_TEST=1 and NODE_PATH for real UI/API test')
    def test_real_browser_quota_and_bandwidth_forms(self):
        self.add_server_and_node()
        script = Path(__file__).with_name('ui_e2e.cjs')
        with patch.object(server, 'FRONT', script.parent.parent/'index.html'), patch.object(server, 'FRONT_CACHE', None), patch.object(server, 'update_status', return_value={'available':False}):
            result = subprocess.run(['node',str(script)], env={**os.environ,'MXIOC_TEST_URL':self.base}, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(self.manager.record(self.manager.list()[0]['id']).get('bandwidths'))
        self.assertEqual(server.profile_record()['remoteNodes'][0]['multiplierUnits'], 2500)
        print(result.stdout.strip())
