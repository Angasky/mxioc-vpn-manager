"""X-Panel DB success is not proof that HandlerService registered a UUID."""
import base64
import copy
import json
import re
import subprocess
import unittest
from unittest.mock import Mock

import panel_user_runtime as runtime
import shared_users


class PanelUserRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.client={'id':'8caf0efc-b4d4-4622-a70f-cc45e2ca9286','email':'second-subscription','flow':'xtls-rprx-vision','enable':True}
        self.peer={'id':'8048f223-cdd9-4a0b-b488-2ca263a9a41e','email':'first-subscription','enable':True}
        self.row={'id':1,'tag':'inbound-443','port':443,'protocol':'vless','settings':{'decryption':'none','clients':[self.peer,self.client]}}
        self.api=Mock();self.api.request.return_value={'api':{'listen':'127.0.0.1:10085'}}
        self.manager=Mock();self.live=False;self.scripts=[]
        def execute(ssh,record,script,**kwargs):
            self.scripts.append(script)
            if script.startswith('for candidate'):return 0,runtime.BINARIES[0]
            if ' api inbounduser ' in script:
                return 0,json.dumps({'users':[{'email':self.client['email'],'account':{'id':self.client['id'],'flow':self.client.get('flow','')}}] if self.live else [{}]})
            if ' api adu ' in script:self.live=True;return 0,'Added 1 user(s) in total.'
            raise AssertionError('unexpected operation')
        self.manager.execute.side_effect=execute

    def sync(self):return runtime.sync_user(self.manager,self.api,{},self.row,self.client)

    def test_saved_but_missing_uuid_is_added_once_and_verified_without_peer_changes(self):
        before=copy.deepcopy(self.row)
        self.assertEqual(self.sync(),{'runtimeVerified':True,'runtimeRepaired':True})
        script=next(s for s in self.scripts if ' api adu ' in s)
        subprocess.run(['bash','-n'],input=script,text=True,capture_output=True,check=True)
        encoded=re.search(r"printf '%s' ([A-Za-z0-9+/=]+)",script).group(1)
        config=json.loads(base64.b64decode(encoded))
        self.assertEqual(config['inbounds'][0]['settings']['clients'],[self.client])
        self.assertNotIn(self.peer['id'],script)
        self.assertNotIn('restart',script);self.assertNotIn(' api rmu ',script)
        self.assertEqual(self.row,before)
        self.scripts.clear();self.assertFalse(self.sync()['runtimeRepaired'])
        self.assertFalse(any(' api adu ' in s for s in self.scripts))

    def test_mismatched_runtime_credential_blocks_replacement(self):
        original=self.manager.execute.side_effect
        def execute(ssh,record,script,**kwargs):
            if ' api inbounduser ' in script:
                return 0,json.dumps({'users':[{'email':self.client['email'],'account':{'id':self.peer['id'],'flow':'xtls-rprx-vision'}}]})
            return original(ssh,record,script,**kwargs)
        self.manager.execute.side_effect=execute
        with self.assertRaisesRegex(ValueError,'停止自动修复'):self.sync()
        self.assertFalse(any(' api adu ' in s for s in self.scripts))

    def test_zero_exit_without_user_registration_is_not_reported_as_success(self):
        original=self.manager.execute.side_effect
        def execute(ssh,record,script,**kwargs):
            if ' api adu ' in script:return 0,'Added 0 user(s) in total.'
            return original(ssh,record,script,**kwargs)
        self.manager.execute.side_effect=execute
        with self.assertRaisesRegex(ValueError,'运行内核未接受'):self.sync()

    def test_api_unavailable_is_explicit_error_but_unsupported_method_is_unknown(self):
        original=self.manager.execute.side_effect
        for output in ('failed to dial: connection refused','rpc error: Unimplemented'):
            def execute(ssh,record,script,**kwargs):
                if ' api inbounduser ' in script:return 1,output
                return original(ssh,record,script,**kwargs)
            self.manager.execute.side_effect=execute
            if 'Unimplemented' in output:self.assertIsNone(self.sync()['runtimeVerified'])
            else:
                with self.assertRaisesRegex(ValueError,'无法连接'):self.sync()

    def test_loopback_only_and_old_panel_api_compatibility(self):
        self.assertEqual(runtime.api_address({'api':{'tag':'api'},'inbounds':[{'tag':'api','listen':'127.0.0.1','port':1234}]}),'127.0.0.1:1234')
        self.assertIsNone(runtime.api_address({'api':{'listen':'198.51.100.1:10085'}}))
        self.api.request.side_effect=ValueError('3x-ui 接口 HTTP 404')
        self.assertIsNone(self.sync()['runtimeVerified']);self.manager.execute.assert_not_called()

    def test_remote_panel_disable_expiry_and_quota_are_never_bypassed(self):
        changes=[{'enable':False}, {'expiryTime':1}, {'total':1,'up':1},
                 {'clientStats':[{'email':self.client['email'],'enable':False}]},
                 {'clientStats':[{'email':self.client['email'],'total':1,'up':1}]}]
        original=copy.deepcopy(self.row)
        for change in changes:
            self.row={**original,**change}
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'X-Panel'):self.sync()
        self.manager.execute.assert_not_called();self.api.request.assert_not_called()

    def test_new_uuid_preserves_existing_flow_and_does_not_copy_expiry_or_credentials(self):
        for flow in ('','xtls-rprx-vision','xtls-rprx-vision-udp443'):
            row={'protocol':'vless','streamSettings':{'security':'reality','network':'raw'},
                 'settings':{'clients':[{**self.peer,'flow':flow,'expiryTime':1,'totalGB':123}]}}
            user=shared_users.new_user(row)
            self.assertEqual(user.get('flow',''),flow);self.assertNotEqual(user['id'],self.peer['id'])
            self.assertEqual(user['expiryTime'],0);self.assertEqual(user['totalGB'],0)
