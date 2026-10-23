import base64
import copy
import contextlib
import io
import socket
import json
import re
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

import core_adapter
import remote_manager as remote
import server


class CoreAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = remote.RemoteManager(Path(self.temp.name), server.parse_node_link, server.node_to_uri)
        self.native = {}
        self.scripts = []
        self.fail_apply = False

    def initialize(self, kind):
        saved = self.manager.save({'name': kind, 'host': '198.51.100.30', 'sshUser': 'root',
            'sshPassword': 'ssh-secret', 'fingerprint': 'SHA256:' + 'a' * 43, 'installType': kind})
        self.identity = saved['id']
        self.native = {'inbounds': [], 'outbounds': [{'tag': 'existing-direct',
                       ('type' if kind == 'sing-box' else 'protocol'): ('direct' if kind == 'sing-box' else 'freedom')}]}
        self.native['route' if kind == 'sing-box' else 'routing'] = {'rules': []}
        self.manager.connect = Mock(return_value=Mock())
        def execute(ssh, record, script, **kwargs):
            if script.startswith('base64 < '):
                return 0, base64.b64encode(json.dumps(self.native).encode()).decode()
            self.scripts.append(script)
            subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True, check=True)
            if self.fail_apply:
                return 22, 'invalid'
            match = re.search(r"printf '%s' '([A-Za-z0-9+/=]+)'", script)
            if match:
                self.native = json.loads(base64.b64decode(match[1]))
            return 0, ''
        self.manager.execute = Mock(side_effect=execute)
        return self.manager.record(self.identity)

    def test_attach_existing_cores_only_reads_and_validates(self):
        for kind in ('xray', 'sing-box'):
            with self.subTest(kind=kind):
                record = self.initialize(kind)
                saved = self.manager.save({'id': self.identity, 'name': kind, 'host': record['host'],
                    'sshUser': 'root', 'fingerprint': record['fingerprint'], 'installType': kind,
                    'connectionMode': 'existing'})
                before = copy.deepcopy(self.native)
                result = self.manager.attach_existing(self.identity)
                with patch('remote_manager.threading.Thread') as worker:
                    with self.assertRaisesRegex(ValueError, '不会执行安装'):
                        self.manager.start_install(self.identity, True)
                worker.assert_not_called()
                self.assertTrue(result['server']['existingVerifiedAt'])
                self.assertIn('验证成功', result['message'])
                self.assertEqual(self.native, before)
                self.assertEqual(self.manager.secret(self.manager.record(self.identity), 'panelPassword'), '')
                self.assertTrue(any('systemctl is-active --quiet ' + kind in cmd for cmd in self.scripts))
                for cmd in self.scripts:
                    for forbidden in ('restart', 'curl ', 'printf ', 'mv ', 'cp '):
                        self.assertNotIn(forbidden, cmd)
                self.manager.remove(self.identity)
                self.scripts.clear()

    def test_existing_core_validation_failure_never_marks_verified_or_installs(self):
        record = self.initialize('xray')
        self.manager.save({'id': self.identity, 'name': 'xray', 'host': record['host'],
            'sshUser': 'root', 'fingerprint': record['fingerprint'], 'installType': 'xray',
            'connectionMode': 'existing'})
        self.fail_apply = True
        with self.assertRaisesRegex(ValueError, '已有 xray 验证失败'):
            self.manager.attach_existing(self.identity)
        self.assertFalse(self.manager.record(self.identity).get('existingVerifiedAt'))
        with self.assertRaisesRegex(ValueError, '请勿提交安装用 JSON'):
            self.manager.save({'id': self.identity, 'name': 'xray', 'host': record['host'],
                'sshUser': 'root', 'fingerprint': record['fingerprint'], 'installType': 'xray',
                'connectionMode': 'existing', 'coreConfig': '{"inbounds":[],"outbounds":[]}'})

    def test_templates_and_relay_preserve_unmanaged_configuration(self):
        for kind in ('xray', 'sing-box'):
            with self.subTest(kind=kind):
                record = self.initialize(kind)
                payload = {'port': 24443, 'remark': 'chain', 'serverName': 'www.microsoft.com',
                           'landingLink': 'socks5://user:pass@198.51.100.40:1080#landing'}
                original = copy.deepcopy(self.native['outbounds'][0])
                result = self.manager.create_relay(self.identity, payload)
                self.assertEqual(len(self.native['inbounds']), 1)
                self.assertEqual(self.native['outbounds'][0], original)
                self.assertEqual(len(self.native['outbounds']), 2)
                self.assertTrue(result['shareLinks'][0].startswith('vless://'))
                self.assertNotIn('privateKey', self.manager.path.read_text())
                rows = self.manager.inbounds(self.identity)['inbounds']
                self.assertEqual(rows[0]['id'], result['inbound']['id'])
                self.manager.delete_inbound(self.identity, result['inbound']['id'])
                self.assertEqual(self.native['inbounds'], [])
                self.assertEqual(self.native['outbounds'], [original])
                key = 'route' if kind == 'sing-box' else 'routing'
                self.assertEqual(self.native[key]['rules'], [])
                self.manager.remove(self.identity)

    def test_failed_apply_does_not_persist_state_or_report_success(self):
        self.initialize('sing-box')
        self.fail_apply = True
        with self.assertRaisesRegex(ValueError, '22'):
            self.manager.create_inbound(self.identity, {'port': 24443, 'template': 'shadowsocks'})
        self.assertNotIn('coreState', self.manager.record(self.identity))
        self.assertEqual(self.native['inbounds'], [])

    def test_disable_and_port_conflict(self):
        self.initialize('xray')
        result = self.manager.create_inbound(self.identity, {'port': 24443, 'template': 'shadowsocks'})
        with self.assertRaisesRegex(ValueError, '监听端口'):
            self.manager.create_inbound(self.identity, {'port': 24443, 'template': 'shadowsocks'})
        self.manager.update_inbound(self.identity, result['inbound']['id'], {**result['inbound'], 'enable': False})
        self.assertEqual(self.native['inbounds'], [])
        self.assertFalse(self.manager.inbounds(self.identity)['inbounds'][0]['enable'])

    def test_xpanel_chinese_settings_and_existing_mode(self):
        output = '\x1b[32mport（端口号）: 2053\x1b[0m\nwebBasePath（访问路径）: /panel-secret/\ncert: /etc/cert.pem\n'
        settings = remote.parse_panel_settings(output, {'host': '198.51.100.5', 'domain': 'panel.example.com'})
        self.assertEqual(settings['panelUrl'], 'https://panel.example.com:2053/panel-secret/')
        saved = self.manager.save({'name': 'X-Panel', 'host': '198.51.100.5', 'sshUser': 'root',
            'sshPassword': 'ssh', 'fingerprint': 'SHA256:' + 'a' * 43, 'installType': 'x-panel',
            'connectionMode': 'existing', 'panelUser': 'a', 'panelPassword': 'old'})
        with self.assertRaisesRegex(ValueError, '不会执行'):
            self.manager.start_install(saved['id'], True)

    def test_meter_failure_never_becomes_zero_usage(self):
        record = self.initialize('sing-box')
        record['meters'] = {'42': 24443}
        self.manager.execute = Mock(return_value=(1, ''))
        with self.assertRaisesRegex(ValueError, '不可核实'):
            self.manager.meter_snapshot(record, Mock())
        self.manager.execute.return_value = (0, '{"nftables": []}')
        with self.assertRaisesRegex(ValueError, '缺失'):
            self.manager.meter_snapshot(record, Mock())

    def test_meter_rule_setup_is_valid_shell_and_restored_on_boot(self):
        self.initialize('sing-box')
        result = self.manager.create_inbound(self.identity, {'port': 24443, 'template': 'shadowsocks'})
        self.manager.ensure_meter(self.identity, result['inbound']['id'])
        script = self.scripts[-1]
        self.assertIn('mxioc-meter-restore.service', script)
        self.assertIn('nft -s list table inet mxioc_usage', script)
        self.assertEqual(self.manager.record(self.identity)['meters'][str(result['inbound']['id'])], 24443)

    def test_sni_probe_runs_remote_tls_and_rejects_private_dns(self):
        self.initialize('xray')
        def execute(ssh, record, script, **kwargs):
            probe = script.split("MXIOC_SNI'\n", 1)[1].rsplit('\nMXIOC_SNI', 1)[0]
            output = io.StringIO()
            connection = MagicMock()
            tls = MagicMock()
            tls.__enter__.return_value.version.return_value = 'TLSv1.3'
            tls.__enter__.return_value.selected_alpn_protocol.return_value = 'h2'
            context = MagicMock()
            context.wrap_socket.return_value = tls
            def addresses(host, port, **kwargs):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '',
                         ('127.0.0.1' if host == 'private.example.com' else '8.8.8.8', 443))]
            with contextlib.redirect_stdout(output), patch('socket.getaddrinfo', side_effect=addresses), \
                    patch('socket.socket', return_value=connection), patch('ssl.create_default_context', return_value=context):
                exec(compile(probe, '<remote-sni-probe>', 'exec'), {})
            return 0, output.getvalue()
        self.manager.execute = Mock(side_effect=execute)
        self.manager.verify_reality_snis = Mock(side_effect=lambda ssh, record, result: result)
        result = self.manager.test_sni(self.identity, ['public.example.com', 'private.example.com'])
        public, private = result['results']
        self.assertTrue(public['ok'])
        self.assertEqual(public['tls'], 'TLSv1.3')
        self.assertFalse(private['ok'])
        self.assertIn('非公网', private['error'])
        with self.assertRaises(ValueError):
            self.manager.test_sni(self.identity, ['example.com; id'])

    def test_sni_without_python_uses_validated_pinned_curl(self):
        self.initialize('xray')
        calls=[]
        def execute(ssh, record, script, **kwargs):
            calls.append(script)
            if 'MXIOC_SNI' in script:return 127,'python3: not found'
            if 'getent ahosts' in script:return 0,'public.example.com 8.8.8.8\nprivate.example.com 127.0.0.1\n'
            self.assertIn('--resolve public.example.com:443:8.8.8.8',script)
            self.assertIn('--tlsv1.3 --tls-max 1.3',script)
            self.assertNotIn('--insecure',script)
            self.assertNotIn('private.example.com',script)
            return 0,'0.123'
        self.manager.execute=Mock(side_effect=execute)
        self.manager.verify_reality_snis=Mock(side_effect=lambda ssh,record,result:result)
        result=self.manager.test_sni(self.identity,['public.example.com','private.example.com'])
        self.assertEqual(result['method'],'curl')
        self.assertEqual(result['results'][0]['latencyMs'],123)
        self.assertFalse(result['results'][1]['ok'])

    def test_tls_success_is_not_enough_for_reality_selection(self):
        self.initialize('xray')
        self.manager.execute=Mock(return_value=(0,'MXIOC_REALITY_RESULT 0 FAIL\n'))
        data={'results':[{'domain':'public.example.com','ok':True,'address':'8.8.8.8','latencyMs':10}]}
        result=self.manager.verify_reality_snis(Mock(),self.manager.record(self.identity),data)
        self.assertFalse(result['results'][0]['ok'])
        self.assertFalse(result['results'][0]['realityVerified'])
        self.assertIn('两次',result['results'][0]['error'])

    def test_reality_probe_is_loopback_only_cached_and_has_cleanup(self):
        self.initialize('xray')
        self.manager.execute=Mock(return_value=(0,'MXIOC_REALITY_RESULT 0 OK\n'))
        row={'domain':'public.example.com','ok':True,'address':'8.8.8.8'}
        for _ in range(2):
            result=self.manager.verify_reality_snis(Mock(),self.manager.record(self.identity),{'results':[row]})
            self.assertTrue(result['results'][0]['realityVerified'])
        self.manager.execute.assert_called_once()
        script=self.manager.execute.call_args.args[2]
        self.assertIn('trap cleanup EXIT',script);self.assertIn('timeout 75',script)
        self.assertIn('for attempt in 1 2',script);self.assertIn('reality-probe.invalid',script)
        self.assertNotIn('0.0.0.0',script)
        subprocess.run(['bash','-n'],input=script,text=True,check=True)

    def test_batch_partial_failure_is_not_selectable_and_force_bypasses_cache(self):
        self.initialize('xray')
        self.manager.execute=Mock(return_value=(0,'MXIOC_REALITY_RESULT 0 OK\nMXIOC_REALITY_RESULT 1 FAIL\n'))
        rows=[{'domain':name,'ok':True,'address':'8.8.8.8'} for name in ('good.example.com','bad.example.com')]
        for _ in range(2):
            result=self.manager.verify_reality_snis(Mock(),self.manager.record(self.identity),{'results':rows})
            self.assertTrue(result['results'][0]['realityVerified'])
            self.assertEqual(result['results'][0]['verifiedAddress'],'8.8.8.8')
            self.assertFalse(result['results'][1]['ok'])
        self.manager.execute.assert_called_once()
        self.manager.verify_reality_snis(Mock(),self.manager.record(self.identity),{'results':rows},force=True)
        self.assertEqual(self.manager.execute.call_count,2)

    def test_tls_probe_retries_an_unreachable_first_ipv6_address(self):
        self.initialize('xray')
        def execute(ssh,record,script,**kwargs):
            probe=script.split("MXIOC_SNI'\n",1)[1].rsplit('\nMXIOC_SNI',1)[0]
            first,second=MagicMock(),MagicMock()
            first.__enter__.return_value=first;second.__enter__.return_value=second
            first.connect.side_effect=OSError('IPv6 route unavailable')
            tls=MagicMock();tls.__enter__.return_value.version.return_value='TLSv1.3'
            tls.__enter__.return_value.selected_alpn_protocol.return_value='h2'
            context=MagicMock();context.wrap_socket.return_value=tls
            addresses=[(socket.AF_INET6,socket.SOCK_STREAM,6,'',('2606:4700:4700::1111',443,0,0)),
                       (socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]
            output=io.StringIO()
            with contextlib.redirect_stdout(output),patch('socket.getaddrinfo',return_value=addresses), \
                    patch('socket.socket',side_effect=[first,second]),patch('ssl.create_default_context',return_value=context):
                exec(compile(probe,'<fallback-address-test>','exec'),{})
            first.connect.assert_called_once();second.connect.assert_called_once()
            return 0,output.getvalue()
        self.manager.execute=Mock(side_effect=execute)
        self.manager.verify_reality_snis=Mock(side_effect=lambda ssh,record,result:result)
        result=self.manager.test_sni(self.identity,['example.com'])
        self.assertTrue(result['results'][0]['ok'])
        self.assertEqual(result['results'][0]['address'],'8.8.8.8')

    def test_python_free_tls_probe_retries_public_addresses(self):
        self.initialize('xray')
        def execute(ssh,record,script,**kwargs):
            if 'MXIOC_SNI' in script:return 127,'python missing'
            if 'getent ahosts' in script:return 0,'example.com 1.1.1.1\nexample.com 8.8.8.8\n'
            if 'example.com:443:1.1.1.1' in script:return 28,'timeout'
            self.assertIn('example.com:443:8.8.8.8',script)
            return 0,'0.080'
        self.manager.execute=Mock(side_effect=execute)
        self.manager.verify_reality_snis=Mock(side_effect=lambda ssh,record,result:result)
        result=self.manager.test_sni(self.identity,['example.com'])
        self.assertTrue(result['results'][0]['ok'])
        self.assertEqual(result['results'][0]['address'],'8.8.8.8')
        self.assertNotIn('error',result['results'][0])

    def test_incomplete_batch_does_not_cache_or_select_missing_results(self):
        self.initialize('xray')
        self.manager.execute=Mock(return_value=(0,''))
        row={'domain':'example.com','ok':True,'address':'8.8.8.8'}
        result=self.manager.verify_reality_snis(Mock(),self.manager.record(self.identity),{'results':[row]})
        self.assertFalse(result['results'][0]['ok'])
        self.assertIn('未返回',result['results'][0]['error'])
        self.assertFalse(self.manager.sni_cache)

    def test_forced_failed_tls_invalidates_previous_success(self):
        self.initialize('xray')
        import time
        record=self.manager.record(self.identity)
        key=(record['id'],record.get('fingerprint'),'example.com','8.8.8.8')
        self.manager.sni_cache[key]=(time.monotonic(),True)
        result=self.manager.verify_reality_snis(Mock(),record,{'results':[{'domain':'example.com','ok':False,'error':'TLS failed'}]},force=True)
        self.assertFalse(result['results'][0]['ok'])
        self.assertNotIn(key,self.manager.sni_cache)


if __name__ == '__main__':
    unittest.main()
