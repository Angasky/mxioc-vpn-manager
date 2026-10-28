import base64
import copy
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        config = root / 'clash.yaml'
        config.write_text(server.yaml_dump(server.minimal_profile_config()))
        values = dict(ROOT=root, PROFILES_FILE=root / 'profiles.json', PROFILES_DIR=root / 'profiles',
                      PROFILES_CACHE=None, PROFILES_MTIME=0, CONFIG_CACHE={}, FILES=[config],
                      BACKUP_DIR=root / 'backups', BUNDLED_TEMPLATE=root / 'missing')
        for name, value in values.items():
            original = getattr(server, name)
            setattr(server, name, value)
            self.addCleanup(setattr, server, name, original)
        previous = getattr(server.CTX, 'profile', 'clash')
        server.CTX.profile = 'clash'
        self.addCleanup(setattr, server.CTX, 'profile', previous)
        server.load_profiles()
        self.manager = Mock()
        self.manager.inbounds.return_value = {'inbounds': [{'id': 1, 'port': 4443, 'up': 0, 'down': 0}]}
        self.manager.delete_inbound.return_value = {'deleted': True}
        self.patcher = patch('server.remote_manager', return_value=self.manager)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def configure(self, total=1000, expire=None):
        record = server.profile_record()
        record['traffic'] = {'enabled': True, 'enforce': True, 'upload': 0, 'download': 0,
                             'total': total, 'expire': expire}
        record['remoteNodes'] = [{'serverId': 'server-a', 'inboundId': 1, 'port': 4443,
                                  'status': 'active', 'up': 0, 'down': 0}]
        server.save_profiles(server.load_profiles())
        return record

    def test_accumulate_deltas_reset_and_no_double_counting(self):
        record = self.configure(total=10000)
        self.manager.inbounds.return_value['inbounds'][0].update(up=100, down=200)
        server.enforce_profile('clash')
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'], 300)
        self.manager.inbounds.return_value['inbounds'][0].update(up=10, down=20)
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'], 330)
        self.manager.delete_inbound.assert_not_called()
        server.PROFILES_CACHE = None
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(server.profile_record())['used'], 330)

    def test_user_counter_migration_never_bills_old_total_or_inbound_noise(self):
        record=self.configure(total=10000)
        binding=record['remoteNodes'][0];binding.update(up=9000,down=1000)
        row=self.manager.inbounds.return_value['inbounds'][0]
        row.update(up=10000,down=2000,settings={'clients':[{'email':'owned','enable':True}]},
                   clientStats=[{'email':'owned','up':300,'down':200}])
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'],0)
        self.assertEqual(binding['counterSource'],'authenticated-client')
        row.update(up=20000,down=4000)
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'],0)
        row['clientStats'][0]['up']=310
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'],10)
        self.assertEqual(binding['lastRawDelta'],10)

    def test_missing_user_counters_pause_billing_instead_of_charging_inbound(self):
        record=self.configure()
        self.manager.inbounds.return_value['inbounds'][0].update(up=999,down=999,
            settings={'clients':[{'email':'owned'}]},clientStats=[])
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'],0)
        self.assertIn('计数缺失',record['enforcementError'])

    def test_detach_server_preserves_remote_and_stops_local_enforcement(self):
        self.configure()
        self.manager.record.return_value = {'bandwidths': {'1': {}}}
        with self.assertRaisesRegex(ValueError, '请确认'):
            server.detach_remote_server('server-a')
        result = server.detach_remote_server('server-a', True)
        self.assertEqual(result, {'detachedBindings': 1, 'remotePreserved': True})
        self.manager.remove.assert_called_once_with('server-a', detach=True)
        self.assertEqual(server.profile_record()['remoteNodes'][0]['status'], 'detached')
        server.enforce_profile('clash')
        self.manager.inbounds.assert_not_called()
        self.manager.delete_inbound.assert_not_called()
        self.manager.set_bandwidth.assert_not_called()

    def test_failed_detach_restores_local_bindings(self):
        self.configure()
        self.manager.record.return_value = {}
        self.manager.remove.side_effect = ValueError('安装任务进行中')
        with self.assertRaisesRegex(ValueError, '安装任务'):
            server.detach_remote_server('server-a', True)
        self.assertEqual(server.profile_record()['remoteNodes'][0]['status'], 'active')

    def test_combined_inbounds_exhaustion_deletes_only_owned_nodes(self):
        record = self.configure(total=500)
        record['remoteNodes'].append({'serverId': 'server-a', 'inboundId': 2, 'port': 4444,
                                      'status': 'active', 'up': 0, 'down': 0})
        other = server.create_profile({'name': 'other'})
        server.profile_record(other['id'])['remoteNodes'] = [{'serverId': 'server-a', 'inboundId': 3,
                                                            'port': 4445, 'status': 'active'}]
        self.manager.inbounds.return_value = {'inbounds': [{'id': 1, 'up': 100, 'down': 150},
                                                           {'id': 2, 'up': 100, 'down': 150},
                                                           {'id': 3, 'up': 9000, 'down': 9000}]}
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'], 500)
        self.assertTrue(server.subscription_blocked(record))
        self.assertEqual([c.args[1] for c in self.manager.delete_inbound.call_args_list], [1, 2])
        self.assertEqual(self.manager.disconnect_port.call_count, 2)
        self.assertEqual(server.profile_record(other['id'])['remoteNodes'][0]['status'], 'active')
        server.enforce_profile('clash')
        self.assertEqual(self.manager.delete_inbound.call_count, 2)

    def test_expiry_still_revokes_if_traffic_snapshot_fails_and_retries(self):
        record = self.configure(expire=int(time.time()) - 1)
        self.manager.inbounds.side_effect = ValueError('offline')
        self.manager.delete_inbound.side_effect = [ValueError('delete failed'), {'deleted': True}]
        server.enforce_profile('clash')
        self.assertTrue(record['accessRevoked'])
        self.assertEqual(record['remoteNodes'][0]['status'], 'active')
        self.assertIn('delete failed', record['enforcementError'])
        server.PROFILES_CACHE = None
        server.enforce_profile('clash')
        self.assertEqual(server.profile_record()['remoteNodes'][0]['status'], 'revoked')

    def test_exclusive_binding_and_baseline(self):
        first = server.bind_remote_node('server-a', 1)
        self.assertEqual(first['up'], 0)
        second = server.create_profile({'name': 'other'})
        with self.assertRaisesRegex(ValueError, '其他订阅'):
            server.bind_remote_node('server-a', 1, second['id'])
        self.assertEqual(len(server.profile_record()['remoteNodes']), 1)

    def test_enforcement_needs_owned_inbound_and_renewal_does_not_recreate(self):
        with self.assertRaisesRegex(ValueError, '独立用户'):
            server.update_traffic({'enforce': True, 'total': 1000})
        record = self.configure(expire=int(time.time()) - 1)
        server.enforce_profile('clash')
        server.update_traffic({'enforce': True, 'total': 10000, 'expire': int(time.time()) + 1000})
        self.assertFalse(server.subscription_blocked(record))
        self.assertEqual(record['remoteNodes'][0]['status'], 'revoked')
        self.manager.create_inbound.assert_not_called()

    def test_expired_and_exhausted_subscriptions_get_and_head_are_denied_all_formats(self):
        self.configure(total=1)
        server.profile_record()['traffic']['upload'] = 1
        httpd = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        record = server.profile_record()
        for path in ('/sub/' + record['slug'], '/convert/' + record['slug'] + '/v2ray',
                     '/convert/' + record['slug'] + '/shadowrocket'):
            for method in ('GET', 'HEAD'):
                with self.subTest(path=path, method=method), self.assertRaises(HTTPError) as error:
                    urlopen(Request('http://127.0.0.1:' + str(httpd.server_address[1]) + path, method=method), timeout=3)
                self.assertEqual(error.exception.code, 403)

    def test_unregistered_chain_refuses_without_remote_mutation(self):
        doc = server.minimal_profile_config()
        doc['proxies'] = [{'name': 'entry', 'type': 'ss', 'server': '198.51.100.1', 'port': 443,
                           'cipher': 'aes-128-gcm', 'password': 'a'},
                          {'name': 'exit', 'type': 'ss', 'server': '198.51.100.2', 'port': 443,
                           'cipher': 'aes-128-gcm', 'password': 'b'}]
        server.FILES[0].write_text(server.yaml_dump(doc))
        self.manager.list.return_value = []
        with self.assertRaisesRegex(ValueError, 'Mihomo'):
            server.mutate_chain('POST', {'mode': 'server', 'name': 'chain', 'entry': 'entry', 'exit': 'exit'})
        self.manager.create_relay.assert_not_called()

    def test_server_chain_creates_exportable_owned_node_and_removes_it(self):
        doc = server.minimal_profile_config()
        entry = {'name': 'entry', 'type': 'ss', 'server': '198.51.100.1', 'port': 443,
                 'cipher': 'aes-128-gcm', 'password': 'a'}
        exit_node = {**entry, 'name': 'exit', 'server': '198.51.100.2', 'password': 'b'}
        generated = {**entry, 'name': 'generated', 'port': 24443, 'password': 'generated-pass'}
        doc['proxies'] = [entry, exit_node]
        server.FILES[0].write_text(server.yaml_dump(doc))
        self.manager.list.return_value = [{'id': 'entry-server', 'host': entry['server']},
                                           {'id': 'exit-server', 'host': exit_node['server']}]
        self.manager.inbounds.side_effect = lambda identity: {'inbounds': [{'id': 7, 'port': 443,
            'shareLinks': [server.node_to_uri(entry if identity == 'entry-server' else exit_node)]}]}
        self.manager.create_relay.return_value = {'inbound': {'id': 50, 'port': 24443, 'remark': 'chain'},
                                                'shareLinks': [server.node_to_uri(generated)]}
        server.mutate_chain('POST', {'mode': 'server', 'name': 'chain', 'entry': 'entry', 'exit': 'exit', 'port': 24443})
        chain = next(n for n in server.read_config()['proxies'] if n['name'] == 'chain')
        self.assertNotIn('dialer-proxy', chain)
        self.assertTrue(server.node_to_uri(chain).startswith('ss://'))
        self.assertEqual(server.profile_record()['remoteNodes'][0]['inboundId'], 50)
        server.remove_server_chain('chain')
        self.manager.delete_inbound.assert_called_once_with('entry-server', 50)
        self.assertFalse(server.profile_record()['serverChains'])
        self.assertFalse(any(n['name'] == 'chain' for n in server.read_config()['proxies']))

    def test_reused_remote_id_is_not_deleted(self):
        record = self.configure(expire=int(time.time()) - 1)
        original = {'port': 4443, 'protocol': 'shadowsocks',
                    'settings': '{"method":"aes-128-gcm","password":"original"}'}
        record['remoteNodes'][0]['identityHash'] = server.remote_node_identity(original)
        self.manager.inbounds.return_value = {'inbounds': [{**original, 'id': 1,
            'settings': '{"method":"aes-128-gcm","password":"different-user"}', 'up': 0, 'down': 0}]}
        server.enforce_profile('clash')
        self.manager.delete_inbound.assert_not_called()
        self.assertIn('身份已变化', record['enforcementError'])
        self.assertTrue(server.subscription_blocked(record))

    def test_owned_node_credentials_are_not_copied_between_profiles(self):
        self.configure()
        with self.assertRaisesRegex(ValueError, '不能复制凭证'):
            server.create_profile({'name': 'shared-by-mistake', 'templateId': 'clash'})


if __name__ == '__main__':
    unittest.main()
