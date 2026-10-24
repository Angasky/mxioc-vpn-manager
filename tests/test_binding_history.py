"""Invalid identity bindings are local history, never live remote ownership."""
import copy
import json
import unittest
from unittest.mock import Mock

import server
import test_subscription_enforcement as fixture


MESSAGE = '远端入站身份已变化，已停止自动删除，避免误删复用 ID 的节点'


class BindingHistoryTests(unittest.TestCase):
    setUp = fixture.EnforcementTests.setUp
    configure = fixture.EnforcementTests.configure

    def reused(self, expire=None):
        record = self.configure(expire=expire)
        record['traffic'].update(upload=100, download=200)
        original = {'port':4443, 'protocol':'shadowsocks',
                    'settings':{'method':'aes-128-gcm','password':'original-test-password'}}
        binding = record['remoteNodes'][0]
        binding['identityHash'] = server.remote_node_identity(original)
        row = {**original, 'id':1, 'up':500, 'down':600,
               'settings':{'method':'aes-128-gcm','password':'replacement-test-password'}}
        self.manager.inbounds.return_value = {'inbounds':[row]}
        return record, binding

    def test_reused_identity_becomes_history_without_billing_or_remote_mutation(self):
        record, binding = self.reused(expire=1)
        before = copy.deepcopy(record['traffic'])
        server.enforce_profile('clash')
        self.assertEqual(binding['status'], 'identity_changed')
        self.assertIn('invalidatedAt', binding)
        self.assertEqual(record['traffic'], before)
        self.assertEqual(server.traffic_info(record)['bindings'][0]['status'], 'identity_changed')
        self.manager.delete_inbound.assert_not_called()
        self.manager.set_bandwidth.assert_not_called()
        self.manager.update_inbound.assert_not_called()
        self.manager.disconnect_port.assert_not_called()
        self.manager.inbounds.reset_mock()
        server.enforce_profile('clash')
        self.manager.inbounds.assert_not_called()

    def test_old_active_identity_error_migrates_locally_and_survives_reload(self):
        record = self.configure()
        record['traffic'].update(upload=100, download=200)
        record['remoteNodes'][0].update(error=MESSAGE)
        before = copy.deepcopy(record['traffic'])
        server.save_profiles(server.load_profiles())
        server.PROFILES_CACHE = None
        migrated = server.profile_record()
        self.assertEqual(migrated['remoteNodes'][0]['status'], 'identity_changed')
        self.assertEqual(migrated['traffic'], before)
        persisted = json.loads(server.PROFILES_FILE.read_text())['profiles'][0]
        self.assertEqual(persisted['remoteNodes'][0]['status'], 'identity_changed')
        self.assertEqual(self.manager.mock_calls, [])

    def test_cleanup_is_local_and_preserves_live_and_other_subscription_bindings(self):
        record = self.configure()
        active = record['remoteNodes'][0]
        old = {**active, 'status':'identity_changed', 'error':MESSAGE}
        record['remoteNodes'].append(old)
        other = server.create_profile({'name':'other'})
        server.profile_record(other['id'])['remoteNodes'] = [copy.deepcopy(old)]
        before = copy.deepcopy(record['traffic'])
        result = server.cleanup_traffic_bindings({'confirmed':True})
        self.assertEqual(result['removed'], 1)
        self.assertEqual(record['remoteNodes'], [active])
        self.assertEqual(record['traffic'], before)
        self.assertEqual(len(server.profile_record(other['id'])['remoteNodes']), 1)
        self.assertEqual(self.manager.mock_calls, [])

    def test_network_error_stays_active_for_retry(self):
        record = self.configure()
        record['remoteNodes'][0]['error'] = 'offline'
        server.save_profiles(server.load_profiles())
        server.PROFILES_CACHE = None
        self.assertEqual(server.profile_record()['remoteNodes'][0]['status'], 'active')

    def test_cleanup_also_recognizes_legacy_active_identity_error(self):
        record = self.configure()
        record['remoteNodes'][0]['error'] = MESSAGE
        server.save_profiles(server.load_profiles())
        server.PROFILES_CACHE = None
        result = server.cleanup_traffic_bindings({'confirmed':True})
        self.assertEqual(result['removed'], 1)
        self.assertFalse(server.profile_record()['remoteNodes'])
        self.assertEqual(self.manager.mock_calls, [])

    def test_cached_profile_reads_do_not_rescan_binding_history(self):
        record = self.configure()
        rows = Mock()
        record['remoteNodes'] = rows
        # The already-loaded profile is the normal request hot path; only the
        # fresh disk-read migration may iterate historic bindings.
        self.assertIs(server.profile_record(), record)
        rows.__iter__ = Mock(side_effect=AssertionError('cached history rescan'))
        self.assertIs(server.profile_record(), record)
        rows.__iter__.assert_not_called()
