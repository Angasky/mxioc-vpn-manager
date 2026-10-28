"""Shared inbound regression: one subscription must never operate on its peers."""
import copy
import json
import unittest
from unittest.mock import Mock, patch

import server
import shared_users as users
import remote_manager as remote
import test_subscription_enforcement as fixture
import test_remote_manager as remote_fixture
import test_core_adapter as core_fixture


class SharedUserTests(unittest.TestCase):
    setUp = fixture.EnforcementTests.setUp

    def row(self):
        row = {'id': 1, 'port': 4443, 'protocol': 'vless', 'remark': 'shared',
               'enable': True, 'tag': 'inbound-4443', 'listen': '',
               'streamSettings': {'network': 'tcp', 'security': 'none'},
               'settings': {'clients': [{'id': '6a5a8f80-b82e-4afd-bf96-0919eb3b25b2', 'email': 'peer', 'enable': True}]},
               'up': 999999, 'down': 999999, 'clientStats': [{'email': 'peer', 'up': 9000, 'down': 9000}]}
        self.manager.inbounds.return_value = {'inbounds': [row]}
        def mutate(sid, binding, operation, client=None):
            current = users.find_user(row, binding, missing_ok=operation in ('add', 'remove'))
            if operation == 'add' and current is None:
                row['settings']['clients'].append(copy.deepcopy(client))
                row['clientStats'].append({'email': client['email'], 'up': 0, 'down': 0})
            elif operation == 'remove':
                row['settings']['clients'] = [c for c in row['settings']['clients'] if c['email'] != binding['userEmail']]
            elif operation in ('pause', 'resume'):
                next(c for c in row['settings']['clients'] if c['email'] == binding['userEmail'])['enable'] = operation == 'resume'
            if operation == 'remove':
                return {'removed': True}
            user = users.find_user(row, binding)
            return {'shareLinks': [server.node_to_uri({'type': 'vless', 'name': 'shared', 'server': '198.51.100.1',
                                                      'port': 4443, 'uuid': user['id']})]}
        self.manager.subscription_user.side_effect = mutate
        return row

    def provision(self):
        return server.provision_subscription_user({'serverId': 's', 'inboundId': 1})

    def traffic(self, total=10000, expire=None):
        record = server.profile_record()
        record['traffic'] = {'enabled': True, 'enforce': True, 'total': total, 'expire': expire,
                             'upload': 0, 'download': 0}
        return record

    def test_two_subscriptions_share_one_port_but_receive_distinct_users(self):
        row = self.row()
        first = self.provision()
        first_uuid = server.read_config()['proxies'][0]['uuid']
        other = server.create_profile({'name': 'second'})
        server.CTX.profile = other['id']
        second = self.provision()
        self.assertNotEqual(first['binding']['userEmail'], second['binding']['userEmail'])
        self.assertNotEqual(first_uuid, server.read_config()['proxies'][0]['uuid'])
        self.assertEqual(len(row['settings']['clients']), 3)
        self.manager.create_inbound.assert_not_called()
        self.manager.ensure_meter.assert_not_called()
        self.manager.delete_inbound.assert_not_called()
        self.assertEqual(self.provision()['added'], 0)
        self.assertEqual(len(row['settings']['clients']), 3)

    def test_user_only_billing_multiplier_and_expiry_preserve_peer(self):
        row = self.row(); self.provision(); record = self.traffic()
        binding = record['remoteNodes'][0]; binding['multiplierUnits'] = 2000
        own = next(s for s in row['clientStats'] if s['email'] == binding['userEmail'])
        own.update(up=100, down=50)
        server.enforce_profile('clash'); server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'], 300)
        # Add/remove a peer must not invalidate this user's ownership.
        row['settings']['clients'].append({'id': 'new-peer', 'email': 'new-peer'})
        record['traffic']['expire'] = 1
        server.enforce_profile('clash')
        self.assertEqual(binding['status'], 'revoked')
        self.assertEqual([c['email'] for c in row['settings']['clients']], ['peer', 'new-peer'])
        self.manager.delete_inbound.assert_not_called()
        self.manager.disconnect_port.assert_not_called()
        self.manager.set_bandwidth.assert_not_called()

    def test_total_exhaustion_revokes_only_user_even_if_counters_disappear(self):
        row = self.row(); self.provision(); record = self.traffic(total=100)
        row['clientStats'][-1].update(up=101)
        server.enforce_profile('clash')
        self.assertEqual(record['remoteNodes'][0]['status'], 'revoked')
        self.assertEqual(len(row['settings']['clients']), 1)
        self.manager.delete_inbound.assert_not_called()

    def test_expiry_works_without_user_stats_and_without_server_snapshot(self):
        for offline in (False, True):
            with self.subTest(offline=offline):
                row = self.row(); self.provision(); record = self.traffic(expire=1)
                row.pop('clientStats')
                if offline:
                    self.manager.inbounds.side_effect = ValueError('offline')
                server.enforce_profile('clash')
                self.assertEqual(record['remoteNodes'][-1]['status'], 'revoked')
                self.manager.inbounds.side_effect = None
                self.manager.delete_inbound.assert_not_called()
                record['remoteNodes'] = []; record.pop('accessRevoked', None); record.pop('traffic')

    def test_missing_stats_never_charge_shared_port_total(self):
        row = self.row(); self.provision(); record = self.traffic()
        row['clientStats'] = []
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'], 0)
        self.assertIn('计数缺失', record['enforcementError'])

    def test_monthly_pause_and_resume_do_not_disable_inbound_or_disconnect_peers(self):
        row = self.row(); self.provision(); record = self.traffic(total=100)
        binding = record['remoteNodes'][0]
        record['traffic']['resetPeriod'] = 'monthly'
        row['clientStats'][-1].update(up=101)
        server.enforce_profile('clash')
        self.assertTrue(binding['monthlyPaused'])
        self.assertFalse(row['settings']['clients'][-1]['enable'])
        self.assertTrue(row['enable']); self.assertTrue(row['settings']['clients'][0]['enable'])
        record['traffic'].update(upload=0, download=0, total=1000)
        server.enforce_profile('clash')
        self.assertNotIn('monthlyPaused', binding)
        self.assertTrue(row['settings']['clients'][-1]['enable'])
        self.manager.disconnect_port.assert_not_called(); self.manager.update_inbound.assert_not_called()

    def test_identity_change_blocks_billing_pause_and_revocation(self):
        for change in ('user', 'stream'):
            row = self.row(); self.provision(); record = self.traffic(expire=1)
            if change == 'user':
                row['settings']['clients'][-1]['id'] = 'replacement-uuid'
            else:
                row['streamSettings']['network'] = 'ws'
            self.manager.subscription_user.reset_mock()
            server.enforce_profile('clash')
            self.assertEqual(record['remoteNodes'][-1]['status'], 'identity_changed')
            self.manager.subscription_user.assert_not_called()
            self.manager.delete_inbound.assert_not_called()
            record['remoteNodes'] = []; record.pop('accessRevoked', None); record.pop('traffic')

    def test_ambiguous_creation_is_recovered_without_allocating_another_uuid(self):
        row = self.row(); mutate = self.manager.subscription_user.side_effect
        def fail_after_apply(*args, **kwargs):
            result = mutate(*args, **kwargs)
            if args[2] == 'add':
                raise ValueError('timeout')
            return result
        self.manager.subscription_user.side_effect = fail_after_apply
        with self.assertRaisesRegex(ValueError, '待核对'): self.provision()
        binding = server.profile_record()['remoteNodes'][0]
        self.assertEqual(binding['status'], 'provisioning')
        self.manager.subscription_user.side_effect = mutate
        self.provision()
        self.assertEqual(len(row['settings']['clients']), 2)
        self.assertEqual(binding['status'], 'active')
        self.assertEqual(len(server.profile_record()['remoteNodes']), 1)

    def test_failed_local_ownership_save_never_grants_remote_access(self):
        self.row()
        with patch('server.save_profiles', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.provision()
        self.manager.subscription_user.assert_not_called()

    def test_speed_limits_rejected_before_port_or_remote_operations(self):
        self.row(); self.provision(); self.manager.reset_mock()
        with self.assertRaisesRegex(ValueError, '共用入站'):
            server.set_node_bandwidth({'serverId': 's', 'inboundId': 1, 'uploadMbps': 10, 'downloadMbps': 10})
        self.manager.set_bandwidth.assert_not_called()
        self.manager.inbounds.assert_not_called()

    def test_native_user_meter_failure_prevents_creation_and_binding(self):
        row = self.row()
        self.manager.prepare_user_meter.side_effect = ValueError('StatsService unavailable')
        with self.assertRaisesRegex(ValueError, 'StatsService'): self.provision()
        self.assertFalse(server.profile_record().get('remoteNodes'))
        self.assertEqual(len(row['settings']['clients']), 1)
        self.manager.subscription_user.assert_not_called()

    def test_multiplier_settles_old_user_usage_first(self):
        row = self.row(); self.provision(); record = self.traffic()
        row['clientStats'][-1].update(up=100)
        server.set_node_multiplier({'serverId': 's', 'inboundId': 1, 'multiplier': 2})
        self.assertEqual(record['traffic']['upload'], 100)
        row['clientStats'][-1].update(up=110)
        server.enforce_profile('clash')
        self.assertEqual(record['traffic']['upload'], 120)

    def test_legacy_migration_keeps_uuid_bills_link_and_counter_baseline(self):
        row = self.row(); record = self.traffic()
        record['traffic'].update(upload=500, download=600)
        record['remoteNodes'] = [{'serverId': 's', 'inboundId': 1, 'port': 4443, 'status': 'active',
                                 'up': 9000, 'down': 9000, 'counterSource': 'authenticated-client',
                                 'identityHash': server.remote_node_identity(row)}]
        old_link = record['slug']
        result = self.provision()
        self.assertEqual(result['binding']['scope'], 'user')
        self.assertEqual(len(row['settings']['clients']), 1)
        self.assertEqual(server.read_config()['proxies'][0]['uuid'], '6a5a8f80-b82e-4afd-bf96-0919eb3b25b2')
        self.assertEqual(server.traffic_info(record)['used'], 1100)
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'], 1100)
        self.assertEqual(record['slug'], old_link)

    def test_duplicate_uuid_cannot_remove_peer_via_panel_identity_endpoint(self):
        row = self.row(); self.provision(); record = self.traffic(expire=1)
        row['settings']['clients'].append({**row['settings']['clients'][-1], 'email': 'copied-by-peer'})
        self.manager.subscription_user.reset_mock()
        server.enforce_profile('clash')
        self.assertEqual(record['remoteNodes'][0]['status'], 'identity_changed')
        self.assertIn('凭据被共用', record['remoteNodes'][0]['error'])
        self.manager.subscription_user.assert_not_called()
        self.manager.delete_inbound.assert_not_called()

    def test_email_reused_in_another_inbound_blocks_aggregate_user_counters(self):
        row = self.row(); self.provision(); record = self.traffic(expire=1)
        peer = copy.deepcopy(row); peer.update(id=2, port=5555)
        self.manager.inbounds.return_value['inbounds'].append(peer)
        self.manager.subscription_user.reset_mock()
        server.enforce_profile('clash')
        self.assertEqual(record['remoteNodes'][0]['status'], 'identity_changed')
        self.assertIn('多个入站重复', record['remoteNodes'][0]['error'])
        self.assertEqual(record['traffic']['upload'], 0)
        self.manager.subscription_user.assert_not_called()

    def test_pending_binding_is_enforced_after_process_restart(self):
        row = self.row(); self.provision(); record = self.traffic(expire=1)
        record['remoteNodes'][0]['status'] = 'provisioning'
        server.save_profiles(server.load_profiles()); server.PROFILES_CACHE = None
        server.enforce_profile('clash')
        self.assertEqual(server.profile_record()['remoteNodes'][0]['status'], 'revoked')
        self.assertEqual(len(row['settings']['clients']), 1)


class RemoteUserAdapterTests(unittest.TestCase):
    setUp = remote_fixture.RemoteManagerTests.setUp
    tearDown = remote_fixture.RemoteManagerTests.tearDown

    def test_panel_mutates_only_client_endpoint_never_rewrites_inbound(self):
        row = {'id': 1, 'port': 4443, 'protocol': 'vless', 'settings': {'clients': []}, 'streamSettings': {}}
        client = users.new_user(row)
        binding = {'inboundId': 1, 'identityHash': users.endpoint_identity(row),
                   'userEmail': client['email'], 'userHash': users.user_identity(client)}
        api = Mock(); api.request.return_value = [row]
        self.manager.with_panel = lambda sid, fn: fn(api, self.manager.record(self.identity))
        self.manager.subscription_user(self.identity, binding, 'add', client)
        path, payload = api.request.call_args.args
        self.assertEqual(path, 'panel/api/inbounds/addClient')
        self.assertEqual(json.loads(payload['settings'])['clients'], [client])
        row['settings']['clients'] = [client, {'id': 'peer', 'email': 'peer'}]
        api.request.reset_mock(); api.request.return_value = [row]
        self.manager.subscription_user(self.identity, binding, 'pause')
        self.assertIn('updateClient/', api.request.call_args.args[0])
        self.assertEqual(len(json.loads(api.request.call_args.args[1]['settings'])['clients']), 1)
        self.assertFalse(json.loads(api.request.call_args.args[1]['settings'])['clients'][0]['enable'])
        api.request.reset_mock(); api.request.return_value = [row]
        self.manager.subscription_user(self.identity, binding, 'remove')
        self.assertEqual(api.request.call_args.args[0], f"panel/api/inbounds/1/delClient/{client['id']}")
        self.assertEqual(len(row['settings']['clients']), 2)

    def test_remote_revalidation_prevents_removing_replaced_user(self):
        row = {'id': 1, 'port': 4443, 'protocol': 'vless', 'settings': {'clients': []}}
        client = users.new_user(row)
        binding = {'inboundId': 1, 'identityHash': users.endpoint_identity(row),
                   'userEmail': client['email'], 'userHash': users.user_identity(client)}
        row['settings']['clients'] = [{**client, 'id': 'replacement'}]
        api = Mock(); api.request.return_value = [row]
        self.manager.with_panel = lambda sid, fn: fn(api, self.manager.record(self.identity))
        with self.assertRaisesRegex(ValueError, '身份'): self.manager.subscription_user(self.identity, binding, 'remove')
        self.assertEqual(api.request.call_count, 1)


class NativeUserStatsTests(unittest.TestCase):
    setUp = core_fixture.CoreAdapterTests.setUp
    initialize = core_fixture.CoreAdapterTests.initialize

    def test_native_config_uses_per_user_stats_and_filters_disabled_users(self):
        for kind in ('xray', 'sing-box'):
            self.initialize(kind)
            original = self.manager.execute.side_effect
            def execute(ssh, record, command, **kwargs):
                if command.endswith(' version'):
                    return 0, 'Tags: with_v2ray_api'
                if ' api statsquery ' in command:
                    return 0, json.dumps({'stat': [{'name': f'user>>>{email}>>>traffic>>>uplink', 'value': '123'}]})
                return original(ssh, record, command, **kwargs)
            self.manager.execute.side_effect = execute
            created = self.manager.create_inbound(self.identity, {'port': 4443, 'template': 'vmess-tcp'})
            email = json.loads(created['inbound']['settings'])['clients'][0]['email']
            self.manager.prepare_user_meter(self.identity, created['inbound']['id'], email)
            stats = self.manager.inbounds(self.identity)['inbounds'][0]['clientStats']
            self.assertEqual(stats, [{'email': email, 'up': 123, 'down': 0}])
            if kind == 'xray':
                self.assertEqual(self.native['api']['listen'], '127.0.0.1:10085')
                self.assertTrue(self.native['policy']['levels']['0']['statsUserUplink'])
            else:
                self.assertEqual(self.native['experimental']['v2ray_api']['stats']['users'], [email])
            legacy = self.manager.create_inbound(self.identity, {'port': 5555, 'template': 'vmess-tcp'})
            records = self.manager.inbounds(self.identity)['inbounds']
            self.assertNotIn('clientStats', next(r for r in records if r['id'] == legacy['inbound']['id']))
            row = created['inbound']; row['settings'] = json.loads(row['settings'])
            row['settings']['clients'][0]['enable'] = False
            self.manager.update_inbound(self.identity, row['id'], row)
            native = self.native['inbounds'][0]
            self.assertEqual(native.get('users', native.get('settings', {}).get('clients')), [])
            self.manager.remove(self.identity)



# Real authentication/HTTP/config persistence with simulated panel transport.
import test_end_to_end as http_fixture


class SharedUserHTTPTests(unittest.TestCase):
    setUp = http_fixture.EndToEndTests.setUp
    request = http_fixture.EndToEndTests.request

    def test_authenticated_two_profile_workflow_and_local_only_saves(self):
        base_request = self.api.request
        def panel_request(path, payload=None, **kwargs):
            if path.endswith('/addClient'):
                row = next(r for r in self.api.rows if r['id'] == int(payload['id']))
                model = users.settings(row)
                clients = json.loads(payload['settings'])['clients']
                model['clients'].extend(clients)
                row['settings'] = json.dumps(model)
                row.setdefault('clientStats', []).extend({'email': c['email'], 'up': 0, 'down': 0} for c in clients)
                return None
            if '/delClient/' in path:
                identity = path.rsplit('/', 1)[1]
                row = next(r for r in self.api.rows if r['id'] == int(path.split('/')[-3]))
                model = users.settings(row)
                model['clients'] = [c for c in model['clients'] if c.get('id') != identity]
                row['settings'] = json.dumps(model)
                return None
            result = base_request(path, payload, **kwargs)
            if path.endswith('inbounds/add'):
                result['clientStats'] = [{'email': c['email'], 'up': 0, 'down': 0} for c in users.settings(result)['clients']]
                self.api.rows[-1]['clientStats'] = copy.deepcopy(result['clientStats'])
            return result
        self.api.request = panel_request
        saved, _ = self.request('POST', '/servers', {'name': 'shared', 'host': '198.51.100.20',
            'sshPort': 22, 'sshUser': 'root', 'sshPassword': 'ssh-test-password', 'fingerprint': remote_fixture.PIN,
            'connectionMode': 'existing', 'installType': 'x-panel', 'panelUser': 'admin',
            'panelPassword': 'panel-test-password', 'panelAddress': 'https://panel.example.com/'})
        sid = saved['server']['id']
        first, _ = self.request('POST', '/servers/users', {'serverId': sid, 'template': 'vmess-tcp', 'port': 24443})
        iid = first['binding']['inboundId']
        other, _ = self.request('POST', '/profiles', {'name': 'second'})
        other_id = other['profile']['id']
        second, _ = self.request('POST', '/servers/users', {'serverId': sid, 'inboundId': iid}, profile=other_id)
        self.assertEqual(len(self.api.rows), 1)
        self.assertEqual(len(users.settings(self.api.rows[0])['clients']), 2)
        self.assertNotEqual(first['shareLinks'], second['shareLinks'])
        self.request('PUT', '/traffic', {'enforce': True, 'upload': 0, 'download': 0, 'total': 1000})
        self.manager.connect.reset_mock()
        self.request('PUT', '/traffic', {'enforce': True, 'preserveUsage': True, 'total': 2000})
        self.manager.connect.assert_not_called()
        self.api.rows[0]['clientStats'][0].update(up=2001)
        sync, _ = self.request('POST', '/traffic/sync', {})
        self.assertEqual(sync['traffic']['used'], 2001)
        self.assertEqual(sync['traffic']['bindings'][0]['status'], 'revoked')
        remaining = users.settings(self.api.rows[0])['clients']
        self.assertEqual([c['email'] for c in remaining], [second['binding']['userEmail']])
        slug = server.profile_record()['slug']
        self.request('GET', '/sub/'+slug, public=True, status=403)
        self.request('PUT', '/servers/bandwidth', {'serverId': sid, 'inboundId': iid, 'uploadMbps': 1}, profile=other_id, status=400)
        denied, _ = self.request('POST', '/servers/users', {'serverId': sid, 'inboundId': iid}, origin='https://other.example', status=403)
        self.assertIn('来源', denied['error'])
