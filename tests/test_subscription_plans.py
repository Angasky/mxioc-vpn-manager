import copy
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import server
import test_subscription_enforcement as fixture


def stamp(value):
    return int(datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp())


class SubscriptionPlanTests(unittest.TestCase):
    setUp = fixture.EnforcementTests.setUp
    configure = fixture.EnforcementTests.configure

    def custom_plan(self, **changes):
        payload = dict(name='自定义套餐', price=88.5, monthlyGiB=25.5, durationMonths=3,
                       resetPeriod='monthly', speedMbps=10, multiplier=1.5)
        payload.update(changes)
        return server.save_subscription_plan(payload)

    def test_custom_template_crud_persists_without_changing_applied_subscription(self):
        plan = self.custom_plan(speedMbps=0)
        server.apply_subscription_plan({'planId': plan['id']})
        record = server.profile_record()
        original = copy.deepcopy(record['traffic'])
        edited = self.custom_plan(id=plan['id'], name='已编辑', monthlyGiB=99)
        self.assertEqual(edited['id'], plan['id'])
        self.assertEqual(record['traffic'], original)
        server.PROFILES_CACHE = None
        self.assertEqual(next(p for p in server.subscription_plans() if p['id'] == plan['id'])['name'], '已编辑')
        server.delete_subscription_plan({'id': plan['id']})
        self.assertFalse(any(p['id'] == plan['id'] for p in server.subscription_plans()))
        self.assertEqual(server.profile_record()['traffic'], original)
        self.assertEqual(server.traffic_info(record)['total'], round(25.5 * 1024 ** 3))

    def test_builtin_edit_delete_and_empty_list_does_not_reseed(self):
        self.custom_plan(id='tier-1', name='自定义档位1')
        self.assertEqual(server.subscription_plans()[0]['name'], '自定义档位1')
        for p in server.subscription_plans():
            server.delete_subscription_plan({'id': p['id']})
        server.PROFILES_CACHE = None
        self.assertEqual(server.subscription_plans(), [])
        self.assertTrue(self.custom_plan()['id'].startswith('plan-'))

    def test_invalid_custom_values_never_persist(self):
        for changes in ({'monthlyGiB':float('nan')}, {'monthlyGiB':True}, {'price':-1},
                        {'durationMonths':1.5}, {'durationMonths':121}, {'speedMbps':0.01},
                        {'speedMbps':-1}, {'multiplier':101}, {'resetPeriod':'daily'},
                        {'name':''}, {'id':'unknown'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.custom_plan(**changes)
        self.assertEqual(len(server.subscription_plans()), 3)

    def test_custom_duration_once_quota_speed_and_multiplier_apply(self):
        plan = self.custom_plan(resetPeriod='none')
        record = self.configure(total=10000)
        row = self.manager.inbounds.return_value['inbounds'][0]
        row.update(protocol='shadowsocks', settings={'method':'aes-128-gcm','password':'owned'})
        self.manager.set_bandwidth.return_value = {'uploadKbps':10000,'downloadKbps':10000}
        now = stamp('2026-10-23T08:00:00')
        with patch('server.time.time', return_value=now):
            result = server.apply_subscription_plan({'planId':plan['id']})
        self.assertEqual(result['expire'], stamp('2027-01-23T08:00:00'))
        self.assertEqual(result['resetPeriod'], 'none')
        self.assertIsNone(result['nextResetAt'])
        self.assertEqual(result['multiplier'], 1.5)
        self.assertEqual(record['remoteNodes'][0]['multiplierUnits'], 1500)
        self.manager.set_bandwidth.assert_called_once_with('server-a',1,10000,10000)
        binding = {'serverId':'server-a','inboundId':2}
        server.inherit_plan_binding(record,binding)
        self.assertEqual(binding['multiplierUnits'],1500)
        self.manager.set_bandwidth.assert_called_with('server-a',2,10000,10000)

    def test_history_cleanup_is_local_scoped_and_preserves_bills_and_active_nodes(self):
        record = self.configure()
        record['traffic'].update(upload=300, download=400)
        active = copy.deepcopy(record['remoteNodes'][0])
        for state in ('detached','revoked','missing'):
            record['remoteNodes'].append({**active,'status':state})
        record['remoteNodes'].append({**active,'status':'unknown'})
        original = copy.deepcopy(record['traffic'])
        with self.assertRaisesRegex(ValueError,'请确认'):
            server.cleanup_traffic_bindings({})
        result = server.cleanup_traffic_bindings({'confirmed':True})
        self.assertEqual(result['removed'],3)
        self.assertEqual(record['remoteNodes'],[active,{**active,'status':'unknown'}])
        self.assertEqual(record['traffic'],original)
        self.assertEqual(self.manager.mock_calls,[])

    def test_three_templates_and_unpriced_third_tier(self):
        for plan, amount, price in zip(server.SUBSCRIPTION_PLANS, (50, 100, 150), (120, 240, None)):
            with self.subTest(plan=plan['id']):
                record = server.profile_record()
                record.pop('traffic', None)
                now = stamp('2026-10-23T08:00:00')
                with patch('server.time.time', return_value=now):
                    result = server.apply_subscription_plan({'planId': plan['id']})
                self.assertEqual(result['total'], amount * 1024 ** 3)
                self.assertEqual(result['price'], price)
                self.assertEqual(result['expire'], stamp('2027-10-23T08:00:00'))
                self.assertEqual(result['nextResetAt'], stamp('2026-11-23T08:00:00'))
                self.assertFalse(result['enforce'])
                self.assertEqual(result['multiplier'], 1)

    def test_apply_preserves_usage_links_expiry_and_settles_old_node_rate(self):
        record = self.configure(total=10000)
        record['remoteNodes'][0]['multiplierUnits'] = 2000
        self.manager.inbounds.return_value['inbounds'][0].update(up=10, down=20)
        before = copy.deepcopy({k: v for k, v in record.items() if k not in ('traffic', 'remoteNodes')})
        first = server.apply_subscription_plan({'planId': 'tier-1'})
        self.assertEqual(first['used'], 60)
        self.assertEqual(record['remoteNodes'][0]['multiplierUnits'], 1000)
        with patch('server.time.time', return_value=first['updatedAt'] + 86400):
            second = server.apply_subscription_plan({'planId': 'tier-2'})
        self.assertEqual(second['used'], 60)
        self.assertEqual(second['expire'], first['expire'])
        self.assertEqual(second['nextResetAt'], first['nextResetAt'])
        self.assertEqual(before, {k: record[k] for k in before})
        self.manager.delete_inbound.assert_not_called()

    def test_apply_clears_existing_bandwidth_only_when_present(self):
        record = self.configure()
        binding = record['remoteNodes'][0]
        binding['bandwidth'] = {'uploadKbps': 100, 'downloadKbps': 200}
        self.manager.set_bandwidth.return_value = {'uploadKbps': 0, 'downloadKbps': 0}
        server.apply_subscription_plan({'planId': 'tier-1'})
        self.manager.set_bandwidth.assert_called_once_with('server-a', 1, 0, 0)
        self.assertEqual(binding['bandwidth']['downloadKbps'], 0)

    def test_invalid_plan_and_offline_settlement_do_not_change_quota(self):
        record = self.configure()
        original = copy.deepcopy(record['traffic'])
        with self.assertRaisesRegex(ValueError, '套餐模板'):
            server.apply_subscription_plan({'planId': 'unknown'})
        self.manager.inbounds.side_effect = ValueError('offline')
        with self.assertRaisesRegex(ValueError, '结算失败'):
            server.apply_subscription_plan({'planId': 'tier-1'})
        self.assertEqual(record['traffic'], original)

    def test_month_end_and_leap_year_do_not_drift(self):
        anchor = stamp('2024-01-31T08:09:10')
        self.assertEqual(server.plan_month(anchor, 1), stamp('2024-02-29T08:09:10'))
        self.assertEqual(server.plan_month(anchor, 2), stamp('2024-03-31T08:09:10'))
        self.assertEqual(server.plan_month(stamp('2024-02-29T08:09:10'), 12), stamp('2025-02-28T08:09:10'))

    def monthly(self):
        record = self.configure()
        record['traffic'].update(resetPeriod='monthly', cycleAnchor=stamp('2026-01-31T08:00:00'),
                                nextResetAt=stamp('2026-02-28T08:00:00'), expire=stamp('2027-01-31T08:00:00'))
        return record

    def test_reset_once_and_skip_offline_months_without_rebilling_old_counters(self):
        record = self.monthly()
        record['traffic'].update(upload=800, download=200)
        self.manager.inbounds.return_value['inbounds'][0].update(up=10000, down=20000)
        now = stamp('2026-05-31T08:00:00')
        with patch('server.time.time', return_value=now):
            server.enforce_profile('clash')
            self.assertEqual(server.traffic_info(record)['used'], 0)
            self.assertEqual(record['traffic']['nextResetAt'], stamp('2026-06-30T08:00:00'))
            self.manager.inbounds.return_value['inbounds'][0]['up'] += 10
            server.enforce_profile('clash')
            self.assertEqual(server.traffic_info(record)['used'], 10)
        self.manager.delete_inbound.assert_not_called()

    def test_monthly_exhaustion_pauses_and_next_month_resumes_same_node(self):
        record = self.monthly()
        row = self.manager.inbounds.return_value['inbounds'][0]
        row.update(enable=True, up=1000)
        with patch('server.time.time', return_value=stamp('2026-02-01T08:00:00')):
            server.enforce_profile('clash')
        self.manager.update_inbound.assert_called_with('server-a', 1, {**row, 'enable': False})
        self.assertTrue(record['remoteNodes'][0]['monthlyPaused'])
        self.assertNotIn('accessRevoked', record)
        self.manager.delete_inbound.assert_not_called()
        row['enable'] = False
        with patch('server.time.time', return_value=stamp('2026-02-28T08:00:00')):
            server.enforce_profile('clash')
        self.manager.update_inbound.assert_called_with('server-a', 1, {**row, 'enable': True})
        self.assertNotIn('monthlyPaused', record['remoteNodes'][0])
        self.assertEqual(record['remoteNodes'][0]['inboundId'], 1)
        self.assertEqual(server.traffic_info(record)['used'], 0)

    def test_expiry_still_revokes_and_does_not_reset(self):
        record = self.monthly()
        record['traffic']['upload'] = 10
        with patch('server.time.time', return_value=stamp('2027-01-31T08:00:00')):
            self.assertFalse(server.reset_monthly_traffic(record))
            server.enforce_profile('clash')
        self.manager.delete_inbound.assert_called_once_with('server-a', 1)

    def test_manual_save_preserves_schedule_and_disable_paused_is_rejected(self):
        record = self.monthly()
        server.update_traffic({'enabled': True, 'enforce': True, 'total': 2000, 'preserveUsage': True})
        self.assertEqual(record['traffic']['resetPeriod'], 'monthly')
        record['remoteNodes'][0]['monthlyPaused'] = True
        with self.assertRaisesRegex(ValueError, '尚未恢复'):
            server.update_traffic({'enabled': False})

    def test_manual_disabled_node_is_never_adopted_for_auto_resume(self):
        record = self.monthly()
        record['traffic']['upload'] = 1000
        self.manager.inbounds.return_value['inbounds'][0]['enable'] = False
        with patch('server.time.time', return_value=stamp('2026-02-01T08:00:00')):
            server.enforce_profile('clash')
        self.assertNotIn('monthlyPaused', record['remoteNodes'][0])
        self.manager.update_inbound.assert_not_called()

    def test_pause_survives_reload_and_offline_rollover_retries(self):
        record = self.monthly()
        record['traffic']['upload'] = 1000
        row = self.manager.inbounds.return_value['inbounds'][0]
        with patch('server.time.time', return_value=stamp('2026-02-01T08:00:00')):
            server.enforce_profile('clash')
        row['enable'] = False
        server.PROFILES_CACHE = None
        record = server.profile_record()
        self.assertTrue(record['remoteNodes'][0]['monthlyPaused'])
        self.manager.inbounds.side_effect = ValueError('offline')
        with patch('server.time.time', return_value=stamp('2026-02-28T08:00:00')):
            server.enforce_profile('clash')
            self.assertTrue(record['remoteNodes'][0]['monthlyPaused'])
            self.assertIn('offline', record['enforcementError'])
            self.manager.inbounds.side_effect = None
            server.enforce_profile('clash')
        self.assertNotIn('monthlyPaused', record['remoteNodes'][0])
        self.manager.delete_inbound.assert_not_called()

    def test_reused_identity_is_not_paused_or_resumed(self):
        record = self.monthly()
        record['traffic']['upload'] = 1000
        row = self.manager.inbounds.return_value['inbounds'][0]
        row.update(protocol='vless', settings={'clients': [{'id': 'replacement'}]})
        record['remoteNodes'][0]['identityHash'] = 'previous-owner'
        with patch('server.time.time', return_value=stamp('2026-02-01T08:00:00')):
            server.enforce_profile('clash')
        self.manager.update_inbound.assert_not_called()
        self.manager.disconnect_port.assert_not_called()
        self.assertIn('身份已变化', record['enforcementError'])

    def test_invalid_monthly_baseline_retries_without_negative_usage(self):
        record = self.monthly()
        row = self.manager.inbounds.return_value['inbounds'][0]
        row['up'] = -1
        with patch('server.time.time', return_value=stamp('2026-02-28T08:00:00')):
            server.enforce_profile('clash')
            self.assertTrue(record['remoteNodes'][0]['monthlyBaselinePending'])
            row['up'] = 500
            server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'], 0)
        self.assertNotIn('monthlyBaselinePending', record['remoteNodes'][0])


if __name__ == '__main__':
    unittest.main()
