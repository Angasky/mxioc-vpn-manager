"""Batch shared users preserve quota, UUID isolation and partial success."""
import copy
import time
import unittest
from unittest.mock import patch

import server
import shared_users as users
import test_subscription_enforcement as fixture


class BatchServerImportTests(unittest.TestCase):
    setUp = fixture.EnforcementTests.setUp

    def setup_rows(self):
        self.rows = [{ 'id':i, 'port':24000+i, 'protocol':'vless', 'enable':True,
                       'remark':f'入口-{i}', 'tag':f'inbound-{i}', 'streamSettings':{},
                       'settings':{'clients':[]}, 'clientStats':[], 'up':999999, 'down':999999}
                     for i in (1,2,3)]
        self.manager.inbounds.return_value={'inbounds':self.rows}
        def mutate(sid,binding,operation,client=None):
            row=next(r for r in self.rows if r['id']==binding['inboundId'])
            current=users.find_user(row,binding,missing_ok=operation in ('add','remove'))
            if operation=='add' and current is None:
                row['settings']['clients'].append(copy.deepcopy(client))
                row['clientStats'].append({'email':client['email'],'up':0,'down':0})
            elif operation=='remove':
                row['settings']['clients']=[c for c in row['settings']['clients'] if c['email']!=binding['userEmail']]
                return {'removed':True}
            current=users.find_user(row,binding)
            return {'shareLinks':[server.node_to_uri({'name':row['remark'],'type':'vless','server':'198.51.100.1',
                                                     'port':row['port'],'uuid':current['id']})]}
        self.manager.subscription_user.side_effect=mutate

    def batch(self,ids=(1,2),**extra):
        return server.batch_subscription_users({'serverId':'s','inboundIds':list(ids),**extra})

    def test_batch_generates_unique_users_and_automatically_enforces_existing_quota(self):
        self.setup_rows();record=server.profile_record()
        expire=int(time.time())+86400
        record['traffic']={'enabled':True,'enforce':False,'upload':100,'download':200,'total':10000,
                           'expire':expire,'multiplierUnits':2000,'planId':'custom','nextResetAt':expire}
        slug=record['slug']
        result=self.batch()
        self.assertEqual((result['succeeded'],result['failed'],result['added']),(2,0,2))
        self.assertEqual(len(record['remoteNodes']),2)
        self.assertEqual(len({n['uuid'] for n in server.read_config()['proxies']}),2)
        self.assertTrue(record['traffic']['enforce']);self.assertTrue(record['traffic']['enabled'])
        self.assertEqual((record['traffic']['upload'],record['traffic']['download'],record['traffic']['expire']),(100,200,expire))
        self.assertEqual(record['traffic']['planId'],'custom');self.assertEqual(record['slug'],slug)
        self.rows[0]['clientStats'][0]['up']=10;self.rows[1]['clientStats'][0]['down']=20
        server.enforce_profile('clash')
        self.assertEqual(server.traffic_info(record)['used'],360)
        self.manager.create_inbound.assert_not_called();self.manager.delete_inbound.assert_not_called()
        self.manager.ensure_meter.assert_not_called()
        self.assertEqual(self.manager.inbounds.call_count,2) # one batch snapshot + one enforcement snapshot

    def test_no_plan_starts_unlimited_metering_without_inventing_expiry(self):
        self.setup_rows();result=self.batch()
        self.assertTrue(result['traffic']['enforce']);self.assertIsNone(result['traffic']['total']);self.assertIsNone(result['traffic']['expire'])
        self.assertEqual(result['traffic']['used'],0)

    def test_repeat_batch_reuses_existing_uuids_and_does_not_duplicate_nodes(self):
        self.setup_rows();self.batch();uuids=[n['uuid'] for n in server.read_config()['proxies']]
        result=self.batch()
        self.assertEqual((result['added'],result['existing']),(0,2))
        self.assertEqual(uuids,[n['uuid'] for n in server.read_config()['proxies']])
        self.assertEqual([len(r['settings']['clients']) for r in self.rows],[1,1,0])
        self.assertEqual(len(server.profile_record()['remoteNodes']),2)

    def test_partial_failure_keeps_success_and_retries_only_failed_inbound(self):
        self.setup_rows();mutate=self.manager.subscription_user.side_effect
        def fail(sid,binding,operation,client=None):
            result=mutate(sid,binding,operation,client)
            if binding['inboundId']==2 and operation=='add':raise ValueError('timeout after apply')
            return result
        self.manager.subscription_user.side_effect=fail
        result=self.batch()
        self.assertEqual((result['succeeded'],result['failed']),(1,1))
        self.assertTrue(server.profile_record()['traffic']['enforce'])
        self.assertEqual(server.profile_record()['remoteNodes'][1]['status'],'provisioning')
        self.manager.subscription_user.side_effect=mutate
        retry=self.batch((2,))
        self.assertEqual(retry['succeeded'],1)
        self.assertEqual([len(r['settings']['clients']) for r in self.rows],[1,1,0])
        self.assertEqual(len(server.read_config()['proxies']),2)

    def test_invalid_parameters_never_connect_or_mutate(self):
        self.setup_rows()
        for ids in ([],[1,1],[True],['1'],[0],list(range(1,52))):
            with self.subTest(ids=ids),self.assertRaises(ValueError):self.batch(ids)
        self.manager.inbounds.assert_not_called();self.manager.subscription_user.assert_not_called()
        self.assertFalse(server.profile_record().get('traffic'))

    def test_expired_exhausted_and_limited_plan_rejected_before_remote_calls(self):
        self.setup_rows();record=server.profile_record()
        for changes in ({'expire':1},{'total':100,'upload':100},{'speedMbps':1}):
            record['traffic']={'enabled':True,'enforce':False,'upload':0,'download':0,'total':10000,**changes}
            before=copy.deepcopy(record['traffic'])
            with self.subTest(changes=changes),self.assertRaises(ValueError):self.batch()
            self.assertEqual(record['traffic'],before)
        self.manager.inbounds.assert_not_called()

    def test_existing_unmetered_legacy_binding_requires_explicit_migration(self):
        self.setup_rows();server.profile_record()['remoteNodes']=[{'serverId':'old','inboundId':9,'status':'active'}]
        with self.assertRaisesRegex(ValueError,'旧版专属绑定'):self.batch()
        self.manager.inbounds.assert_not_called();self.manager.subscription_user.assert_not_called()

    def test_disabled_traffic_cannot_bypass_expired_subscription_on_auto_enable(self):
        self.setup_rows();server.profile_record()['traffic']={'enabled':False,'expire':1,'upload':1,'download':2}
        with self.assertRaisesRegex(ValueError,'已到期'):self.batch()
        self.manager.inbounds.assert_not_called()

    def test_missing_unsupported_disabled_rows_report_failure_without_side_effects(self):
        self.setup_rows();self.rows[0]['protocol']='shadowsocks';self.rows[1]['enable']=False
        result=self.batch((1,2,99))
        self.assertEqual(result['failed'],3);self.assertEqual(result['succeeded'],0)
        self.assertFalse(server.profile_record().get('traffic'))
        self.manager.subscription_user.assert_not_called()

    def test_export_failure_still_enables_expiry_for_created_user(self):
        self.setup_rows()
        with patch('server.write_config',side_effect=OSError('disk full')):
            result=self.batch((1,))
        self.assertEqual(result['failed'],1)
        self.assertEqual(server.profile_record()['remoteNodes'][0]['status'],'active')
        self.assertTrue(server.profile_record()['traffic']['enforce'])
        self.assertEqual(self.batch((1,))['succeeded'],1)
        self.assertEqual(len(self.rows[0]['settings']['clients']),1)

    def test_limit_persistence_failure_never_grants_remote_users(self):
        self.setup_rows()
        with patch('server.save_profiles',side_effect=OSError('disk full')):
            result=self.batch()
        self.assertEqual(result['failed'],2)
        self.assertFalse(server.profile_record().get('traffic'))
        self.manager.subscription_user.assert_not_called()
        self.assertFalse(server.profile_record().get('remoteNodes'))

    def test_distinct_subscriptions_get_distinct_credentials_on_same_inbounds(self):
        self.setup_rows();self.batch()
        first=[n['uuid'] for n in server.read_config()['proxies']]
        other=server.create_profile({'name':'second'});server.CTX.profile=other['id']
        self.batch();second=[n['uuid'] for n in server.read_config()['proxies']]
        self.assertFalse(set(first)&set(second))
        self.assertEqual([len(r['settings']['clients']) for r in self.rows],[2,2,0])

import test_end_to_end as http_fixture
from unittest.mock import Mock


class BatchServerImportHTTPTests(unittest.TestCase):
    setUp = http_fixture.EndToEndTests.setUp
    request = http_fixture.EndToEndTests.request
    setup_rows = BatchServerImportTests.setup_rows

    def test_real_http_batch_routes_profile_isolation_and_expiry(self):
        self.manager=Mock()
        patched=patch('server.remote_manager',return_value=self.manager);patched.start();self.addCleanup(patched.stop)
        self.setup_rows()
        first,_=self.request('POST','/servers/users/batch',{'serverId':'s','inboundIds':[1,2]})
        self.assertEqual(first['succeeded'],2);self.assertTrue(first['traffic']['enforce'])
        other,_=self.request('POST','/profiles',{'name':'second'})
        other_id=other['profile']['id']
        self.request('POST','/servers/users/batch',{'serverId':'s','inboundIds':[1,2]},profile=other_id)
        self.assertEqual(len(self.rows[0]['settings']['clients']),2)
        first_email=server.profile_record('clash')['remoteNodes'][0]['userEmail']
        second_email=server.profile_record(other_id)['remoteNodes'][0]['userEmail']
        self.assertNotEqual(first_email,second_email)
        self.request('PUT','/traffic',{'enforce':True,'preserveUsage':True,'total':10000,'expire':1})
        self.request('POST','/traffic/sync',{})
        self.assertEqual([c['email'] for c in self.rows[0]['settings']['clients']],[second_email])
        self.manager.delete_inbound.assert_not_called()
        before=self.manager.subscription_user.call_count
        self.request('POST','/servers/users/batch',{'serverId':'s','inboundIds':[1]},profile=other_id,origin='https://other.example',status=403)
        self.assertEqual(self.manager.subscription_user.call_count,before)
        self.request('POST','/servers/users/batch',{'serverId':'s','inboundIds':[1]},status=400)
