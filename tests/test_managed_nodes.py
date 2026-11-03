import copy
import unittest
from unittest.mock import patch

import server
import shared_users
from managed_nodes import references, node_identity
import test_subscription_enforcement as fixture


class ManagedNodesTests(unittest.TestCase):
    setUp = fixture.EnforcementTests.setUp
    configure = fixture.EnforcementTests.configure

    def owned(self, legacy=False):
        record = self.configure()
        node = {'name':'owned', 'type':'vless', 'server':'node.example.com', 'port':4443,
                'uuid':'11111111-1111-4111-8111-111111111111'}
        binding = record['remoteNodes'][0]
        binding.update(scope='user', userEmail='owner', userHash=shared_users.user_identity({'id':node['uuid'], 'email':'owner'}), importedNames=['owned'])
        if not legacy:
            binding['importedNodes'] = references([node])
        doc = server.read_config()
        doc['proxies'] = [node]
        doc['proxy-groups'][0]['proxies'] = ['owned']
        server.write_config(doc)
        server.save_profiles(server.load_profiles())
        return record, binding, node

    def test_authoritative_absence_removes_yaml_and_references(self):
        record,binding,node = self.owned()
        result = server.reconcile_server_nodes('server-a', [])
        self.assertEqual(result['removed'],1)
        self.assertEqual(server.read_config()['proxies'],[])
        self.assertEqual(server.read_config()['proxy-groups'][0]['proxies'],['DIRECT'])
        self.assertEqual(binding['status'],'missing')
        self.assertEqual(record['traffic']['upload'],0)
        self.manager.delete_inbound.assert_not_called()
        server.PROFILES_CACHE=None
        self.assertEqual(server.profile_record()['remoteNodes'][0]['status'],'missing')

    def test_historical_user_binding_and_renamed_node(self):
        _,binding,node = self.owned(legacy=True)
        doc=server.read_config();doc['proxies'][0]['name']='renamed';doc['proxy-groups'][0]['proxies']=['renamed'];server.write_config(doc)
        self.assertEqual(server.reconcile_server_nodes('server-a',[])['removed'],1)
        self.assertEqual(server.read_config()['proxies'],[])

    def test_reused_name_with_new_credentials_is_preserved(self):
        _,binding,node=self.owned()
        doc=server.read_config();doc['proxies'][0]['uuid']='22222222-2222-4222-8222-222222222222';server.write_config(doc)
        self.assertEqual(server.reconcile_server_nodes('server-a',[])['removed'],0)
        self.assertEqual(len(server.read_config()['proxies']),1)

    def test_offline_and_malformed_snapshot_never_delete(self):
        record,binding,node=self.owned();record['traffic']['enforce']=False
        self.manager.inbounds.side_effect=TimeoutError('offline')
        self.assertFalse(server.enforce_profile('clash'))
        self.assertEqual(len(server.read_config()['proxies']),1)
        self.assertEqual(binding['status'],'active')
        for rows in (None,[{}],[{'id':True}],[{'id':1},{'id':1}]):
            with self.assertRaises(ValueError):server.reconcile_server_nodes('server-a',rows)
        self.assertEqual(binding['status'],'active')

    def test_unmetered_profile_is_reconciled_and_failure_retries(self):
        record,binding,node=self.owned();record['traffic']['enforce']=False
        self.manager.inbounds.return_value={'inbounds':[]}
        with patch('server.write_config',side_effect=OSError('disk')):
            self.assertFalse(server.enforce_profile('clash'))
        self.assertEqual(len(server.read_config()['proxies']),1)
        self.assertTrue(server.enforce_profile('clash'))
        self.assertEqual(server.read_config()['proxies'],[])

    def test_targets_only_hide_confirmed_local_imports(self):
        record,binding,node=self.owned()
        payload={'serverId':'server-a','inboundIds':[1,2]}
        row=server.subscription_import_targets(payload)['profiles'][0]
        self.assertEqual(row['importedInboundIds'],[1])
        binding['status']='provisioning'
        self.assertEqual(server.subscription_import_targets(payload)['profiles'][0]['importedInboundIds'],[])
        binding['status']='active'
        doc=server.read_config();doc['proxies']=[];doc['proxy-groups'][0]['proxies']=['DIRECT'];server.write_config(doc)
        self.assertEqual(server.subscription_import_targets(payload)['profiles'][0]['importedInboundIds'],[])
        self.assertEqual(node_identity(node),node_identity({**node,'name':'renamed'}))

    def test_partial_mirror_failure_repairs_on_retry(self):
        record,binding,node=self.owned()
        from pathlib import Path
        primary=server.current_files()[0];mirror=primary.with_name('mirror.yaml');mirror.write_bytes(primary.read_bytes())
        record['files'].append(str(mirror));server.save_profiles(server.load_profiles())
        def interrupted(doc,*args,**kwargs):
            primary.write_text(server.yaml_dump(doc),encoding='utf-8')
            raise OSError('mirror failed')
        with patch('server.write_config',side_effect=interrupted):
            self.assertTrue(server.reconcile_server_nodes('server-a',[])['errors'])
        self.assertEqual(server.read_config()['proxies'],[])
        self.assertIn('owned',mirror.read_text())
        self.assertFalse(server.reconcile_server_nodes('server-a',[])['errors'])
        self.assertEqual(primary.read_bytes(),mirror.read_bytes())

    def test_failed_metadata_commit_keeps_cleanup_retryable(self):
        _,binding,node=self.owned();binding['status']='missing';server.save_profiles(server.load_profiles())
        with patch('server.save_profiles',side_effect=OSError('index failed')):
            with self.assertRaises(OSError):server.cleanup_missing_nodes('clash')
        self.assertNotIn('localNodesRemovedAt',binding)
        server.cleanup_missing_nodes('clash')
        self.assertIn('localNodesRemovedAt',binding)


if __name__=='__main__':unittest.main()
