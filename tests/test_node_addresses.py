"""Every server export path must retain the explicitly selected client endpoint."""
import copy
import unittest
from unittest.mock import patch

import remote_manager as remote
import server
import shared_users as users
import test_remote_manager as fixture
import test_failover as failover_fixture


class NodeAddressTests(unittest.TestCase):
    setUp = fixture.RemoteManagerTests.setUp
    tearDown = fixture.RemoteManagerTests.tearDown
    with_fake_api = fixture.RemoteManagerTests.with_fake_api

    def test_second_created_node_and_listing_keep_bound_domain(self):
        self.manager.save({**self.payload,'id':self.identity,'domain':'nodes.example.com'})
        api=fixture.FakeAPI()
        with self.with_fake_api(api):
            for port in (24443,24444):
                created=self.manager.create_inbound(self.identity,{'port':port,'template':'vmess-tcp'})
                self.assertEqual(server.parse_node_link(created['shareLinks'][0])['server'],'nodes.example.com')
            listed=self.manager.inbounds(self.identity)['inbounds']
            self.assertEqual([server.parse_node_link(r['shareLinks'][0])['server'] for r in listed],['nodes.example.com']*2)
        self.assertEqual(self.manager.record(self.identity)['host'],self.payload['host'])

    def test_user_scoped_export_uses_node_domain_and_preserves_own_uuid(self):
        self.manager.save({**self.payload,'id':self.identity,'domain':'panel.example.com','nodeAddress':'proxy.example.com'})
        api=fixture.FakeAPI()
        with self.with_fake_api(api):
            row=self.manager.create_inbound(self.identity,{'port':24443,'template':'vmess-tcp'})['inbound']
            client=users.settings(row)['clients'][0]
            binding={'inboundId':row['id'],'identityHash':users.endpoint_identity(row),
                     'userEmail':client['email'],'userHash':users.user_identity(client)}
            node=server.parse_node_link(self.manager.subscription_user(self.identity,binding,'read')['shareLinks'][0])
        self.assertEqual(node['server'],'proxy.example.com');self.assertEqual(node['uuid'],client['id'])

    def test_client_endpoint_does_not_replace_panel_hostname_or_sni(self):
        row=remote.build_inbound(fixture.FakeAPI(),{'port':24443,'template':'vless-reality','serverName':'www.example.org'})
        record={**self.manager.record(self.identity),'domain':'bound.example.com','nodeAddress':'proxy.example.com',
                'panelAddress':'https://admin.example.com/panel/'}
        node=remote.inbound_nodes(row,record)[0]
        self.assertEqual(node['server'],'proxy.example.com');self.assertEqual(node['servername'],'www.example.org')
        record.update(domain='',nodeAddress='')
        self.assertEqual(remote.inbound_nodes(row,record)[0]['server'],record['host'])

    def test_node_address_is_validated_persisted_preserved_and_explicitly_clearable(self):
        saved=self.manager.save({**self.payload,'id':self.identity,'domain':'bound.example.com','nodeAddress':'Proxy.Example.com.'})
        self.assertEqual(saved['nodeAddress'],'proxy.example.com')
        # Older clients omitting the new field must retain it and the old domain.
        older={**self.payload,'id':self.identity};older.pop('domain',None)
        self.manager.save(older)
        record=self.manager.record(self.identity)
        self.assertEqual(remote.node_address(record),'proxy.example.com');self.assertEqual(record['domain'],'bound.example.com')
        self.manager.save({**older,'nodeAddress':''})
        self.assertEqual(remote.node_address(self.manager.record(self.identity)),'bound.example.com')
        restored=remote.RemoteManager(self.root,server.parse_node_link,server.node_to_uri)
        self.assertEqual(remote.node_address(restored.record(self.identity)),'bound.example.com')
        for value in ('https://proxy.example.com/path','proxy.example.com:443','a;id','127.0.0.1','[::1]','proxy.example.com\npath'):
            with self.subTest(value=value),self.assertRaises(ValueError):
                self.manager.save({**self.payload,'id':self.identity,'nodeAddress':value})

    def test_standalone_cores_accept_node_domain_without_panel_domain_or_tls_changes(self):
        for kind in ('xray','sing-box'):
            self.manager.save({**self.payload,'id':self.identity,'installType':kind,'domain':'','nodeAddress':'core.example.com'})
            record=self.manager.record(self.identity)
            self.assertEqual(remote.node_address(record),'core.example.com');self.assertEqual(record['domain'],'')

    def test_xray_raw_transport_exports_as_client_tcp(self):
        row=remote.build_inbound(fixture.FakeAPI(),{'port':24443,'template':'vless-reality'})
        import json
        stream=json.loads(row['streamSettings']);stream['network']='raw';row['streamSettings']=stream
        node=remote.inbound_nodes(row,self.manager.record(self.identity))[0]
        self.assertNotIn('network',node)
        self.assertEqual(server.parse_node_link(server.node_to_uri(node)).get('network','tcp'),'tcp')

    def test_ipv6_node_address_roundtrips_in_shared_link(self):
        record={**self.manager.record(self.identity),'nodeAddress':'[2001:db8::9]'}
        row=remote.build_inbound(fixture.FakeAPI(),{'port':24443,'template':'vmess-tcp'})
        self.assertEqual(server.parse_node_link(server.node_to_uri(remote.inbound_nodes(row,record)[0]))['server'],'2001:db8::9')


class NodeAddressChainTests(unittest.TestCase):
    setUp = failover_fixture.FailoverTests.setUp
    provision = failover_fixture.FailoverTests.provision

    def test_custom_node_domains_match_managed_servers_for_chain_and_failover(self):
        self.provision()
        hosts=[]
        for index,node in enumerate(self.nodes):
            old=node['server'];node['server']=f'node-{index}.example.com'
            hosts.append({'id':node['name'],'host':old,'nodeAddress':node['server']})
        self.manager.list.return_value=hosts
        doc=server.read_config();doc['proxies']=copy.deepcopy(self.nodes);server.write_config(doc)
        self.assertEqual(server.create_failover(self.payload)['status'],'active')
