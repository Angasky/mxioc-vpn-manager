import json
import unittest
from types import SimpleNamespace

import remote_manager as remote
import server


class RemoteHY2Tests(unittest.TestCase):
    def test_create_export_import_across_server_types(self):
        for kind in ('sing-box', 'xray', 'panel'):
            with self.subTest(kind=kind):
                row = remote.build_inbound(SimpleNamespace(kind=kind), {
                    'template': 'hysteria2', 'remark': 'HY2 test', 'port': 24443,
                    'serverName': 'vpn.example.com', 'certFile': '/etc/cert.pem', 'keyFile': '/etc/key.pem'})
                settings = json.loads(row['settings'])
                stream = json.loads(row['streamSettings'])
                client = settings['clients'][0]
                self.assertEqual(row['protocol'], 'hysteria2' if kind == 'sing-box' else 'hysteria')
                self.assertEqual(stream['tlsSettings']['alpn'], ['h3'])
                if kind != 'sing-box':
                    self.assertEqual(stream['network'], 'hysteria')
                    self.assertEqual(settings['version'], 2)
                    self.assertTrue(client['auth'])
                nodes = remote.inbound_nodes(row, {'host': '198.51.100.10'})
                self.assertEqual(len(nodes), 1)
                node = nodes[0]
                self.assertNotIn('network', node)
                self.assertEqual(node['sni'], 'vpn.example.com')
                restored = server.parse_node_link(server.node_to_uri(node))
                self.assertEqual(restored['password'], client.get('auth') or client['password'])

    def test_panel_auth_and_disabled_users(self):
        row = {'protocol': 'hysteria', 'port': 24443, 'settings': {'version': 2, 'clients': [
            {'auth': 'correct:@ secret', 'password': 'wrong', 'email': 'user'},
            {'auth': 'disabled', 'enable': False}]}, 'streamSettings': {'network': 'hysteria', 'security': 'tls', 'tlsSettings': {'serverName': 'vpn.example.com'}}}
        nodes = remote.inbound_nodes(row, {'host': '198.51.100.10'})
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]['password'], 'correct:@ secret')
        row['settings']['version'] = 1
        self.assertEqual(remote.inbound_nodes(row, {'host': '198.51.100.10'}), [])

    def test_missing_auth_is_not_exported_as_broken_node(self):
        with self.assertRaises(ValueError):
            remote.inbound_nodes({'protocol': 'hysteria', 'port': 24443, 'settings': {'clients': [{}]}}, {'host': '198.51.100.10'})

    def test_shared_panel_hy2_credentials_and_identity(self):
        try:
            import shared_users
        except ImportError:
            self.skipTest('定制版使用专属入站')
        row = {'id': 1, 'port': 24443, 'protocol': 'hysteria', 'settings': {'version': 2, 'clients': []}}
        user = shared_users.new_user(row)
        self.assertTrue(user['auth'])
        row['settings']['clients'].append(user)
        binding = {'identityHash': shared_users.endpoint_identity(row), 'userEmail': user['email'], 'userHash': shared_users.user_identity(user)}
        self.assertEqual(shared_users.find_user(row, binding), user)
        user['auth'] = 'changed'
        with self.assertRaises(ValueError):
            shared_users.find_user(row, binding)
