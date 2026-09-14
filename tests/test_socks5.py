import unittest

import server


class Socks5Tests(unittest.TestCase):
    def test_authenticated_link_round_trip(self):
        node = server.parse_node_link(
            "socks5://alice:p%40ss%3Aword@proxy.example.com:1080"
            "?udp=true&tls=true&sni=edge.example.com#US%20SOCKS5"
        )
        self.assertEqual(node["type"], "socks5")
        self.assertEqual(node["username"], "alice")
        self.assertEqual(node["password"], "p@ss:word")
        self.assertTrue(node["tls"])

        rebuilt = server.parse_node_link(server.node_to_uri(node))
        for key in ("name", "type", "server", "port", "username", "password", "tls", "servername"):
            self.assertEqual(rebuilt.get(key), node.get(key))

    def test_no_auth_socks_alias(self):
        node = server.parse_node_link("socks://127.0.0.1:1081?udp=false#NoAuth")
        self.assertEqual(node["type"], "socks5")
        self.assertNotIn("username", node)
        self.assertNotIn("password", node)
        self.assertFalse(node["udp"])

    def test_clash_subscription_import(self):
        text = """proxies:
  - name: Clash SOCKS
    type: socks5
    server: 192.0.2.10
    port: 1080
    username: demo
    password: secret
    udp: true
"""
        nodes, skipped = server.parse_subscription_text(text)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["type"], "socks5")
        self.assertEqual(skipped, [])


if __name__ == "__main__":
    unittest.main()
