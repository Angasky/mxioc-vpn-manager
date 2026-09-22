import unittest

import server


class HttpProxyTests(unittest.TestCase):
    def test_authenticated_http_link_round_trip(self):
        node = server.parse_node_link(
            "http://alice:p%40ss%3Aword@proxy.example.com:8080"
            "?host=edge.example.com&user-agent=Mxioc#HTTP%20Proxy"
        )
        self.assertEqual(node["type"], "http")
        self.assertFalse(node["udp"])
        self.assertNotIn("tls", node)
        self.assertEqual(node["username"], "alice")
        self.assertEqual(node["password"], "p@ss:word")
        self.assertEqual(node["headers"]["Host"], "edge.example.com")

        rebuilt = server.parse_node_link(server.node_to_uri(node))
        for key in ("name", "type", "server", "port", "username", "password", "headers"):
            self.assertEqual(rebuilt.get(key), node.get(key))

    def test_https_link_round_trip(self):
        node = server.parse_node_link(
            "https://user:secret@[2001:db8::20]:8443"
            "?sni=proxy.example.com&skip-cert-verify=true"
            "&fingerprint=AA%3ABB#HTTPS%20Proxy"
        )
        self.assertEqual(node["type"], "http")
        self.assertTrue(node["tls"])
        self.assertFalse(node["udp"])
        self.assertEqual(node["sni"], "proxy.example.com")
        self.assertTrue(node["skip-cert-verify"])

        exported = server.node_to_uri(node)
        self.assertTrue(exported.startswith("https://"))
        rebuilt = server.parse_node_link(exported)
        for key in ("name", "type", "server", "port", "username", "password", "tls", "sni",
                    "skip-cert-verify", "fingerprint"):
            self.assertEqual(rebuilt.get(key), node.get(key))

    def test_clash_https_alias_is_normalized(self):
        text = """proxies:
  - name: HTTPS alias
    type: https
    server: 192.0.2.20
    port: 443
    username: demo
    password: secret
"""
        nodes, skipped = server.parse_subscription_text(text)
        self.assertEqual(skipped, [])
        self.assertEqual(nodes[0]["type"], "http")
        self.assertTrue(nodes[0]["tls"])


if __name__ == "__main__":
    unittest.main()
