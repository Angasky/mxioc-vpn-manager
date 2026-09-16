import unittest

import server


class IPv6LinkTests(unittest.TestCase):
    def test_imports_unbracketed_vless_ipv6(self):
        link = (
            "vless://8fa52c91-230d-41aa-9439-f79144597e2d@"
            "2600:1700:2bc1:409e:beee:ef11:f7f5:9adf:443"
            "?encryption=none&flow=xtls-rprx-vision&security=reality"
            "&sni=www.sony.com&type=tcp#ATT-V6"
        )
        node = server.parse_node_link(link)
        self.assertEqual(node["server"], "2600:1700:2bc1:409e:beee:ef11:f7f5:9adf")
        self.assertEqual(node["port"], 443)
        self.assertEqual(node["name"], "ATT-V6")
        exported = server.node_to_uri(node)
        self.assertIn("@[2600:1700:2bc1:409e:beee:ef11:f7f5:9adf]:443?", exported)
        self.assertEqual(server.parse_node_link(exported)["server"], node["server"])

    def test_keeps_standard_bracketed_ipv6(self):
        link = "socks5://user:pass@[2001:db8::10]:1080?udp=true#IPv6-SOCKS"
        node = server.parse_node_link(link)
        self.assertEqual(node["server"], "2001:db8::10")
        self.assertEqual(node["port"], 1080)

    def test_imports_unbracketed_hysteria2_ipv6(self):
        link = "hysteria2://secret@2001:db8:1::20:8443?sni=edge.example.com#IPv6-HY2"
        node = server.parse_node_link(link)
        self.assertEqual(node["server"], "2001:db8:1::20")
        self.assertEqual(node["port"], 8443)


if __name__ == "__main__":
    unittest.main()
