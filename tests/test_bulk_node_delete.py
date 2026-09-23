import unittest

import server


def sample_config():
    return {
        "proxies": [
            {"name": "Entry", "type": "vless", "server": "entry.example", "port": 443},
            {"name": "Exit", "type": "socks5", "server": "exit.example", "port": 1080},
            {"name": "Chain", "type": "socks5", "server": "exit.example", "port": 1080,
             "dialer-proxy": "Entry"},
            {"name": "Other", "type": "vless", "server": "other.example", "port": 443},
        ],
        "proxy-groups": [
            {"name": "Proxy", "type": "select", "proxies": ["DIRECT", "Entry", "Exit", "Chain", "Other"]},
            {"name": "Media", "type": "select", "proxies": ["Proxy", "Chain", "Other"]},
        ],
        "rules": ["DOMAIN,entry.example,Entry", "DOMAIN,other.example,Other", "MATCH,Proxy"],
    }


class BulkNodeDeleteTests(unittest.TestCase):
    def test_deletes_multiple_nodes_and_all_references(self):
        doc = sample_config()
        deleted = server.delete_nodes_from_doc(doc, ["Exit", "Other", "Exit"])
        self.assertEqual(deleted, ["Exit", "Other"])
        self.assertEqual([node["name"] for node in doc["proxies"]], ["Entry", "Chain"])
        self.assertEqual(doc["proxy-groups"][0]["proxies"], ["DIRECT", "Entry", "Chain"])
        self.assertEqual(doc["proxy-groups"][1]["proxies"], ["Proxy", "Chain"])
        self.assertEqual(doc["rules"], ["DOMAIN,entry.example,Entry", "MATCH,Proxy"])

    def test_entry_requires_dependent_chain_to_be_selected(self):
        doc = sample_config()
        with self.assertRaisesRegex(ValueError, "请同时勾选"):
            server.delete_nodes_from_doc(doc, ["Entry"])
        self.assertEqual(len(doc["proxies"]), 4)

        deleted = server.delete_nodes_from_doc(doc, ["Entry", "Chain"])
        self.assertEqual(deleted, ["Entry", "Chain"])
        self.assertEqual([node["name"] for node in doc["proxies"]], ["Exit", "Other"])

    def test_rejects_empty_or_missing_selection(self):
        with self.assertRaisesRegex(ValueError, "至少选择"):
            server.delete_nodes_from_doc(sample_config(), [])
        with self.assertRaisesRegex(ValueError, "节点不存在"):
            server.delete_nodes_from_doc(sample_config(), ["Missing"])


if __name__ == "__main__":
    unittest.main()
