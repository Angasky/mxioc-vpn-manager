import copy
import unittest
from unittest.mock import patch

import server


class CountryFlagTests(unittest.TestCase):
    def test_name_normalization_never_stacks_flags(self):
        self.assertEqual(server.country_flag("us"), "🇺🇸")
        self.assertEqual(server.name_with_country_flag("美国节点", "🇺🇸"), "🇺🇸 美国节点")
        self.assertEqual(server.name_with_country_flag("🇺🇸 美国节点", "🇺🇸"), "🇺🇸 美国节点")
        self.assertEqual(server.name_with_country_flag("🇭🇰 🇺🇸 美国节点", "🇺🇸"), "🇺🇸 美国节点")

    def test_bulk_flagging_renames_references_and_is_idempotent(self):
        doc = {
            "proxies": [
                {"name": "入口", "type": "vless", "server": "1.1.1.1", "port": 443},
                {"name": "🇺🇸 出口", "type": "socks5", "server": "8.8.8.8", "port": 1080,
                 "dialer-proxy": "入口"},
            ],
            "proxy-groups": [{"name": "Proxy", "type": "select", "proxies": ["入口", "🇺🇸 出口"]}],
            "rules": ["DOMAIN,example.com,入口", "MATCH,Proxy"],
        }
        written = []

        def lookup(value):
            return ("US", value)

        with patch.object(server, "read_config", return_value=doc), \
                patch.object(server, "write_config", side_effect=lambda value, reason: written.append(copy.deepcopy(value))), \
                patch.object(server, "country_for_server", side_effect=lookup):
            first = server.add_country_flags({"names": []})
            second = server.add_country_flags({"names": []})

        self.assertEqual(first["updated"], 1)
        self.assertEqual(second["updated"], 0)
        self.assertEqual([node["name"] for node in doc["proxies"]], ["🇺🇸 入口", "🇺🇸 出口"])
        self.assertEqual(doc["proxies"][1]["dialer-proxy"], "🇺🇸 入口")
        self.assertEqual(doc["proxy-groups"][0]["proxies"], ["🇺🇸 入口", "🇺🇸 出口"])
        self.assertEqual(doc["rules"][0], "DOMAIN,example.com,🇺🇸 入口")
        self.assertEqual(len(written), 1)


if __name__ == "__main__":
    unittest.main()
