import copy
import unittest
from unittest.mock import patch

import server


class NodeMembershipTests(unittest.TestCase):
    def setUp(self):
        self.doc = {"proxies": [{"name": "A"}], "proxy-groups": [
            {"name": "Proxy", "type": "select", "proxies": ["DIRECT", "A"]},
            {"name": "Cloudflare", "type": "select", "proxies": ["Proxy"]},
            {"name": "managed", "type": "select", "proxies": ["A"]}]}

    def test_atomic_membership_preserves_uneditable_groups_and_order(self):
        with patch.object(server, "read_config", return_value=self.doc), patch.object(server, "eligible_group_names", return_value=["Proxy", "Cloudflare"]), patch.object(server, "write_config") as write:
            server.mutate_node_membership({"name": "A", "groups": ["Cloudflare"]})
            self.assertEqual(self.doc["proxy-groups"][0]["proxies"], ["DIRECT"])
            self.assertEqual(self.doc["proxy-groups"][1]["proxies"], ["Proxy", "A"])
            self.assertEqual(self.doc["proxy-groups"][2]["proxies"], ["A"])
            write.assert_called_once_with(self.doc, "node-groups")

    def test_rejects_stale_or_protected_groups_without_writing(self):
        before = copy.deepcopy(self.doc)
        with patch.object(server, "read_config", return_value=self.doc), patch.object(server, "eligible_group_names", return_value=["Proxy"]), patch.object(server, "write_config") as write:
            for payload in [{"name": "missing", "groups": []}, {"name": "A", "groups": ["managed"]}, {"name": "A", "groups": "Proxy"}]:
                with self.assertRaises(ValueError):
                    server.mutate_node_membership(payload)
            write.assert_not_called()
            self.assertEqual(before, self.doc)

    def test_cloudflare_template_defaults_to_proxy(self):
        import yaml
        from pathlib import Path
        doc = yaml.safe_load((Path(__file__).resolve().parents[1] / "templates/clash.yaml").read_text(encoding="utf-8"))
        group = next(group for group in doc["proxy-groups"] if "Cloudflare" in group["name"])
        self.assertIn("Proxy", group["proxies"][0])
