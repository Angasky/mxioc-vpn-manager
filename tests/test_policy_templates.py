import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class PolicyTemplateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        overrides = patch.multiple(
            server, ROOT=root, PROFILES_DIR=root / "profiles", PROFILES_FILE=root / "profiles.json",
            BACKUP_DIR=root / "backups", FILES=[root / "clash.yaml"],
            BUNDLED_TEMPLATE=Path(__file__).resolve().parents[1] / "templates" / "clash.yaml",
            PROFILES_CACHE=None, PROFILES_MTIME=0, CONFIG_CACHE={},
        )
        overrides.start()
        self.addCleanup(overrides.stop)
        server.FILES[0].write_text(server.yaml_dump({
            "proxies": [{"name": "server-node", "type": "trojan", "server": "example.net", "port": 443,
                         "password": "fixture-node-secret"}],
            "proxy-groups": [{"name": "Exchange", "type": "select", "proxies": ["server-node", "DIRECT"]}],
            "rules": ["DOMAIN-SUFFIX,binance.com,Exchange", "DOMAIN,external.example,server-node", "MATCH,DIRECT"],
        }), encoding="utf-8")

    def test_extract_edit_apply_and_delete_template_without_copying_credentials(self):
        seed = server.policy_templates_query({"source": ["current"]})["template"]
        self.assertEqual(seed["groups"][0]["proxies"], ["DIRECT"])
        self.assertEqual(seed["rules"], ["DOMAIN-SUFFIX,binance.com,Exchange", "MATCH,DIRECT"])
        created = server.save_policy_template("POST", {"name": "Exchange plan", **seed})["template"]
        identity = created["id"]
        profile = server.create_profile({"name": "Client A", "templateId": identity})
        self.assertNotIn("fixture-node-secret", server.PROFILES_FILE.read_text(encoding="utf-8"))
        doc = server.yaml_load(server.current_files(profile["id"])[0].read_text(encoding="utf-8"))
        self.assertEqual(doc["rules"], seed["rules"])
        self.assertEqual(doc["proxies"], [])
        self.assertTrue(all(url.endswith("#DIRECT") for url in doc["dns"]["nameserver-policy"]["+.openai.com"]))
        edited = {**created, "name": "Updated", "rules": ["DOMAIN,api.binance.com,Exchange", "MATCH,DIRECT"]}
        server.save_policy_template("PUT", edited)
        another = server.create_profile({"name": "Client B", "templateId": identity})
        second = server.yaml_load(server.current_files(another["id"])[0].read_text(encoding="utf-8"))
        self.assertEqual(second["rules"], edited["rules"])
        server.save_policy_template("DELETE", {"id": identity})
        self.assertEqual(server.policy_templates_query({})["templates"], [])
        self.assertTrue(server.current_files(profile["id"])[0].exists())
        with self.assertRaises(ValueError):
            server.create_profile({"name": "Missing template", "templateId": identity})

    def test_group_updates_route_atomically_and_preserves_other_rules(self):
        old = "DOMAIN-SUFFIX,binance.com,Exchange"
        group = {"name": "Binance", "type": "select", "proxies": ["DIRECT"]}
        server.mutate_group("PUT", {"oldName": "Exchange", "config": group,
                                    "expectedGroupRules": [old],
                                    "groupRules": ["binance.com", "IP-CIDR,192.0.2.0/24,no-resolve"]})
        expected = ["DOMAIN-SUFFIX,binance.com,Binance", "IP-CIDR,192.0.2.0/24,Binance,no-resolve",
                    "DOMAIN,external.example,server-node", "MATCH,DIRECT"]
        self.assertEqual(server.read_config()["rules"], expected)
        with self.assertRaises(ValueError):
            server.mutate_group("PUT", {"oldName": "Binance", "config": group,
                                        "expectedGroupRules": [old], "groupRules": []})
        self.assertEqual(server.read_config()["rules"], expected)

    def test_template_requires_valid_references_and_accepts_bundled_seed(self):
        seed = server.policy_templates_query({"source": ["default"]})["template"]
        server.save_policy_template("POST", {"name": "Default copy", **seed})
        bad = {"name": "Invalid", "groups": [{"name": "Cycle", "type": "select", "proxies": ["Cycle"]}],
               "rules": ["MATCH,Cycle"]}
        with self.assertRaises(ValueError):
            server.save_policy_template("POST", bad)
        with self.assertRaises(ValueError):
            server.save_policy_template("POST", {**bad, "groups": [], "rules": ["MATCH,Missing"]})
