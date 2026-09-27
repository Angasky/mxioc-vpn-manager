import tempfile
import unittest
from pathlib import Path

import server


class ProfileSlugTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.originals = {
            name: getattr(server, name)
            for name in (
                "ROOT", "PROFILES_FILE", "PROFILES_DIR", "PROFILES_CACHE",
                "PROFILES_MTIME", "CONFIG_CACHE", "FILES", "BUNDLED_TEMPLATE",
            )
        }
        root = Path(self.temp.name)
        config = root / "clash.yaml"
        config.write_text(server.yaml_dump(server.minimal_profile_config()), encoding="utf-8")
        server.ROOT = root
        server.PROFILES_FILE = root / "profiles.json"
        server.PROFILES_DIR = root / "profiles"
        server.PROFILES_CACHE = None
        server.PROFILES_MTIME = 0
        server.CONFIG_CACHE = {}
        server.FILES = [config]
        server.BUNDLED_TEMPLATE = root / "missing-template.yaml"

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(server, name, value)
        self.temp.cleanup()

    def test_new_install_uses_random_twelve_character_slug(self):
        record = server.load_profiles()["profiles"][0]
        public = server.public_profile(record)
        self.assertRegex(record["slug"], r"^[a-z0-9]{12}$")
        self.assertFalse(public["customSlug"])
        self.assertEqual(public["url"], "/sub/" + record["slug"])
        self.assertNotEqual(public["url"], "/clash")

    def test_new_profile_defaults_to_random_slug(self):
        server.load_profiles()
        profile = server.create_profile({"name": "专用订阅", "templateId": "blank"})
        self.assertRegex(profile["slug"], r"^[a-z0-9]{12}$")
        self.assertFalse(profile["customSlug"])

    def test_high_risk_mode_allows_custom_star_slug_and_can_be_disabled(self):
        server.load_profiles()
        profile = server.create_profile({
            "name": "自定义订阅", "templateId": "blank",
            "customSlug": True, "slug": "/***",
        })
        self.assertEqual(profile["slug"], "***")
        self.assertEqual(profile["url"], "/sub/%2A%2A%2A")
        self.assertTrue(profile["customSlug"])

        updated = server.update_profile({
            "oldId": profile["id"], "name": "自定义订阅",
            "customSlug": False,
        })
        self.assertRegex(updated["slug"], r"^[a-z0-9]{12}$")
        self.assertNotEqual(updated["slug"], "***")
        self.assertFalse(updated["customSlug"])

    def test_duplicate_custom_slug_is_rejected(self):
        server.load_profiles()
        server.create_profile({"name": "A", "customSlug": True, "slug": "shared"})
        with self.assertRaisesRegex(ValueError, "已经存在"):
            server.create_profile({"name": "B", "customSlug": True, "slug": "shared"})

    def test_legacy_main_link_is_preserved_until_high_risk_is_disabled(self):
        legacy = {
            "profiles": [{
                "id": "clash", "name": "Clash", "protected": True,
                "files": [str(server.FILES[0])],
            }]
        }
        server.save_profiles(legacy)
        public = server.list_profiles()[0]
        self.assertEqual(public["url"], "/clash")
        self.assertTrue(public["customSlug"])

        updated = server.update_profile({
            "oldId": "clash", "name": "Clash", "customSlug": False,
        })
        self.assertRegex(updated["slug"], r"^[a-z0-9]{12}$")
        self.assertEqual(updated["url"], "/sub/" + updated["slug"])
        self.assertFalse(updated["customSlug"])


if __name__ == "__main__":
    unittest.main()
