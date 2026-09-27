import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import server


class PublicSubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.originals = {
            name: getattr(server, name)
            for name in (
                "ROOT", "PROFILES_FILE", "PROFILES_DIR", "PROFILES_CACHE",
                "PROFILES_MTIME", "CONFIG_CACHE", "FILES",
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
        server.PROFILES_FILE.write_text(json.dumps({"profiles": [{
            "id": "clash", "name": "Mxioc VPN", "protected": True,
            "files": [str(config)],
        }]}), encoding="utf-8")
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        for name, value in self.originals.items():
            setattr(server, name, value)
        self.temp.cleanup()

    def test_main_clash_subscription_is_public_without_login(self):
        port = self.httpd.server_address[1]
        with urlopen(f"http://127.0.0.1:{port}/clash", timeout=3) as response:
            body = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn("proxies:", body)
            self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_qr_svg_is_generated_locally(self):
        svg = server.subscription_qr_svg("http://192.0.2.1/clash")
        self.assertIn(b"<svg", svg)
        self.assertGreater(len(svg), 500)

    def test_new_install_random_slug_is_public_and_clash_alias_is_absent(self):
        server.PROFILES_FILE.unlink()
        server.PROFILES_CACHE = None
        server.PROFILES_MTIME = 0
        profile = server.public_profile(server.load_profiles()["profiles"][0])
        port = self.httpd.server_address[1]
        with urlopen(f"http://127.0.0.1:{port}{profile['url']}", timeout=3) as response:
            self.assertEqual(response.status, 200)
        with self.assertRaises(HTTPError) as error:
            urlopen(f"http://127.0.0.1:{port}/clash", timeout=3)
        self.assertEqual(error.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
