import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server


class PublicSubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original_profile = getattr(server.CTX, "profile", "clash")
        server.CTX.profile = "clash"
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
        server.CTX.profile = self.original_profile
        self.temp.cleanup()

    def test_unconfigured_traffic_does_not_advertise_fake_quota(self):
        profile = server.list_profiles()[0]
        port = self.httpd.server_address[1]
        with urlopen(f"http://127.0.0.1:{port}{profile['url']}", timeout=3) as response:
            self.assertIsNone(response.headers.get("Subscription-Userinfo"))
        self.assertFalse(profile["traffic"]["configured"])

    def test_three_client_formats_share_persisted_usage_on_get_and_head(self):
        doc = server.minimal_profile_config()
        doc["proxies"] = [{"name": "test", "type": "trojan", "server": "example.com",
                            "port": 443, "password": "test-password"}]
        server.FILES[0].write_text(server.yaml_dump(doc), encoding="utf-8")
        profile = server.list_profiles()[0]
        result = server.update_traffic({"upload": 1024, "download": 2048,
                                        "total": 1048576, "expire": 1893456000})
        self.assertEqual(result["used"], 3072)
        server.PROFILES_CACHE = None
        self.assertEqual(server.list_profiles()[0]["traffic"]["used"], 3072)
        port = self.httpd.server_address[1]
        paths = [profile["url"], f"/convert/{profile['slug']}/v2ray",
                 f"/convert/{profile['slug']}/shadowrocket"]
        for path in paths:
            for method in ("GET", "HEAD"):
                with self.subTest(path=path, method=method):
                    with urlopen(Request(f"http://127.0.0.1:{port}{path}", method=method), timeout=3) as response:
                        self.assertEqual(response.headers["Subscription-Userinfo"],
                                         "upload=1024; download=2048; total=1048576; expire=1893456000")
                        self.assertTrue(response.headers["Profile-Title"].startswith("base64:"))
                        if method == "HEAD":
                            self.assertEqual(response.read(), b"")
        self.assertEqual(server.traffic_info(server.profile_record())['used'],3072,
                         'subscription GET/HEAD must never add proxy usage')

    def test_usage_validation_disable_and_profile_isolation(self):
        server.load_profiles()
        server.update_traffic({"upload": 2, "download": 8, "total": 5})
        self.assertTrue(server.traffic_info(server.profile_record())["exhausted"])
        other = server.create_profile({"name": "other"})
        self.assertFalse(other["traffic"]["configured"])
        for invalid in (-1, 1.5, True, "100", 2 ** 53):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                server.update_traffic({"download": invalid})
        self.assertEqual(server.traffic_info(server.profile_record())["used"], 10)
        server.update_traffic({"upload": 1, "download": 1})
        self.assertEqual(server.subscription_userinfo(server.profile_record()), "upload=1; download=1; total=0")
        server.update_traffic({"enabled": False})
        self.assertIsNone(server.subscription_userinfo(server.profile_record()))

    def test_traffic_management_requires_admin_session(self):
        port = self.httpd.server_address[1]
        endpoint = f"http://127.0.0.1:{port}/admin/api/traffic"
        for method in ("GET", "PUT"):
            request = Request(endpoint, method=method, headers={
                "Origin": f"https://127.0.0.1:{port}",
                "X-Forwarded-Proto": "https", "Content-Type": "application/json",
            }, data=b'{"total":100}' if method == "PUT" else None)
            with self.subTest(method=method), self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=3)
            self.assertEqual(error.exception.code, 401)
        self.assertFalse(server.traffic_info(server.profile_record())["configured"])

    def test_remote_server_routes_are_authenticated_before_any_connection(self):
        port = self.httpd.server_address[1]
        routes = {"GET": ["/server-chains", "/servers", "/servers/jobs?id=unknown", "/servers/metrics?id=unknown", "/servers/inbounds?id=unknown"],
                  "POST": ["/servers", "/servers/probe", "/servers/install", "/servers/test", "/servers/attach", "/servers/diagnose", "/servers/inbounds", "/servers/relay", "/servers/sni", "/servers/bind", "/servers/users", "/servers/users/batch", "/servers/import", "/traffic/sync", "/nodes/validate"],
                  "PUT": ["/servers", "/servers/inbounds", "/servers/bandwidth", "/traffic/bindings/remove"], "DELETE": ["/server-chains", "/servers", "/servers/inbounds"]}
        with patch.object(server, "remote_manager") as manager:
            for method, paths in routes.items():
                for path in paths:
                    request = Request(f"http://127.0.0.1:{port}/admin/api" + path, method=method,
                                      data=b'{}' if method != "GET" else None,
                                      headers={"Origin": f"https://127.0.0.1:{port}", "X-Forwarded-Proto": "https", "Content-Type": "application/json"})
                    with self.subTest(method=method, path=path), self.assertRaises(HTTPError) as error:
                        urlopen(request, timeout=3)
                    self.assertEqual(error.exception.code, 401)
            manager.assert_not_called()

    def test_legacy_clash_alias_is_disabled_after_secure_migration(self):
        profile = server.list_profiles()[0]
        port = self.httpd.server_address[1]
        with urlopen(f"http://127.0.0.1:{port}{profile['url']}", timeout=3) as response:
            body = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn("proxies:", body)
            self.assertIn("attachment", response.headers["Content-Disposition"])
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        with self.assertRaises(HTTPError) as error:
            urlopen(f"http://127.0.0.1:{port}/clash", timeout=3)
        self.assertEqual(error.exception.code, 404)

    def test_qr_svg_is_generated_locally(self):
        svg = server.subscription_qr_svg("http://192.0.2.1/clash")
        self.assertIn(b"<svg", svg)
        self.assertIn(b'<rect width="100%" height="100%" fill="#fff"/>', svg)
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
