import tempfile
import unittest
from pathlib import Path

import server


class AccountManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original_auth = server.AUTH
        self.original_legacy = server.LEGACY_AUTH
        self.original_root = server.ROOT
        self.original_sessions_file = server.SESSIONS_FILE
        self.original_sessions = server.SESSIONS
        root = Path(self.temp.name)
        server.AUTH = root / "auth.json"
        server.LEGACY_AUTH = root / "legacy.auth"
        server.ROOT = root
        server.SESSIONS_FILE = root / "sessions.json"
        server.SESSIONS = None
        salt, digest = server.password_hash("old-password")
        server.save_auth("admin", salt, digest)

    def tearDown(self):
        server.AUTH = self.original_auth
        server.LEGACY_AUTH = self.original_legacy
        server.ROOT = self.original_root
        server.SESSIONS_FILE = self.original_sessions_file
        server.SESSIONS = self.original_sessions
        self.temp.cleanup()

    def test_username_and_password_can_be_changed_together(self):
        token = server.create_session()
        username = server.update_auth("admin", "old-password", "owner", "new-password")
        self.assertEqual(username, "owner")
        self.assertTrue(server.authenticate("owner", "new-password"))
        self.assertFalse(server.authenticate("admin", "old-password"))
        self.assertFalse(server.session_valid("Bearer " + token))

    def test_username_can_change_without_replacing_password(self):
        server.update_auth("admin", "old-password", "operator", "")
        self.assertTrue(server.authenticate("operator", "old-password"))

    def test_invalid_current_credentials_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "当前用户名或密码错误"):
            server.update_auth("admin", "wrong-password", "operator", "")

    def test_short_new_password_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "至少需要 10 位"):
            server.update_auth("admin", "old-password", "admin", "short")


if __name__ == "__main__":
    unittest.main()
