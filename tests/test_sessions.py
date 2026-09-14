import tempfile
import time
import unittest
from pathlib import Path

import server


class PersistentSessionTests(unittest.TestCase):
    def setUp(self):
        self.original_root = server.ROOT
        self.original_file = server.SESSIONS_FILE
        self.original_sessions = server.SESSIONS
        self.temp = tempfile.TemporaryDirectory()
        server.ROOT = Path(self.temp.name)
        server.SESSIONS_FILE = server.ROOT / "sessions.json"
        server.SESSIONS = None

    def tearDown(self):
        server.ROOT = self.original_root
        server.SESSIONS_FILE = self.original_file
        server.SESSIONS = self.original_sessions
        self.temp.cleanup()

    def test_cookie_session_survives_memory_reset(self):
        token = server.create_session()
        self.assertTrue(server.session_valid("", f"other=1; mxioc_session={token}"))
        self.assertNotIn(token, server.SESSIONS_FILE.read_text(encoding="utf-8"))

        server.SESSIONS = None
        self.assertTrue(server.session_valid("", f"mxioc_session={token}"))

    def test_expired_and_revoked_sessions_are_rejected(self):
        token = server.create_session()
        server.SESSIONS[server.session_digest(token)] = time.time() - 1
        server.save_sessions_locked()
        self.assertFalse(server.session_valid("Bearer " + token))

        token = server.create_session()
        server.revoke_session("", f"mxioc_session={token}")
        self.assertFalse(server.session_valid("", f"mxioc_session={token}"))

    def test_cookie_security_attributes(self):
        cookie = server.session_cookie("token")
        for value in ("Max-Age=2592000", "HttpOnly", "Secure", "SameSite=Strict", "Path=/admin"):
            self.assertIn(value, cookie)


if __name__ == "__main__":
    unittest.main()
