import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class UpdateStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.originals = {
            "BUNDLED_VERSION_FILE": server.BUNDLED_VERSION_FILE,
            "UPDATE_STATE_FILE": server.UPDATE_STATE_FILE,
            "UPDATE_MARKER_FILE": server.UPDATE_MARKER_FILE,
            "UPDATE_RESULT_FILE": server.UPDATE_RESULT_FILE,
        }
        server.BUNDLED_VERSION_FILE = root / "version"
        server.UPDATE_STATE_FILE = root / "state.json"
        server.UPDATE_MARKER_FILE = root / "marker.json"
        server.UPDATE_RESULT_FILE = root / "result.json"
        server.BUNDLED_VERSION_FILE.write_text("old-sha", encoding="utf-8")

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(server, name, value)
        self.temp.cleanup()

    def test_daily_cache_and_dismiss_current_release(self):
        release = {"latestSha": "new-sha", "latestMessage": "New feature",
                   "latestUrl": "https://example.invalid/commit", "publishedAt": "2026-01-01T00:00:00Z"}
        with patch.object(server, "fetch_latest_release", return_value=release) as fetch:
            first = server.update_status(force=True)
            second = server.update_status()
            dismissed = server.dismiss_update()

        self.assertTrue(first["available"])
        self.assertTrue(second["available"])
        self.assertFalse(dismissed["available"])
        self.assertTrue(dismissed["dismissed"])
        self.assertEqual(fetch.call_count, 1)

    def test_stale_cache_is_refreshed(self):
        server.write_json_file(server.UPDATE_STATE_FILE, {
            "latestSha": "old-sha", "checkedAt": int(time.time()) - 24 * 3600 - 1,
        })
        release = {"latestSha": "next-sha", "latestMessage": "Next",
                   "latestUrl": "", "publishedAt": ""}
        with patch.object(server, "fetch_latest_release", return_value=release) as fetch:
            status = server.update_status()
        self.assertEqual(status["latestSha"], "next-sha")
        self.assertEqual(fetch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
