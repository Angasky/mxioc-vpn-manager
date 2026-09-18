import copy
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "work" / "organize-proxy-layout.py"
if not SCRIPT.exists():
    SCRIPT = Path("/tmp/organize-proxy-layout.py")
SPEC = importlib.util.spec_from_file_location("organize_proxy_layout", SCRIPT)
layout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(layout)


class ProxyLayoutTests(unittest.TestCase):
    def test_organizes_main_group_without_changing_nodes_or_business_groups(self):
        doc = {
            "proxies": [
                {"name": "香港 Mxioc VLESS 🇭🇰", "type": "vless"},
                {"name": "美国 Mxioc CN2→落地 VLESS 🇺🇸", "type": "vless", "dialer-proxy": "入口"},
                {"name": "日本 Mxioc TUIC 🇯🇵", "type": "tuic"},
                {"name": "导入的 SOCKS5 节点", "type": "socks5"},
            ],
            "proxy-groups": [
                {"name": "✈️ Proxy", "type": "select", "proxies": ["DIRECT", "香港 Mxioc VLESS 🇭🇰"]},
                {"name": "🤖 ChatGPT", "type": "select", "proxies": ["DIRECT", "香港 Mxioc VLESS 🇭🇰"]},
            ],
        }
        original_nodes = copy.deepcopy(doc["proxies"])
        original_business = copy.deepcopy(doc["proxy-groups"][1])
        result = layout.organize(doc)

        self.assertEqual(doc["proxies"], original_nodes)
        self.assertEqual(next(g for g in doc["proxy-groups"] if g["name"] == "🤖 ChatGPT"), original_business)
        main = next(g for g in doc["proxy-groups"] if g["name"] == "✈️ Proxy")
        self.assertEqual(main["proxies"][0:2], ["DIRECT", "美国 Mxioc CN2→落地 VLESS 🇺🇸"])
        self.assertIn("🇭🇰 香港节点", main["proxies"])
        self.assertIn("🔗 链式代理", main["proxies"])
        self.assertEqual(result["🧰 其他节点"], ["导入的 SOCKS5 节点"])


if __name__ == "__main__":
    unittest.main()
