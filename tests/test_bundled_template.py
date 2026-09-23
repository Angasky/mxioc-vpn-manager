import importlib.util
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mxioc_server_template_test", ROOT / "server.py")
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)
TEMPLATE = ROOT / "templates" / "clash.yaml"


def load_template():
    return yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))


def test_bundled_template_is_complete_and_has_no_nodes():
    doc = load_template()
    server.validate_config(doc)

    assert doc["proxies"] == []
    assert len(doc["proxy-groups"]) == 20
    assert len(doc["rules"]) >= 200
    assert len(doc["rule-providers"]) == 17
    assert doc["dns"]["nameserver-policy"]

    group_names = {group["name"] for group in doc["proxy-groups"]}
    required = {
        "✈️ Proxy", "🤖 ChatGPT", "▶️ YouTube", "𝕏 X/推特", "💬 WhatsApp",
        "📘 Facebook", "✈️ Telegram", "🎬 Netflix", "📹 TikTok",
        "🛍️ TIKTOK SHOP", "☁️ 甲骨文 Oracle", "🛡️ 基础广告拦截", "🔥 强力广告拦截",
    }
    assert required <= group_names


def test_bundled_template_contains_no_private_line_endpoints():
    doc = load_template()
    serialized = yaml.safe_dump(doc, allow_unicode=True).lower()
    for marker in ("mxioc.com", "sexydick.me", "3hcloud", "hybgzs", "yunque56.com"):
        assert marker not in serialized

    for rule in doc["rules"]:
        if rule.startswith("IP-CIDR,"):
            assert "/32," not in rule
        if rule.startswith("IP-CIDR6,"):
            assert "/128," not in rule or rule.startswith("IP-CIDR6,::1/128,")


def test_empty_profile_uses_an_independent_template_copy():
    first = server.empty_profile_config(TEMPLATE)
    second = server.empty_profile_config(TEMPLATE)
    assert first == load_template()
    first["proxy-groups"][0]["proxies"].append("MUTATED")
    assert "MUTATED" not in second["proxy-groups"][0]["proxies"]
