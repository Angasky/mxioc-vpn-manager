from pathlib import Path
from urllib.parse import quote

import yaml


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "clash.yaml"
GOOGLE_GROUP = "谷歌服务"
YOUTUBE_GROUP = "▶️ YouTube"


def template():
    return yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))


def test_google_group_and_complete_provider_family_are_present():
    doc = template()
    group = next(item for item in doc["proxy-groups"] if item["name"] == GOOGLE_GROUP)
    assert group["proxies"] == ["✈️ Proxy", "DIRECT"]

    expected = {
        "youtube-services",
        "google-services-main",
        "google-services-drive",
        "google-services-earth",
        "google-services-fcm",
        "google-services-search",
        "google-services-voice",
        "google-services-gemini",
    }
    assert expected <= set(doc["rule-providers"])
    for name in expected:
        provider = doc["rule-providers"][name]
        assert provider["behavior"] == "classical"
        assert provider["format"] == "yaml"
        assert provider["interval"] == 86400


def test_youtube_rules_are_evaluated_before_google_rules():
    rules = template()["rules"]
    youtube = rules.index(f"RULE-SET,youtube-services,{YOUTUBE_GROUP}")
    google = rules.index(f"RULE-SET,google-services-main,{GOOGLE_GROUP}")
    geosite = rules.index(f"GEOSITE,google,{GOOGLE_GROUP}")
    assert youtube < google < geosite

    youtube_processes = [
        rule for rule in rules
        if rule.startswith("PROCESS-NAME,com.google.android") and rule.endswith("," + YOUTUBE_GROUP)
    ]
    assert any("youtube" in rule.lower() for rule in youtube_processes)
    assert not any("youtube" in rule.lower() and rule.endswith("," + GOOGLE_GROUP) for rule in rules)


def test_google_apps_domains_and_dns_use_google_group():
    doc = template()
    rules = doc["rules"]
    for value in (
        "com.google.android.gms", "com.android.vending", "GoogleDriveFS.exe",
    ):
        assert f"PROCESS-NAME,{value},{GOOGLE_GROUP}" in rules
    for domain in ("google.com", "googleapis.com", "gstatic.com", "googleusercontent.com"):
        assert f"DOMAIN-SUFFIX,{domain},{GOOGLE_GROUP}" in rules

    encoded_google = "#" + quote(GOOGLE_GROUP, safe="")
    encoded_youtube = "#" + quote(YOUTUBE_GROUP, safe="")
    policy = doc["dns"]["nameserver-policy"]
    for domain in (
        "+.google.com", "+.googleapis.com", "+.android.com", "+.googleplay.com",
        "+.gmail.com", "+.firebaseio.com", "+.gemini.google.com",
    ):
        assert all(encoded_google in server for server in policy[domain])
    for domain in ("+.youtube.com", "+.googlevideo.com", "+.ytimg.com"):
        assert all(encoded_youtube in server for server in policy[domain])
