#!/usr/bin/env python3
import os
import tempfile
import urllib.request
from pathlib import Path


DESTINATION = Path("/opt/mxioc-rule-manager/rules/clash")
SOURCES = {
    "anti-ad-basic.yaml": {
        "url": "https://anti-ad.net/clash.yaml",
        "minimum_rules": 50000,
    },
    "advertising-lite-strong.yaml": {
        "url": (
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Clash/AdvertisingLite/AdvertisingLite_Classical.yaml"
        ),
        "minimum_rules": 20000,
    },
}


def update_file(name, source):
    request = urllib.request.Request(
        source["url"], headers={"User-Agent": "Mxioc-AdRules-Updater/1.0"}
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        content = response.read()
    text = content.decode("utf-8")
    if "payload:" not in text:
        raise ValueError(f"{name}: upstream file has no payload")
    rule_count = sum(1 for line in text.splitlines() if line.lstrip().startswith("- "))
    if rule_count < source["minimum_rules"]:
        raise ValueError(f"{name}: only {rule_count} rules received")

    descriptor, temporary_name = tempfile.mkstemp(prefix=name + ".", dir=DESTINATION)
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, DESTINATION / name)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return rule_count


def main():
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for name, source in SOURCES.items():
        print(f"{name}: {update_file(name, source)} rules")


if __name__ == "__main__":
    main()
