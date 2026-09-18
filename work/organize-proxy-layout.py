#!/usr/bin/env python3
"""One-time production layout organizer; preserves every proxy object and node name."""

import sys

sys.path.insert(0, "/opt/mxioc-rule-manager")
import server  # noqa: E402


CATEGORY_ORDER = [
    "⭐ 常用节点",
    "🇭🇰 香港节点",
    "🇺🇸 美国节点",
    "🇯🇵 日本节点",
    "🇰🇷 韩国节点",
    "🇻🇳 越南节点",
    "🔗 链式代理",
    "🧰 其他节点",
]


def names_matching(nodes, predicate):
    return [node["name"] for node in nodes if predicate(node)]


def organize(doc):
    nodes = doc.get("proxies", [])
    before_names = [node.get("name") for node in nodes]

    categories = {
        "⭐ 常用节点": names_matching(nodes, lambda n: (
            "⭐" in n["name"] or "GPT专用" in n["name"] or n["name"].startswith("🚀")
            or "CN2→落地 VLESS" in n["name"]
        )),
        "🇭🇰 香港节点": names_matching(nodes, lambda n: (
            "🇭🇰" in n["name"] or "香港" in n["name"] or n["name"].startswith("HK ")
        )),
        "🇺🇸 美国节点": names_matching(nodes, lambda n: (
            "🇺🇸" in n["name"] or "美国" in n["name"] or n["name"].startswith("🚀US ")
            or "洛杉矶" in n["name"] or "GPT专用" in n["name"]
        )),
        "🇯🇵 日本节点": names_matching(nodes, lambda n: "🇯🇵" in n["name"] or "日本" in n["name"]),
        "🇰🇷 韩国节点": names_matching(nodes, lambda n: "🇰🇷" in n["name"] or "韩国" in n["name"]),
        "🇻🇳 越南节点": names_matching(nodes, lambda n: (
            "🇻🇳" in n["name"] or "越南" in n["name"] or "VN 住宅" in n["name"]
        )),
        "🔗 链式代理": names_matching(nodes, lambda n: bool(n.get("dialer-proxy"))),
    }
    categorized = {name for values in categories.values() for name in values}
    categories["🧰 其他节点"] = [name for name in before_names if name not in categorized]

    groups = doc.setdefault("proxy-groups", [])
    main_index = next((i for i, group in enumerate(groups) if group.get("name") == "✈️ Proxy"), -1)
    if main_index < 0:
        raise ValueError("未找到主代理组 ✈️ Proxy")
    main = groups[main_index]
    old_group_names = set(CATEGORY_ORDER)
    groups[:] = [group for group in groups if group.get("name") not in old_group_names]
    main_index = groups.index(main)
    category_groups = [
        {"name": name, "type": "select", "proxies": categories[name]}
        for name in CATEGORY_ORDER if categories[name]
    ]
    groups[main_index + 1:main_index + 1] = category_groups

    current_shortcut = "美国 Mxioc CN2→落地 VLESS 🇺🇸"
    main["proxies"] = ["DIRECT"]
    if current_shortcut in before_names:
        main["proxies"].append(current_shortcut)
    main["proxies"].extend(group["name"] for group in category_groups)

    after_names = [node.get("name") for node in doc.get("proxies", [])]
    if before_names != after_names:
        raise RuntimeError("安全检查失败：节点名称或顺序被意外修改")
    return categories


if __name__ == "__main__":
    config = server.read_config()
    result = organize(config)
    server.write_config(config, "organize-proxy-layout")
    for group_name in CATEGORY_ORDER:
        if group_name in result:
            print(f"{group_name}: {len(result[group_name])}")
