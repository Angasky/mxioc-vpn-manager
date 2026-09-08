#!/usr/bin/env python3
import hashlib
import hmac
import base64
import json
import os
import copy
import re
import secrets
import shutil
import tempfile
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse, urlsplit

import yaml

ROOT = Path("/opt/mxioc-rule-manager")
FRONT = ROOT / "index.html"
AUTH = Path("/etc/mxioc-rule-manager.auth.json")
LEGACY_AUTH = Path("/etc/mxioc-rule-manager.auth")
FILES = [
    Path("/etc/sing-box/subscribe/clash-cn-route"),
    Path("/etc/sing-box/subscribe/clash-cn-route.yml"),
]
PROFILES_FILE = ROOT / "profiles.json"
PROFILES_DIR = ROOT / "profiles"
BACKUP_DIR = ROOT / "backups"
SESSIONS = {}
LOCK = threading.RLock()
CTX = threading.local()
MAX_BODY = 2 * 1024 * 1024
BUILTINS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
NON_NODE_GROUPS = {"🛑 广告拦截", "🛡️ 基础广告拦截", "🔥 强力广告拦截"}


def load_profiles():
    ROOT.mkdir(parents=True, exist_ok=True)
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    if not PROFILES_FILE.exists():
        data = {"profiles": [{"id": "clash", "name": "Mxioc VPN", "protected": True,
                              "files": [str(path) for path in FILES]}]}
        save_profiles(data)
    data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
    if not isinstance(data.get("profiles"), list):
        raise ValueError("订阅配置索引损坏")
    return data


def save_profiles(data):
    PROFILES_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(PROFILES_FILE, 0o600)


def profile_record(profile_id=None):
    profile_id = profile_id or getattr(CTX, "profile", "clash") or "clash"
    record = next((x for x in load_profiles()["profiles"] if x.get("id") == profile_id), None)
    if not record:
        raise ValueError("所选订阅配置不存在")
    return record


def current_files(profile_id=None):
    record = profile_record(profile_id)
    return [Path(x) for x in record.get("files", [])]


def empty_profile_config():
    return {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info",
        "ipv6": False, "proxies": [],
        "proxy-groups": [{"name": "\u2708\ufe0f Proxy", "type": "select", "proxies": ["DIRECT"]}],
        "rules": ["MATCH,\u2708\ufe0f Proxy"],
        "dns": {"enable": True, "ipv6": False, "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "default-nameserver": ["223.5.5.5", "119.29.29.29"],
                "nameserver": ["https://1.1.1.1/dns-query#%E2%9C%88%EF%B8%8F%20Proxy",
                               "https://dns.google/dns-query#%E2%9C%88%EF%B8%8F%20Proxy"],
                "direct-nameserver": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
                "direct-nameserver-follow-policy": False, "nameserver-policy": {}}
    }


def public_profile(record):
    return {"id": record["id"], "name": record.get("name", record["id"]),
            "protected": bool(record.get("protected")),
            "url": "/clash" if record["id"] == "clash" else "/sub/" + record["id"]}


def list_profiles():
    return [public_profile(x) for x in load_profiles()["profiles"]]


def valid_profile_id(value):
    value = str(value or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,39}", value):
        raise ValueError("链接标识只能使用 2-40 位小写字母、数字、横线或下划线")
    if value in {"admin", "sub", "clash"}:
        raise ValueError("该链接标识已被系统保留")
    return value


def create_profile(payload):
    data = load_profiles()
    profile_id = valid_profile_id(payload.get("id"))
    name = str(payload.get("name", "")).strip()
    if not name:
        raise ValueError("订阅名称不能为空")
    if any(x["id"] == profile_id for x in data["profiles"]):
        raise ValueError("订阅链接标识已经存在")
    template_id = str(payload.get("templateId", "blank"))
    if template_id == "blank":
        doc = empty_profile_config()
    else:
        doc = copy.deepcopy(yaml.safe_load(current_files(template_id)[0].read_text(encoding="utf-8")))
    path = PROFILES_DIR / f"{profile_id}.yaml"
    validate_config(doc)
    path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=4096), encoding="utf-8")
    os.chmod(path, 0o644)
    data["profiles"].append({"id": profile_id, "name": name, "protected": False, "files": [str(path)]})
    save_profiles(data)
    return public_profile(data["profiles"][-1])


def update_profile(payload):
    data = load_profiles()
    old_id = str(payload.get("oldId", ""))
    record = next((x for x in data["profiles"] if x["id"] == old_id), None)
    if not record:
        raise ValueError("订阅配置不存在")
    name = str(payload.get("name", "")).strip()
    if not name:
        raise ValueError("订阅名称不能为空")
    record["name"] = name
    if not record.get("protected"):
        new_id = valid_profile_id(payload.get("id"))
        if new_id != old_id and any(x["id"] == new_id for x in data["profiles"]):
            raise ValueError("新的链接标识已经存在")
        if new_id != old_id:
            old_path = Path(record["files"][0])
            new_path = PROFILES_DIR / f"{new_id}.yaml"
            old_path.rename(new_path)
            record["id"] = new_id
            record["files"] = [str(new_path)]
    save_profiles(data)
    return public_profile(record)


def delete_profile(profile_id):
    data = load_profiles()
    record = next((x for x in data["profiles"] if x["id"] == profile_id), None)
    if not record:
        raise ValueError("订阅配置不存在")
    if record.get("protected"):
        raise ValueError("主订阅不能删除")
    for path in current_files(profile_id):
        path.unlink(missing_ok=True)
    data["profiles"] = [x for x in data["profiles"] if x["id"] != profile_id]
    save_profiles(data)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 240000)
    return salt, digest.hex()


def load_auth():
    if AUTH.exists():
        return json.loads(AUTH.read_text(encoding="utf-8"))
    if LEGACY_AUTH.exists():
        username, password = LEGACY_AUTH.read_text(encoding="utf-8").strip().split(":", 1)
        salt, digest = password_hash(password)
        save_auth(username, salt, digest)
        return {"username": username, "salt": salt, "hash": digest}
    password = secrets.token_urlsafe(15)
    salt, digest = password_hash(password)
    save_auth("admin", salt, digest)
    (ROOT / "initial-password.txt").write_text("admin:" + password + "\n", encoding="utf-8")
    os.chmod(ROOT / "initial-password.txt", 0o600)
    return {"username": "admin", "salt": salt, "hash": digest}


def save_auth(username, salt, digest):
    AUTH.write_text(json.dumps({"username": username, "salt": salt, "hash": digest}), encoding="utf-8")
    os.chmod(AUTH, 0o600)


def authenticate(username, password):
    auth = load_auth()
    _, digest = password_hash(password, auth["salt"])
    return hmac.compare_digest(username, auth["username"]) and hmac.compare_digest(digest, auth["hash"])


def session_valid(header):
    if not header.startswith("Bearer "):
        return False
    token = header[7:]
    expires = SESSIONS.get(token, 0)
    if expires <= time.time():
        SESSIONS.pop(token, None)
        return False
    SESSIONS[token] = time.time() + 12 * 3600
    return True


def read_config():
    files = current_files()
    with LOCK:
        doc = yaml.safe_load(files[0].read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("配置文件不是有效的 YAML 对象")
    return doc


def validate_config(doc):
    if not isinstance(doc, dict):
        raise ValueError("配置必须是 YAML 对象")
    proxies = doc.get("proxies", [])
    groups = doc.get("proxy-groups", [])
    rules = doc.get("rules", [])
    if not isinstance(proxies, list) or not isinstance(groups, list) or not isinstance(rules, list):
        raise ValueError("proxies、proxy-groups 和 rules 必须是数组")
    node_names = [x.get("name") for x in proxies if isinstance(x, dict)]
    group_names = [x.get("name") for x in groups if isinstance(x, dict)]
    if any(not x for x in node_names + group_names):
        raise ValueError("节点和策略组必须有名称")
    if len(node_names) != len(set(node_names)):
        raise ValueError("节点名称不能重复")
    if len(group_names) != len(set(group_names)):
        raise ValueError("策略组名称不能重复")
    known = set(node_names) | set(group_names) | BUILTINS
    for group in groups:
        for ref in group.get("proxies", []) or []:
            if ref not in known:
                raise ValueError(f"策略组 {group['name']} 引用了不存在的项目：{ref}")
    for node in proxies:
        if not node.get("type") or not node.get("server") or not node.get("port"):
            raise ValueError(f"节点 {node.get('name', '?')} 缺少 type、server 或 port")
        dialer = node.get("dialer-proxy")
        if dialer and dialer not in known:
            raise ValueError(f"链式节点 {node.get('name', '?')} 引用了不存在的前置中转：{dialer}")
    yaml.safe_load(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False))


def write_config(doc, reason="manual"):
    validate_config(doc)
    text = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=4096)
    yaml.safe_load(text)
    profile_id = profile_record()["id"]
    files = current_files()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with LOCK:
        shutil.copy2(files[0], BACKUP_DIR / f"{profile_id}.{stamp}.{reason}.yaml")
        for path in files:
            fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_name, 0o644)
                os.replace(temp_name, path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
    prune_backups()


def prune_backups():
    items = sorted(BACKUP_DIR.glob("*.yaml"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in items[100:]:
        old.unlink(missing_ok=True)


def rule_parts(raw):
    if not isinstance(raw, str):
        return {"raw": str(raw), "type": "RAW", "value": str(raw), "action": "", "options": ""}
    if raw.startswith("MATCH,"):
        return {"raw": raw, "type": "MATCH", "value": "", "action": raw.split(",", 1)[1], "options": ""}
    parts = raw.split(",")
    if len(parts) < 3:
        return {"raw": raw, "type": "RAW", "value": raw, "action": "", "options": ""}
    action_index = len(parts) - 1
    if parts[-1] in ("no-resolve", "src") and len(parts) >= 4:
        action_index -= 1
    return {
        "raw": raw,
        "type": parts[0],
        "value": ",".join(parts[1:action_index]),
        "action": parts[action_index],
        "options": ",".join(parts[action_index + 1:]),
    }


def build_rule(item):
    if item.get("rawMode"):
        raw = str(item.get("raw", "")).strip()
        if not raw or "\n" in raw or "\r" in raw:
            raise ValueError("原始规则不能为空或包含换行")
        return raw
    kind = str(item.get("type", "DOMAIN-SUFFIX")).strip().upper()
    value = str(item.get("value", "")).strip()
    action = str(item.get("action", "DIRECT")).strip()
    options = str(item.get("options", "")).strip().strip(",")
    if kind == "MATCH":
        return f"MATCH,{action}"
    if not kind or not value or not action or any(x in value for x in "\r\n"):
        raise ValueError("规则类型、匹配值和动作不能为空")
    return f"{kind},{value},{action}" + (f",{options}" if options else "")


def b64decode_text(value):
    value = unquote(value).strip()
    value += "=" * (-len(value) % 4)
    try:
        return __import__("base64").urlsafe_b64decode(value.encode()).decode("utf-8")
    except Exception:
        return __import__("base64").b64decode(value.encode()).decode("utf-8")


def first(query, *names, default=""):
    for name in names:
        if name in query and query[name]:
            return unquote(query[name][0])
    return default


def bool_value(value, default=False):
    if value is None or value == "":
        return default
    return str(value).lower() in ("1", "true", "yes", "on")


def certificate_fingerprint(value):
    """Convert a PEM certificate carried in a share-link query into Mihomo's SHA-256 pin."""
    value = str(value or "").strip()
    if not value:
        return ""
    match = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        value,
        flags=re.S,
    )
    if not match:
        raise ValueError("TLS 证书内容不完整")
    # parse_qs converts literal '+' in base64 into spaces. Commas in links are line separators.
    encoded = match.group(1).replace(",", "")
    encoded = "".join("+" if char.isspace() else char for char in encoded)
    try:
        der = base64.b64decode(encoded, validate=True)
    except Exception as error:
        raise ValueError("TLS 证书不是有效的 PEM/Base64 内容") from error
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))


def parse_node_link(link):
    link = str(link or "").strip().strip('"\'').replace("\\://", "://").replace("\\@", "@").replace("\\.", ".")
    if not link or "://" not in link:
        raise ValueError("请输入完整的节点链接")
    scheme = link.split("://", 1)[0].lower()
    if scheme == "hy2":
        link = "hysteria2://" + link.split("://", 1)[1]
        scheme = "hysteria2"
    if scheme == "vmess":
        raw = link.split("://", 1)[1].split("#", 1)[0]
        data = json.loads(b64decode_text(raw))
        config = {
            "name": str(data.get("ps") or "导入的 VMess 节点"), "type": "vmess",
            "server": str(data.get("add") or ""), "port": int(data.get("port") or 0),
            "uuid": str(data.get("id") or ""), "alterId": int(data.get("aid") or 0),
            "cipher": str(data.get("scy") or "auto"), "udp": True,
            "network": str(data.get("net") or "tcp")
        }
        if str(data.get("tls", "")).lower() in ("tls", "1", "true"):
            config["tls"] = True
        sni = str(data.get("sni") or data.get("host") or "")
        if sni:
            config["servername"] = sni
        if config["network"] == "ws":
            config["ws-opts"] = {"path": str(data.get("path") or "/")}
            if data.get("host"):
                config["ws-opts"]["headers"] = {"Host": str(data["host"])}
        elif config["network"] == "grpc":
            config["grpc-opts"] = {"grpc-service-name": str(data.get("path") or data.get("serviceName") or "grpc")}
        return config
    if scheme == "ss":
        body = link.split("://", 1)[1]
        fragment = unquote(body.split("#", 1)[1]) if "#" in body else "导入的 Shadowsocks 节点"
        body = body.split("#", 1)[0].split("?", 1)[0]
        if "@" not in body:
            body = b64decode_text(body)
        auth, endpoint = body.rsplit("@", 1)
        if ":" not in auth:
            auth = b64decode_text(auth)
        cipher, password = auth.split(":", 1)
        parsed = urlsplit("ss://x@" + endpoint)
        return {"name": fragment, "type": "ss", "server": parsed.hostname or "",
                "port": parsed.port or 0, "cipher": unquote(cipher), "password": unquote(password), "udp": True}
    if scheme not in ("vless", "tuic", "hysteria2", "trojan"):
        raise ValueError("暂不支持该链接协议")
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    name = unquote(parsed.fragment) or f"导入的 {scheme.upper()} 节点"
    config = {"name": name, "type": scheme, "server": parsed.hostname or "",
              "port": parsed.port or 0, "udp": True}
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    network = first(query, "type", "network", default="tcp")
    sni = first(query, "sni", "peer", "servername")
    if scheme == "vless":
        config.update({"uuid": username, "network": network, "encryption": first(query, "encryption", default="none")})
        flow = first(query, "flow")
        if flow: config["flow"] = flow
        security = first(query, "security")
        if security in ("tls", "reality"):
            config["tls"] = True
        if sni: config["servername"] = sni
        fingerprint = first(query, "fp", "fingerprint")
        if fingerprint: config["client-fingerprint"] = fingerprint
        public_key, short_id = first(query, "pbk", "publicKey"), first(query, "sid", "shortId")
        if public_key:
            config["reality-opts"] = {"public-key": public_key, "short-id": short_id}
    elif scheme == "tuic":
        config.update({"uuid": username, "password": password or first(query, "password"),
                       "congestion-controller": first(query, "congestion_control", "congestion-controller", default="bbr"),
                       "udp-relay-mode": first(query, "udp_relay_mode", "udp-relay-mode", default="native")})
        if sni: config["sni"] = sni
        alpn = first(query, "alpn", default="h3") or "h3"
        config["alpn"] = [x for x in alpn.split(",") if x]
        if bool_value(first(query, "allow_insecure", "insecure")): config["skip-cert-verify"] = True
    elif scheme == "hysteria2":
        config["password"] = password or username
        if sni: config["sni"] = sni
        obfs = first(query, "obfs")
        if obfs: config["obfs"] = obfs
        obfs_password = first(query, "obfs-password", "obfsPassword")
        if obfs_password: config["obfs-password"] = obfs_password
        alpn = first(query, "alpn") or "h3"
        config["alpn"] = [x for x in alpn.split(",") if x]
        up, down = first(query, "upmbps", "up"), first(query, "downmbps", "down")
        if up: config["up"] = up if re.search(r"[a-zA-Z]", up) else f"{up} Mbps"
        if down: config["down"] = down if re.search(r"[a-zA-Z]", down) else f"{down} Mbps"
        if bool_value(first(query, "insecure", "allowInsecure")): config["skip-cert-verify"] = True
    else:
        config.update({"password": username, "network": network})
        if sni: config["sni"] = sni
        fingerprint = first(query, "fp", "fingerprint")
        if fingerprint: config["client-fingerprint"] = fingerprint
        if bool_value(first(query, "allowInsecure", "insecure")): config["skip-cert-verify"] = True
    if network == "grpc":
        config["grpc-opts"] = {"grpc-service-name": first(query, "serviceName", "service_name", default="grpc")}
    elif network == "ws":
        config["ws-opts"] = {"path": first(query, "path", default="/")}
        host = first(query, "host")
        if host: config["ws-opts"]["headers"] = {"Host": host}
    if scheme in ("tuic", "hysteria2"):
        embedded_certificate = first(query, "tls_certificate", "tls-certificate")
        if embedded_certificate:
            config["fingerprint"] = certificate_fingerprint(embedded_certificate)
    if not config.get("server") or not config.get("port"):
        raise ValueError("链接中缺少服务器地址或端口")
    return config


def snapshot():
    doc = read_config()
    files = current_files()
    proxies = []
    for index, node in enumerate(doc.get("proxies", [])):
        proxies.append({"index": index, "name": node.get("name", ""), "type": node.get("type", ""),
                        "server": node.get("server", ""), "port": node.get("port", ""), "config": node})
    groups = []
    for index, group in enumerate(doc.get("proxy-groups", [])):
        groups.append({"index": index, "name": group.get("name", ""), "type": group.get("type", ""),
                       "count": len(group.get("proxies", []) or []), "config": group})
    rules = []
    for index, raw in enumerate(doc.get("rules", [])):
        row = rule_parts(raw)
        row["index"] = index
        rules.append(row)
    policy = doc.get("dns", {}).get("nameserver-policy", {}) or {}
    dns_policies = [{"domain": key, "servers": value if isinstance(value, list) else [value]}
                    for key, value in policy.items()]
    return {"nodes": proxies, "groups": groups, "rules": rules, "dnsPolicies": dns_policies,
            "updated": datetime.fromtimestamp(files[0].stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "profile": public_profile(profile_record())}


def replace_references(doc, old, new=None):
    for node in doc.get("proxies", []):
        if node.get("dialer-proxy") == old and new:
            node["dialer-proxy"] = new
    for group in doc.get("proxy-groups", []):
        refs = group.get("proxies", []) or []
        group["proxies"] = [new if ref == old and new else ref for ref in refs if ref != old or new]
    updated = []
    for raw in doc.get("rules", []):
        parts = rule_parts(raw)
        if parts["action"] == old:
            if new:
                raw = raw[:raw.rfind(old)] + new + raw[raw.rfind(old) + len(old):]
            else:
                continue
        updated.append(raw)
    doc["rules"] = updated


def mutate_node(method, payload):
    doc = read_config()
    nodes = doc.setdefault("proxies", [])
    old_name = str(payload.get("oldName", ""))
    if method == "DELETE":
        name = str(payload.get("name", ""))
        if not any(x.get("name") == name for x in nodes):
            raise ValueError("节点不存在")
        dependants = [x.get("name") for x in nodes if x.get("dialer-proxy") == name]
        if dependants:
            raise ValueError("该节点正被链式代理用作前置中转，请先删除或修改：" + "、".join(dependants))
        doc["proxies"] = [x for x in nodes if x.get("name") != name]
        replace_references(doc, name)
    else:
        config = payload.get("config")
        if not isinstance(config, dict):
            raise ValueError("节点配置必须是 JSON 对象")
        config = dict(config)
        name = str(config.get("name", "")).strip()
        if not name:
            raise ValueError("节点名称不能为空")
        if method == "POST":
            if any(x.get("name") == name for x in nodes):
                raise ValueError("节点名称已存在")
            nodes.append(config)
            if payload.get("addToGroups", True):
                for group in doc.get("proxy-groups", []):
                    if (group.get("type") == "select"
                            and group.get("name") not in NON_NODE_GROUPS
                            and name not in (group.get("proxies", []) or [])):
                        group.setdefault("proxies", []).append(name)
        else:
            index = next((i for i, x in enumerate(nodes) if x.get("name") == old_name), -1)
            if index < 0:
                raise ValueError("原节点不存在")
            if name != old_name and any(x.get("name") == name for x in nodes):
                raise ValueError("新节点名称已存在")
            nodes[index] = config
            if name != old_name:
                replace_references(doc, old_name, name)
    write_config(doc, "node")


def mutate_group(method, payload):
    doc = read_config()
    groups = doc.setdefault("proxy-groups", [])
    old_name = str(payload.get("oldName", ""))
    if method == "DELETE":
        name = str(payload.get("name", ""))
        if name == "\u2708\ufe0f Proxy":
            raise ValueError("主 Proxy 策略组不能删除")
        if not any(x.get("name") == name for x in groups):
            raise ValueError("策略组不存在")
        groups[:] = [x for x in groups if x.get("name") != name]
        replace_references(doc, name)
    else:
        config = payload.get("config")
        if not isinstance(config, dict):
            raise ValueError("策略组配置必须是 JSON 对象")
        config = dict(config)
        name = str(config.get("name", "")).strip()
        config["name"] = name
        if not name or not config.get("type"):
            raise ValueError("策略组名称和类型不能为空")
        if method == "POST":
            if any(x.get("name") == name for x in groups):
                raise ValueError("策略组名称已存在")
            groups.append(config)
        else:
            index = next((i for i, x in enumerate(groups) if x.get("name") == old_name), -1)
            if index < 0:
                raise ValueError("原策略组不存在")
            if name != old_name and any(x.get("name") == name for x in groups):
                raise ValueError("新策略组名称已存在")
            groups[index] = config
            if name != old_name:
                replace_references(doc, old_name, name)
    write_config(doc, "group")


def mutate_rule(method, payload):
    doc = read_config()
    rules = doc.setdefault("rules", [])
    old_raw = str(payload.get("oldRaw", ""))
    if method == "DELETE":
        if old_raw not in rules:
            raise ValueError("规则不存在")
        rules.remove(old_raw)
    else:
        raw = build_rule(payload)
        if method == "POST":
            index = int(payload.get("index", 0))
            rules.insert(max(0, min(index, len(rules))), raw)
        else:
            try:
                index = rules.index(old_raw)
            except ValueError:
                raise ValueError("原规则不存在")
            rules[index] = raw
    write_config(doc, "rule")


def move_rule(payload):
    doc = read_config()
    rules = doc.setdefault("rules", [])
    raw = str(payload.get("raw", ""))
    try:
        index = rules.index(raw)
    except ValueError:
        raise ValueError("规则不存在")
    direction = int(payload.get("direction", 0))
    target = max(0, min(len(rules) - 1, index + direction))
    rules[index], rules[target] = rules[target], rules[index]
    write_config(doc, "rule-order")


def mutate_dns(method, payload):
    doc = read_config()
    policy = doc.setdefault("dns", {}).setdefault("nameserver-policy", {})
    old = str(payload.get("oldDomain", ""))
    if method == "DELETE":
        if old not in policy:
            raise ValueError("DNS 分流规则不存在")
        del policy[old]
    else:
        domain = str(payload.get("domain", "")).strip()
        servers = payload.get("servers", [])
        if isinstance(servers, str):
            servers = [x.strip() for x in servers.splitlines() if x.strip()]
        if not domain or not servers:
            raise ValueError("域名和 DNS 服务器不能为空")
        if old and old != domain:
            policy.pop(old, None)
        policy[domain] = servers
    write_config(doc, "dns")


class Handler(BaseHTTPRequestHandler):
    server_version = "MxiocManager/2"

    def json_out(self, value, status=200):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY:
            raise ValueError("请求内容过大")
        return json.loads(self.rfile.read(length) or b"{}")

    def authorized(self):
        if session_valid(self.headers.get("Authorization", "")):
            return True
        self.json_out({"error": "请重新登录"}, 401)
        return False

    def select_profile(self):
        profile_id = self.headers.get("X-Profile", "clash")
        profile_record(profile_id)
        CTX.profile = profile_id

    def subscription(self, profile_id):
        try:
            record = profile_record(profile_id)
            body = current_files(profile_id)[0].read_bytes()
            filename = quote(record.get("name", profile_id) + ".yaml")
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + filename)
            self.send_header("Profile-Update-Interval", "24")
            self.send_header("Subscription-Userinfo", "upload=0; download=0; total=1125899906842624; expire=4102444800")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            self.send_error(404)

    def page(self):
        body = FRONT.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/admin", "/admin/"):
            return self.page()
        if path.startswith("/sub/"):
            return self.subscription(unquote(path[5:]))
        if not self.authorized():
            return
        try:
            if path == "/admin/api/profiles":
                self.json_out({"profiles": list_profiles()})
                return
            self.select_profile()
            if path == "/admin/api/snapshot":
                self.json_out(snapshot())
            elif path == "/admin/api/raw":
                self.json_out({"yaml": current_files()[0].read_text(encoding="utf-8")})
            elif path == "/admin/api/backups":
                BACKUP_DIR.mkdir(parents=True, exist_ok=True)
                profile_id = profile_record()["id"]
                items = sorted(BACKUP_DIR.glob(profile_id + ".*.yaml"), key=lambda p: p.stat().st_mtime, reverse=True)
                self.json_out({"backups": [{"name": p.name, "size": p.stat().st_size,
                                             "time": datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")}
                                            for p in items[:100]]})
            else:
                self.send_error(404)
        except Exception as exc:
            self.json_out({"error": str(exc)}, 400)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/admin/api/login":
            try:
                data = self.body()
                if not authenticate(str(data.get("username", "")), str(data.get("password", ""))):
                    time.sleep(0.35)
                    return self.json_out({"error": "用户名或密码错误"}, 401)
                token = secrets.token_urlsafe(32)
                SESSIONS[token] = time.time() + 12 * 3600
                return self.json_out({"token": token})
            except Exception as exc:
                return self.json_out({"error": str(exc)}, 400)
        if not self.authorized():
            return
        try:
            data = self.body()
            if path == "/admin/api/profiles":
                return self.json_out({"ok": True, "profile": create_profile(data)})
            self.select_profile()
            if path == "/admin/api/nodes": mutate_node("POST", data)
            elif path == "/admin/api/import-node":
                config = parse_node_link(data.get("link", ""))
                mutate_node("POST", {"config": config, "addToGroups": data.get("addToGroups", True)})
            elif path == "/admin/api/groups": mutate_group("POST", data)
            elif path == "/admin/api/rules": mutate_rule("POST", data)
            elif path == "/admin/api/rules/move": move_rule(data)
            elif path == "/admin/api/dns": mutate_dns("POST", data)
            elif path == "/admin/api/password":
                if not authenticate(str(data.get("username", "")), str(data.get("current", ""))):
                    raise ValueError("当前密码错误")
                new_password = str(data.get("new", ""))
                if len(new_password) < 10:
                    raise ValueError("新密码至少需要 10 位")
                auth = load_auth()
                salt, digest = password_hash(new_password)
                save_auth(auth["username"], salt, digest)
                SESSIONS.clear()
            elif path == "/admin/api/backups/restore":
                name = Path(str(data.get("name", ""))).name
                backup = BACKUP_DIR / name
                if not backup.exists():
                    raise ValueError("备份不存在")
                doc = yaml.safe_load(backup.read_text(encoding="utf-8"))
                write_config(doc, "before-restore")
            else:
                return self.send_error(404)
            self.json_out({"ok": True})
        except Exception as exc:
            self.json_out({"error": str(exc)}, 400)

    def do_PUT(self):
        if not self.authorized():
            return
        path = urlparse(self.path).path
        try:
            data = self.body()
            if path == "/admin/api/profiles":
                return self.json_out({"ok": True, "profile": update_profile(data)})
            self.select_profile()
            if path == "/admin/api/nodes": mutate_node("PUT", data)
            elif path == "/admin/api/groups": mutate_group("PUT", data)
            elif path == "/admin/api/rules": mutate_rule("PUT", data)
            elif path == "/admin/api/dns": mutate_dns("PUT", data)
            elif path == "/admin/api/raw":
                doc = yaml.safe_load(str(data.get("yaml", "")))
                write_config(doc, "raw")
            else:
                return self.send_error(404)
            self.json_out({"ok": True})
        except Exception as exc:
            self.json_out({"error": str(exc)}, 400)

    def do_DELETE(self):
        if not self.authorized():
            return
        path = urlparse(self.path).path
        try:
            data = self.body()
            if path == "/admin/api/profiles":
                delete_profile(str(data.get("id", "")))
                return self.json_out({"ok": True})
            self.select_profile()
            if path == "/admin/api/nodes": mutate_node("DELETE", data)
            elif path == "/admin/api/groups": mutate_group("DELETE", data)
            elif path == "/admin/api/rules": mutate_rule("DELETE", data)
            elif path == "/admin/api/dns": mutate_dns("DELETE", data)
            else:
                return self.send_error(404)
            self.json_out({"ok": True})
        except Exception as exc:
            self.json_out({"error": str(exc)}, 400)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    load_profiles()
    load_auth()
    ThreadingHTTPServer(("127.0.0.1", 62577), Handler).serve_forever()
