#!/usr/bin/env python3
import hashlib
import hmac
import base64
import io
import gzip
import uuid
import json
import os
import copy
import ipaddress
import re
import secrets
import shutil
import socket
import string
import subprocess
import tempfile
import threading
import time
import calendar
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlsplit
from urllib.request import Request, urlopen

import yaml
import qrcode
from qrcode.image.svg import SvgPathImage
try:
    from yaml import CSafeLoader as YamlLoader, CSafeDumper as YamlDumper
except ImportError:
    from yaml import SafeLoader as YamlLoader, SafeDumper as YamlDumper


class QuotedYamlString(str):
    pass


def _represent_quoted_yaml_string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(value), style="'")


YamlDumper.add_representer(QuotedYamlString, _represent_quoted_yaml_string)


def yaml_load(stream):
    return yaml.load(stream, Loader=YamlLoader)


def quote_reality_short_ids(value):
    if isinstance(value, dict):
        return {
            key: (QuotedYamlString(str(item)) if key == "short-id" and item is not None
                  else quote_reality_short_ids(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [quote_reality_short_ids(item) for item in value]
    return value


def yaml_dump(data):
    return yaml.dump(quote_reality_short_ids(data), Dumper=YamlDumper,
                     allow_unicode=True, sort_keys=False, width=4096)


ROOT = Path("/opt/mxioc-rule-manager")
FRONT = ROOT / "index.html"
BUNDLED_TEMPLATE = ROOT / "templates" / "clash.yaml"
AUTH = Path("/etc/mxioc-rule-manager.auth.json")
LEGACY_AUTH = Path("/etc/mxioc-rule-manager.auth")
FILES = [
    Path("/etc/sing-box/subscribe/clash-cn-route"),
    Path("/etc/sing-box/subscribe/clash-cn-route.yml"),
]
PROFILES_FILE = ROOT / "profiles.json"
PROFILES_DIR = ROOT / "profiles"
BACKUP_DIR = ROOT / "backups"
SESSIONS_FILE = ROOT / "sessions.json"
BUNDLED_VERSION_FILE = ROOT / "version"
UPDATE_STATE_FILE = ROOT / "update-state.json"
UPDATE_MARKER_FILE = ROOT / "update-in-progress.json"
UPDATE_RESULT_FILE = ROOT / "update-result.json"
UPDATE_INSTALLER_FILE = ROOT / ".updates" / "install.sh"
UPDATE_RUNNER_FILE = ROOT / ".updates" / "run.sh"
REPOSITORY = "Angasky/mxioc-vpn-manager"
REPOSITORY_API = f"https://api.github.com/repos/{REPOSITORY}/commits/main"
REPOSITORY_RAW = f"https://raw.githubusercontent.com/{REPOSITORY}"
SESSIONS = None
SESSION_LOCK = threading.RLock()
SESSION_TTL = 12 * 3600
MAX_SESSIONS = 8
PBKDF2_ITERATIONS = 600_000
LEGACY_PBKDF2_ITERATIONS = 240_000
LOGIN_WINDOW = 15 * 60
LOGIN_MAX_FAILURES = 5
LOGIN_FAILURES = {}
LOGIN_LOCK = threading.RLock()
LOCK = threading.RLock()
ENFORCEMENT_LOCK = threading.RLock()
ENFORCEMENT_INTERVAL = 30
ENFORCEMENT_WAKE = threading.Event()
UPDATE_LOCK = threading.RLock()
GEO_LOCK = threading.RLock()
GEO_RATE_LOCK = threading.Lock()
GEO_CACHE = {}
GEO_NEXT_REQUEST = 0.0
REMOTE_MANAGERS = {}
REMOTE_MANAGER_LOCK = threading.RLock()
HOST_MONITOR = None
CTX = threading.local()
MAX_BODY = 2 * 1024 * 1024
MAX_SUBSCRIPTION = 8 * 1024 * 1024


def remote_manager():
    from remote_manager import RemoteManager
    with REMOTE_MANAGER_LOCK:
        key = str(ROOT.resolve())
        if key not in REMOTE_MANAGERS:
            REMOTE_MANAGERS[key] = RemoteManager(ROOT, parse_node_link, node_to_uri)
        return REMOTE_MANAGERS[key]

def host_metrics(identity):
    from server_monitor import HostMonitor
    global HOST_MONITOR
    with REMOTE_MANAGER_LOCK:
        if HOST_MONITOR is None:
            HOST_MONITOR = HostMonitor()
    return HOST_MONITOR.sample(remote_manager(), identity)

BUILTINS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
NON_NODE_GROUPS = {"🛑 广告拦截", "🛡️ 基础广告拦截", "🔥 强力广告拦截"}
SUPPORTED_NODE_TYPES = {"vless", "tuic", "hysteria2", "trojan", "ss", "vmess", "socks5", "http", "mieru", "snell"}
# A node supported by the Mihomo subscription is not necessarily supported by
# Xray or Shadowrocket. Keep their existing export compatibility explicit.
CLIENT_LINK_TYPES = SUPPORTED_NODE_TYPES - {"mieru", "snell"}
SHADOWROCKET_LINK_TYPES = CLIENT_LINK_TYPES | {"snell"}
CONVERSION_FORMATS = {
    "v2rayn": {
        "name": "电脑 v2rayN 节点订阅", "types": CLIENT_LINK_TYPES,
        "note": "新版 v2rayN；独立信息节点显示流量和剩余时间，更新订阅刷新。信息节点不可连接；TUIC/Hysteria2 需支持的内核。",
    },
    "v2rayng": {
        "name": "安卓 v2rayNG 节点订阅", "types": CLIENT_LINK_TYPES - {"tuic"},
        "note": "新版 v2rayNG；提供标准流量和到期响应头，过滤不支持的 TUIC。节点列表不含主备逻辑。",
    },
    "v2rayn-ha": {
        "name": "电脑 v2rayN · Xray 主备配置", "types": set(), "kind": "xray-ha",
        "extension": ".json", "contentType": "application/json; charset=utf-8",
        "note": "作为独立订阅导入，使用新版 Xray 内核；每个主备组生成一份自定义配置，按顺序切换及恢复切回。SOCKS/HTTP 端口 10808/10809。",
    },
    "v2rayng-ha": {
        "name": "安卓 v2rayNG · Xray 主备配置", "types": set(), "kind": "xray-ha",
        "extension": ".json", "contentType": "application/json; charset=utf-8",
        "note": "新版 v2rayNG 自定义 JSON 订阅；每个主备组一份完整 Xray 配置，不与普通节点订阅混用。端口需与 App 的本地 SOCKS 设置一致（默认 10808）。",
    },
    "shadowrocket-ha": {
        "name": "小火箭主备 · 第一步：节点订阅", "types": SHADOWROCKET_LINK_TYPES, "kind": "shadowrocket-nodes",
        "note": "添加到首页订阅。仅包含受管主备组的转发路径，名称与第二步策略配置对应；流量与到期信息随订阅更新。",
    },
    "shadowrocket-config": {
        "name": "小火箭主备 · 第二步：策略配置", "types": set(), "kind": "shadowrocket-config", "extension": ".conf",
        "note": "先导入第一步节点，再在配置页添加并启用此配置，使用配置路由。按优先顺序 fallback，勿开启可能跳到其他出口的全局回退；恢复切回仍需在 iPhone 实测。",
    },
    "v2ray": {
        "name": "V2Ray 通用节点订阅（兼容旧链接）",
        "types": CLIENT_LINK_TYPES,
        "note": "适合新版 v2rayN；旧版 V2Ray/v2rayNG 可能不支持 TUIC、Hysteria2 或 Reality。",
    },
    "shadowrocket": {
        "name": "Shadowrocket（小火箭）订阅",
        "types": SHADOWROCKET_LINK_TYPES,
        "note": "适合新版 Shadowrocket，包含 Snell 节点与 PSK；服务端协议版本须匹配，旧客户端请先升级。",
    },
}


def read_json_file(path, default=None):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else (default or {})
    except Exception:
        return default or {}


def write_json_file(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def current_version():
    try:
        return BUNDLED_VERSION_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def fetch_latest_release():
    request = Request(REPOSITORY_API, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "mxioc-vpn-manager-update-checker",
    })
    with urlopen(request, timeout=15) as response:
        payload = json.loads(response.read(MAX_BODY).decode("utf-8"))
    commit = payload.get("commit") or {}
    return {
        "latestSha": str(payload.get("sha", "")),
        "latestMessage": str((commit.get("message") or "").splitlines()[0]),
        "latestUrl": str(payload.get("html_url", "")),
        "publishedAt": str(((commit.get("committer") or {}).get("date") or "")),
    }


def update_status(force=False):
    with UPDATE_LOCK:
        state = read_json_file(UPDATE_STATE_FILE)
        now = int(time.time())
        checked = int(state.get("checkedAt") or 0)
        if force or not state.get("latestSha") or now - checked >= 24 * 3600:
            try:
                state.update(fetch_latest_release())
                state["checkedAt"] = now
                state.pop("checkError", None)
                write_json_file(UPDATE_STATE_FILE, state)
            except Exception as exc:
                state["checkedAt"] = now
                state["checkError"] = str(exc)
                write_json_file(UPDATE_STATE_FILE, state)
        current = current_version()
        latest = str(state.get("latestSha") or "")
        dismissed = str(state.get("dismissedSha") or "")
        result = read_json_file(UPDATE_RESULT_FILE)
        return {
            "currentSha": current,
            "latestSha": latest,
            "latestMessage": state.get("latestMessage", ""),
            "latestUrl": state.get("latestUrl", ""),
            "publishedAt": state.get("publishedAt", ""),
            "checkedAt": state.get("checkedAt", 0),
            "checkError": state.get("checkError", ""),
            "available": bool(latest and latest != current and latest != dismissed),
            "dismissed": bool(latest and latest == dismissed),
            "updating": UPDATE_MARKER_FILE.exists(),
            "lastResult": result,
        }


def dismiss_update():
    with UPDATE_LOCK:
        status = update_status()
        if status["latestSha"]:
            state = read_json_file(UPDATE_STATE_FILE)
            state["dismissedSha"] = status["latestSha"]
            write_json_file(UPDATE_STATE_FILE, state)
        return update_status()


def start_update(force=False):
    with UPDATE_LOCK:
        status = update_status(force=True)
        if status["updating"]:
            raise ValueError("更新任务正在执行，请稍候")
        sha = status["latestSha"]
        if not sha:
            raise ValueError("暂时无法获取仓库最新版本")
        if sha == status["currentSha"] and not force:
            raise ValueError("当前已经是最新版本")
        installer_url = f"{REPOSITORY_RAW}/{sha}/install.sh"
        request = Request(installer_url, headers={"User-Agent": "mxioc-vpn-manager-updater"})
        with urlopen(request, timeout=20) as response:
            installer = response.read(MAX_BODY)
        if not installer.startswith(b"#!/usr/bin/env bash"):
            raise ValueError("下载的更新程序格式不正确")
        UPDATE_INSTALLER_FILE.parent.mkdir(parents=True, exist_ok=True)
        UPDATE_INSTALLER_FILE.write_bytes(installer)
        os.chmod(UPDATE_INSTALLER_FILE, 0o700)
        marker = {"sha": sha, "startedAt": int(time.time())}
        write_json_file(UPDATE_MARKER_FILE, marker)
        runner = """#!/usr/bin/env bash
set +e
LOG=/opt/mxioc-rule-manager/update.log
if /bin/bash /opt/mxioc-rule-manager/.updates/install.sh --update-only >>\"$LOG\" 2>&1; then
  printf '{\"ok\":true,\"sha\":\"%s\"}\n' \"$MXIOC_RELEASE_SHA\" > /opt/mxioc-rule-manager/update-result.json
  rc=0
else
  rc=$?
  printf '{\"ok\":false,\"sha\":\"%s\",\"error\":\"更新失败，请查看 update.log\"}\n' \"$MXIOC_RELEASE_SHA\" > /opt/mxioc-rule-manager/update-result.json
fi
rm -f /opt/mxioc-rule-manager/update-in-progress.json /opt/mxioc-rule-manager/.updates/install.sh /opt/mxioc-rule-manager/.updates/run.sh
exit "$rc"
"""
        UPDATE_RUNNER_FILE.write_text(runner, encoding="utf-8", newline="\n")
        os.chmod(UPDATE_RUNNER_FILE, 0o700)
        unit = "mxioc-self-update-" + sha[:12]
        raw_base = f"{REPOSITORY_RAW}/{sha}"
        try:
            subprocess.Popen([
                "systemd-run", "--unit", unit, "--collect", "--property=Type=oneshot",
                f"--setenv=MXIOC_RAW_BASE={raw_base}", f"--setenv=MXIOC_RELEASE_SHA={sha}",
                "/bin/bash", str(UPDATE_RUNNER_FILE),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        except Exception:
            UPDATE_MARKER_FILE.unlink(missing_ok=True)
            UPDATE_INSTALLER_FILE.unlink(missing_ok=True)
            UPDATE_RUNNER_FILE.unlink(missing_ok=True)
            raise
        return marker


def start_uninstall(purge_data=False):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = f"/var/backups/mxioc-rule-manager-{stamp}"
    runner = Path(f"/run/mxioc-rule-manager-uninstall-{secrets.token_hex(6)}.sh")
    preserve = "" if purge_data else f"""
mkdir -p "{backup_dir}"
tar -czf "{backup_dir}/user-data.tar.gz" \\
  /etc/sing-box/subscribe /opt/mxioc-rule-manager/profiles.json \\
  /opt/mxioc-rule-manager/profiles /opt/mxioc-rule-manager/backups /opt/mxioc-rule-manager/remote \\
  /etc/mxioc-rule-manager.auth.json /etc/mxioc-rule-manager.auth 2>/dev/null || true
"""
    purge = """
rm -f /etc/sing-box/subscribe/clash-cn-route /etc/sing-box/subscribe/clash-cn-route.yml
""" if purge_data else ""
    script = f"""#!/usr/bin/env bash
set +e
sleep 2
{preserve}{purge}systemctl disable --now mxioc-rule-manager.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/mxioc-rule-manager.service
systemctl daemon-reload >/dev/null 2>&1 || true
rm -f /etc/nginx/conf.d/mxioc-rule-manager.conf
nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
rm -f /etc/mxioc-rule-manager.auth.json /etc/mxioc-rule-manager.auth
rm -f /usr/local/bin/vpn
rm -rf /opt/mxioc-rule-manager
rm -f -- "$0"
"""
    runner.write_text(script, encoding="utf-8", newline="\n")
    os.chmod(runner, 0o700)
    unit = "mxioc-self-uninstall-" + secrets.token_hex(5)
    try:
        subprocess.Popen([
            "systemd-run", "--unit", unit, "--collect", "--property=Type=oneshot",
            "/bin/bash", str(runner),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        runner.unlink(missing_ok=True)
        raise
    return {"purgeData": bool(purge_data), "backupPath": "" if purge_data else backup_dir}


def update_checker_loop():
    while True:
        try:
            update_status(force=True)
        except Exception:
            pass
        threading.Event().wait(24 * 3600)


PROFILES_CACHE = None
PROFILES_MTIME = 0


def load_profiles():
    global PROFILES_CACHE, PROFILES_MTIME
    ROOT.mkdir(parents=True, exist_ok=True)
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    if not PROFILES_FILE.exists():
        data = {"profiles": [{"id": "clash", "name": "Mxioc VPN", "protected": True,
                              "slug": random_slug(), "customSlug": False,
                              "files": [str(path) for path in FILES]}]}
        save_profiles(data)
        return data
    try:
        mtime = PROFILES_FILE.stat().st_mtime_ns
        if PROFILES_CACHE is not None and PROFILES_MTIME == mtime:
            data = PROFILES_CACHE
            loaded_from_disk = False
        else:
            data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
            loaded_from_disk = True
        if not isinstance(data.get("profiles"), list):
            raise ValueError("订阅配置索引损坏")
        migrated = False
        for record in data["profiles"]:
            if not record.get("slug") or (record.get("customSlug") and len(str(record.get("slug", ""))) < 32):
                record["slug"] = unique_slug(data)
                record["customSlug"] = False
                migrated = True
            # Earlier versions stopped destructive actions on reused IDs but
            # accidentally left their old ownership records marked active.
            for binding in (record.get("remoteNodes", []) if loaded_from_disk else ()):
                if (binding.get("status") == "active" and str(binding.get("error") or "").startswith(
                        "远端入站身份已变化，已停止自动删除")):
                    binding["status"] = "identity_changed"
                    binding.setdefault("invalidatedAt", int(time.time()))
                    migrated = True
        if migrated:
            save_profiles(data)
            return data
        PROFILES_CACHE = data
        PROFILES_MTIME = mtime
        return data
    except Exception:
        data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        return data


def save_profiles(data):
    global PROFILES_CACHE, PROFILES_MTIME
    text = json.dumps(data, ensure_ascii=False, indent=2)
    descriptor, temporary = tempfile.mkstemp(prefix=".profiles-", dir=str(PROFILES_FILE.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, PROFILES_FILE)
    finally:
        Path(temporary).unlink(missing_ok=True)
    PROFILES_CACHE = data
    PROFILES_MTIME = PROFILES_FILE.stat().st_mtime_ns



def profile_record(profile_id=None):
    profile_id = profile_id or getattr(CTX, "profile", "clash") or "clash"
    record = next((x for x in load_profiles()["profiles"] if x.get("id") == profile_id), None)
    if not record:
        raise ValueError("所选订阅配置不存在")
    return record


def random_slug(length=50):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def record_slug(record):
    return str(record.get("slug") or record.get("id") or "")


def unique_slug(data, length=50):
    existing = {record_slug(record) for record in data.get("profiles", [])}
    for _ in range(100):
        value = random_slug(length)
        if value not in existing:
            return value
    raise ValueError("暂时无法生成唯一订阅链接，请重试")


def unique_profile_id(data):
    existing = {str(record.get("id", "")) for record in data.get("profiles", [])}
    for _ in range(100):
        value = "profile_" + random_slug()
        if value not in existing:
            return value
    raise ValueError("暂时无法生成唯一配置标识，请重试")


def public_profile_record(slug):
    slug = str(slug or "")
    record = next((item for item in load_profiles()["profiles"] if record_slug(item) == slug), None)
    if not record:
        raise ValueError("订阅链接不存在")
    return record


def current_files(profile_id=None):
    record = profile_record(profile_id)
    return [Path(x) for x in record.get("files", [])]


def minimal_profile_config():
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


def empty_profile_config(template_path=None):
    """Return a fresh copy of the bundled, node-free Clash template."""
    path = Path(template_path) if template_path is not None else BUNDLED_TEMPLATE
    if not path.is_file():
        return minimal_profile_config()
    doc = yaml_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("内置 Clash 模板不是有效的 YAML 对象")
    validate_config(doc)
    return copy.deepcopy(doc)


def public_profile(record):
    slug = record_slug(record)
    return {"id": record["id"], "name": record.get("name", record["id"]),
            "protected": bool(record.get("protected")), "slug": slug,
            "customSlug": bool(record.get("customSlug", False)),
            "url": "/sub/" + quote(slug, safe=""), "traffic": traffic_info(record)}


SUBSCRIPTION_PLANS = (
    {"id": "tier-1", "name": "档位1", "price": 120, "monthlyGiB": 50},
    {"id": "tier-2", "name": "档位2", "price": 240, "monthlyGiB": 100},
    {"id": "tier-3", "name": "档位3", "price": None, "monthlyGiB": 150},
)


def subscription_plans():
    with LOCK:
        rows = load_profiles().get("subscriptionPlans", SUBSCRIPTION_PLANS)
        return [{"durationMonths": 12, "resetPeriod": "monthly", "speedMbps": 0, "multiplier": 1, **row}
                for row in copy.deepcopy(list(rows))]


def save_subscription_plan(payload):
    from bandwidth import rate_kbps, multiplier_units
    import math
    name = str(payload.get("name", "")).strip()
    if not name or len(name) > 60:
        raise ValueError("模板名称须为 1–60 个字符")
    def number(key, minimum, maximum, nullable=False):
        value = payload.get(key)
        if nullable and value in (None, ""):
            return None
        if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
            raise ValueError("模板数值无效：" + key)
        return value
    amount = number("monthlyGiB", 0.001, 1_000_000)
    price = number("price", 0, 100_000_000, True)
    months = number("durationMonths", 1, 120)
    if type(months) is not int:
        raise ValueError("有效期月数必须为整数")
    period = payload.get("resetPeriod", "monthly")
    if period not in ("monthly", "none"):
        raise ValueError("流量重置周期无效")
    speed = rate_kbps(payload.get("speedMbps")) / 1000
    if 0 < speed < 0.1:
        raise ValueError("非零限速至少为 0.1 Mbps")
    multiplier = multiplier_units(payload.get("multiplier", 1)) / 1000
    with LOCK:
        rows = subscription_plans()
        identity = payload.get("id")
        if identity and not any(p["id"] == identity for p in rows):
            raise ValueError("模板已不存在，请刷新后重试")
        if not identity and len(rows) >= 100:
            raise ValueError("最多保存 100 个套餐模板")
        result = dict(id=identity or "plan-" + secrets.token_hex(8), name=name, price=price,
                      monthlyGiB=amount, durationMonths=months, resetPeriod=period,
                      speedMbps=speed, multiplier=multiplier)
        rows = [result if p["id"] == identity else p for p in rows]
        if not identity:
            rows.append(result)
        data = load_profiles()
        data["subscriptionPlans"] = rows
        save_profiles(data)
        return result


def delete_subscription_plan(payload):
    with LOCK:
        data = load_profiles()
        rows = subscription_plans()
        if not any(p["id"] == payload.get("id") for p in rows):
            raise ValueError("模板已不存在")
        data["subscriptionPlans"] = [p for p in rows if p["id"] != payload["id"]]
        save_profiles(data)


def cleanup_traffic_bindings(payload):
    if payload.get("confirmed") is not True:
        raise ValueError("请确认只清理当前订阅的失效历史绑定，不删除远端节点")
    with ENFORCEMENT_LOCK, LOCK:
        record = profile_record()
        rows = record.get("remoteNodes", [])
        removed = [b for b in rows if b.get("status") in ("detached", "revoked", "missing", "identity_changed")]
        record["remoteNodes"] = [b for b in rows if b.get("status") not in ("detached", "revoked", "missing", "identity_changed")]
        record["enforcementError"] = "；".join(dict.fromkeys(b["error"] for b in record["remoteNodes"] if b.get("error")))[:1500]
        save_profiles(load_profiles())
        return {"removed": len(removed), "traffic": traffic_info(record)}


def binding_record_token(profile_id, binding):
    # Ignore mutable samples/status so background collection does not invalidate
    # a pending click. Scope the identity to this subscription and generation.
    identity = [profile_id] + [binding.get(key) for key in
                              ("serverId", "inboundId", "port", "identityHash", "boundAt", "name", "userEmail", "userHash")]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def public_binding_records(record):
    return [{**copy.deepcopy(binding), "recordIndex": index,
             "recordToken": binding_record_token(record.get("id", ""), binding)}
            for index, binding in enumerate(record.get("remoteNodes", []))]


def remove_traffic_binding(payload):
    """Remove one local record, including active ones, without remote effects."""
    if payload.get("confirmed") is not True:
        raise ValueError("请确认只删除本地绑定记录，远端节点及计费用量保持不变")
    index, token = payload.get("recordIndex"), payload.get("recordToken")
    if type(index) is not int or index < 0 or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("绑定记录参数无效，请刷新列表后重试")
    # A sweep holding a binding reference must finish before ownership is removed.
    with ENFORCEMENT_LOCK, LOCK:
        record = profile_record()
        rows = record.get("remoteNodes", [])
        if index >= len(rows) or not hmac.compare_digest(token, binding_record_token(record["id"], rows[index])):
            raise ValueError("绑定记录已变更，请刷新列表后重试")
        old_error, had_error = record.get("enforcementError"), "enforcementError" in record
        record["remoteNodes"] = rows[:index] + rows[index + 1:]
        record["enforcementError"] = "；".join(dict.fromkeys(b["error"] for b in record["remoteNodes"] if b.get("error")))[:1500]
        try:
            save_profiles(load_profiles())
        except Exception:
            record["remoteNodes"] = rows
            if had_error:
                record["enforcementError"] = old_error
            else:
                record.pop("enforcementError", None)
            raise
        return {"removed": 1, "traffic": traffic_info(record)}


def inherit_plan_binding(record, binding):
    stored = record.get("traffic") or {}
    if not stored.get("planId"):
        return
    speed = round((stored.get("speedMbps") or 0) * 1000)
    bandwidth = None
    if speed:
        bandwidth = remote_manager().set_bandwidth(binding["serverId"], binding["inboundId"], speed, speed)
    with LOCK:
        binding["multiplierUnits"] = stored.get("multiplierUnits", 1000)
        if bandwidth is not None:
            binding["bandwidth"] = bandwidth


def plan_month(anchor, months):
    """Calendar anniversaries in UTC, clamped without drifting after February."""
    from datetime import timezone
    date = datetime.fromtimestamp(anchor, timezone.utc)
    year, month = divmod(date.year * 12 + date.month - 1 + months, 12)
    return int(date.replace(year=year, month=month + 1,
                            day=min(date.day, calendar.monthrange(year, month + 1)[1])).timestamp())


def reset_monthly_traffic(record, now=None):
    stored = record.get("traffic") or {}
    now = int(time.time()) if now is None else now
    anchor, next_reset = stored.get("cycleAnchor"), stored.get("nextResetAt")
    if (stored.get("resetPeriod") != "monthly" or not anchor or not next_reset
            or now < next_reset or (stored.get("expire") and now >= stored["expire"])):
        return False
    month = 1
    while plan_month(anchor, month) <= now:
        month += 1
    stored.update(upload=0, download=0, rawUpload=0, rawDownload=0,
                  nextResetAt=plan_month(anchor, month), updatedAt=now)
    for binding in record.get("remoteNodes", []):
        binding.update(monthlyBaselinePending=True, uploadRemainder=0, downloadRemainder=0)
    return True


def apply_subscription_plan(payload):
    plan = next((p for p in subscription_plans() if p["id"] == payload.get("planId")), None)
    if plan is None:
        raise ValueError("请选择有效的套餐模板")
    with ENFORCEMENT_LOCK:
        record = profile_record()
        if record.get("accessRevoked"):
            raise ValueError("该订阅节点已撤销，请先续期并重新创建节点，再套用套餐")
        if plan["resetPeriod"] != "monthly" and any(b.get("monthlyPaused") for b in record.get("remoteNodes", [])):
            raise ValueError("请先增加月额度并同步恢复暂停节点，再切换一次性流量套餐")
        if plan['speedMbps'] and any(b.get('scope') == 'user' and b.get('status') == 'active' for b in record.get('remoteNodes', [])):
            raise ValueError('共用入站暂不支持按用户限速，请选择不限速套餐')
        if (record.get("traffic") or {}).get("enforce"):
            if not enforce_profile(record["id"], revoke=False):
                raise ValueError("原用量结算失败，套餐未套用，请恢复服务器连接后重试")
        # Remote operations are explicit here, never hidden in ordinary quota saves.
        for binding in record.get("remoteNodes", []):
            if binding.get("status") != "active":
                continue
            value = binding.get("bandwidth") or {}
            speed = round(plan["speedMbps"] * 1000)
            if speed or value.get("uploadKbps") or value.get("downloadKbps"):
                if speed:
                    row = next((r for r in remote_manager().inbounds(binding["serverId"])["inbounds"] if r["id"] == binding["inboundId"]), None)
                    if not row or (binding.get("identityHash") and binding["identityHash"] != remote_node_identity(row)):
                        raise ValueError("节点不存在或身份已变化，套餐限速未下发")
                    require_dedicated_inbound(row)
                result = remote_manager().set_bandwidth(binding["serverId"], binding["inboundId"], speed, speed)
                with LOCK:
                    binding["bandwidth"] = result
                    save_profiles(load_profiles())
        now = int(time.time())
        previous = record.get("traffic") or {}
        # Reapplying/changing a tier never renews the year or the monthly anchor.
        anchor = previous.get("cycleAnchor", now) if previous.get("resetPeriod") == plan["resetPeriod"] else now
        update_traffic({"enabled": True, "enforce": bool(previous.get("enforce")),
                                 "preserveUsage": True, "multiplier": plan["multiplier"],
                                 "total": round(plan["monthlyGiB"] * 1024 ** 3),
                                 "expire": previous.get("expire") if previous.get("planId") else plan_month(now, plan["durationMonths"])})
        with LOCK:
            record["traffic"].update(planId=plan["id"], planName=plan["name"], price=plan["price"],
                                     resetPeriod=plan["resetPeriod"], cycleAnchor=anchor,
                                     durationMonths=plan["durationMonths"], speedMbps=plan["speedMbps"],
                                     nextResetAt=(previous.get("nextResetAt") or plan_month(anchor, 1)) if plan["resetPeriod"] == "monthly" else None)
            for binding in record.get("remoteNodes", []):
                binding["multiplierUnits"] = round(plan["multiplier"] * 1000)
            save_profiles(load_profiles())
            ENFORCEMENT_WAKE.set()
            return traffic_info(record)


def traffic_info(record):
    with LOCK:
        return _traffic_info(record)


def _traffic_info(record):
    stored = record.get("traffic") or {}
    if not stored.get("enabled"):
        return {"configured": False, "plans": subscription_plans(), "bindings": public_binding_records(record),
                "enforcementError": record.get("enforcementError", "")}
    upload = stored.get("upload", 0)
    download = stored.get("download", 0)
    total = stored.get("total")
    expire = stored.get("expire")
    used = upload + download
    return {"configured": True, "plans": subscription_plans(),
            **{key: stored.get(key) for key in ("planId", "planName", "price", "resetPeriod", "nextResetAt", "durationMonths", "speedMbps")},
            "upload": upload, "download": download,
            "total": total, "expire": expire, "used": used,
            "multiplier": stored.get("multiplierUnits", 1000) / 1000,
            "rawUpload": stored.get("rawUpload", 0), "rawDownload": stored.get("rawDownload", 0),
            "rawUsed": stored.get("rawUpload", 0) + stored.get("rawDownload", 0),
            "remaining": max(0, total - used) if total is not None else None,
            "percent": min(100, round(used / total * 100, 2)) if total else 0,
            "exhausted": total is not None and used >= total,
            "expired": expire is not None and expire <= int(time.time()),
            "updatedAt": stored.get("updatedAt"), "enforce": bool(stored.get("enforce")),
            "bindings": public_binding_records(record),
            "enforcementError": record.get("enforcementError", ""),
            "lastCheckedAt": record.get("lastEnforcedAt"),
            "revoked": bool(record.get("accessRevoked"))}


def update_traffic(payload):
    from bandwidth import multiplier_units
    # A quota/date edit does not alter ownership or remote resources. Serialize its
    # local write with metering commits, not with slow SSH collection. Once remote
    # revocation has begun, keep the original enforcement-lock ordering for renewal.
    with LOCK:
        record = profile_record()
        previous = record.get("traffic") or {}
        units = multiplier_units(payload.get("multiplier", previous.get("multiplierUnits", 1000) / 1000))
        if (payload.get("enabled") is not False and previous.get("enforce")
                and payload.get("enforce", True) is True and not record.get("accessRevoked")
                and units == previous.get("multiplierUnits", 1000)):
            fast_payload = dict(payload)
            preserve = fast_payload.get("preserveUsage", False)
            if type(preserve) is not bool:
                raise ValueError("保留用量参数无效")
            if preserve:
                fast_payload.update(upload=previous.get("upload", 0), download=previous.get("download", 0))
            result = _update_traffic(fast_payload)
            ENFORCEMENT_WAKE.set()
            return result
    with ENFORCEMENT_LOCK:
        payload = dict(payload)
        old = profile_record().get("traffic") or {}
        units = multiplier_units(payload.get("multiplier", old.get("multiplierUnits", 1000) / 1000))
        preserve = payload.get("preserveUsage", False)
        if type(preserve) is not bool:
            raise ValueError("保留用量参数无效")
        if preserve:
            payload.update(upload=old.get("upload", 0), download=old.get("download", 0))
        validate_traffic_update(payload, profile_record())
        if units != old.get("multiplierUnits", 1000) and old.get("enforce"):
            if not enforce_profile(profile_record()["id"], revoke=False):
                raise ValueError("原倍率用量结算失败，未更改倍率；请恢复服务器连接后重试")
        if preserve:
            current = profile_record().get("traffic") or {}
            payload.update(upload=current.get("upload", 0), download=current.get("download", 0))
        if payload.get("enforce") is True and not old.get("enforce"):
            for binding in profile_record().get("remoteNodes", []):
                if binding.get("status") == "active":
                    if binding.get('scope') == 'user':
                        remote_manager().prepare_user_meter(binding['serverId'], binding['inboundId'], binding['userEmail'])
                    else:
                        remote_manager().ensure_meter(binding["serverId"], binding["inboundId"])
        result = _update_traffic(payload)
        # Normal edits must not synchronously SSH to every bound server.
        # The existing sweep handles metering/revocation; explicit sync remains available.
        if (profile_record().get("traffic") or {}).get("enforce"):
            ENFORCEMENT_WAKE.set()
        return traffic_info(profile_record())


def validate_traffic_update(payload, record):
    """Validate a complete edit before sampling or provisioning remote counters."""
    if (any(b.get("monthlyPaused") for b in record.get("remoteNodes", []))
            and (payload.get("enabled") is False or payload.get("enforce") is False)):
        raise ValueError("月额度暂停的节点尚未恢复，请先增加额度并同步恢复后再关闭限制")
    if payload.get("enabled") is False:
        if record.get("accessRevoked"):
            raise ValueError("节点已撤销，请先续期/调整额度并重新创建专属节点")
        return None
    values = {}
    for key in ("upload", "download", "total", "expire"):
        value = payload.get(key, 0 if key in ("upload", "download") else None)
        if value is None and key in ("total", "expire"):
            values[key] = None
            continue
        if type(value) is not int or not 0 <= value <= 9_007_199_254_740_991:
            raise ValueError("流量和到期时间必须是非负安全整数")
        if key in ("total", "expire") and value == 0:
            raise ValueError("总流量或到期时间须大于零，不限请留空")
        if key == "expire" and value > 253402300799:
            raise ValueError("到期时间超出有效日期范围")
        values[key] = value
    if values["upload"] + values["download"] > 9_007_199_254_740_991:
        raise ValueError("已用流量超出可支持的范围")
    enforce = payload.get("enforce", (record.get("traffic") or {}).get("enforce", False))
    if type(enforce) is not bool:
        raise ValueError("服务器强制限制参数无效")
    if enforce and not record.get("accessRevoked") and not any(x.get("status") == "active" for x in record.get("remoteNodes", [])):
        raise ValueError("请先在服务器入站中添加该订阅的独立用户，再启用强制限制")
    from bandwidth import multiplier_units
    previous = record.get("traffic") or {}
    units = multiplier_units(payload.get("multiplier", previous.get("multiplierUnits", 1000) / 1000))
    return {**{key: previous[key] for key in ("planId", "planName", "price", "resetPeriod", "cycleAnchor", "nextResetAt", "durationMonths", "speedMbps") if key in previous},
            "enabled": True, **values, "enforce": enforce, "updatedAt": int(time.time()),
            "multiplierUnits": units, "rawUpload": previous.get("rawUpload", 0),
            "rawDownload": previous.get("rawDownload", 0)}


def _update_traffic(payload):
    with LOCK:
        record = profile_record()
        legacy_units = (record.get("traffic") or {}).get("multiplierUnits", 1000)
        if payload.get("enabled") is False:
            if record.get("accessRevoked"):
                raise ValueError("节点已撤销，请先续期/调整额度并重新创建专属节点")
            record.pop("traffic", None)
        else:
            record["traffic"] = validate_traffic_update(payload, record)
            if not traffic_info(record).get("expired") and not traffic_info(record).get("exhausted"):
                record.pop("accessRevoked", None)
        if "multiplier" not in payload:
            for binding in record.get("remoteNodes", []):
                binding.setdefault("multiplierUnits", legacy_units)
        save_profiles(load_profiles())
        return traffic_info(record)


def subscription_blocked(record):
    info = traffic_info(record)
    return bool(record.get("accessRevoked") or (info.get("enforce") and
                (info.get("expired") or info.get("exhausted"))))


def remote_node_identity(row):
    if not row.get("protocol") or "settings" not in row:
        return None
    settings = row["settings"]
    if isinstance(settings, str):
        settings = json.loads(settings)
    identity = {"port": row["port"], "protocol": row["protocol"], "settings": settings}
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def metered_counters(row):
    """Panel user counters exclude unauthenticated inbound connection overhead."""
    if not isinstance(row.get('clientStats'), list):
        return {'up': row.get('up', 0), 'down': row.get('down', 0), 'source': 'inbound'}
    settings = row.get('settings') or {}
    settings = json.loads(settings) if isinstance(settings, str) else settings
    clients = [c for c in settings.get('clients', []) if c.get('enable') is not False]
    if not clients and row.get('protocol') in ('shadowsocks', 'http', 'socks'):
        return {'up': row.get('up', 0), 'down': row.get('down', 0), 'source': 'inbound'}
    if len(clients) != 1 or not clients[0].get('email'):
        raise ValueError('专属入站缺少唯一的认证用户，已暂停计费')
    stats = [s for s in row['clientStats'] if s.get('email') == clients[0]['email']]
    if len(stats) != 1 or any(type(stats[0].get(k)) is not int or stats[0][k] < 0 for k in ('up', 'down')):
        raise ValueError('认证用户流量计数缺失，已暂停计费，不能当作零或入站总流量')
    return {'up': stats[0]['up'], 'down': stats[0]['down'], 'source': 'authenticated-client'}


def require_dedicated_inbound(row):
    settings = row.get("settings") or {}
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except ValueError:
            raise ValueError("无法核对入站用户信息，请先检查远端配置")
    clients = settings.get("clients", []) if isinstance(settings, dict) else []
    if not isinstance(clients, list):
        raise ValueError("无法核对入站用户列表，请先检查远端配置")
    if len(row.get("shareLinks") or []) > 1 or (isinstance(clients, list) and len(clients) > 1):
        raise ValueError("该入站包含多个用户，仅可导入连接信息；请创建专属入站再绑定限制，避免删除整个共用入站")


def bind_remote_node(server_id, inbound_id, profile_id=None):
    """An entire dedicated inbound has exactly one subscription owner."""
    with ENFORCEMENT_LOCK:
        profile_id = profile_record(profile_id)["id"]
        inbound_id = int(inbound_id)
        with LOCK:
            matches = [(owner, b) for owner in load_profiles()["profiles"] for b in owner.get("remoteNodes", [])
                       if (b["serverId"], b["inboundId"]) == (server_id, inbound_id)]
            active = [(owner, b) for owner, b in matches if b.get("status") == "active"]
            if any(owner["id"] != profile_id for owner, _ in active):
                raise ValueError("该入站已绑定其他订阅，不能重复计量或跨用户撤销")
            if active:
                return copy.deepcopy(active[0][1])
            if matches:
                raise ValueError("该入站已撤销，请重新创建专属节点")
        manager = remote_manager()
        rows = manager.inbounds(server_id)["inbounds"]
        row = next((r for r in rows if r["id"] == inbound_id), None)
        if not row:
            raise ValueError("服务器入站不存在")
        require_dedicated_inbound(row)
        manager.ensure_meter(server_id, inbound_id)
        # First binding starts at the current counter, not historic shared usage.
        reading = metered_counters(row)
        binding = {"serverId": server_id, "inboundId": inbound_id, "name": row.get("remark", ""),
                   "port": row["port"], "status": "active", "up": reading['up'],
                   "down": reading['down'], "counterSource": reading['source'], "multiplierUnits": 1000, "boundAt": int(time.time()), "identityHash": remote_node_identity(row), "error": ""}
        inherit_plan_binding(profile_record(profile_id), binding)
        with LOCK:
            profile_record(profile_id).setdefault("remoteNodes", []).append(binding)
            save_profiles(load_profiles())
        return copy.deepcopy(binding)


def import_server_inbound(payload):
    """Import live server links; clients cannot supply replacement credentials."""
    with ENFORCEMENT_LOCK:
        record = profile_record()
        if subscription_blocked(record):
            raise ValueError("当前订阅已到期或流量用尽，请先续期或调整额度")
        server_id = str(payload.get("serverId", ""))
        inbound_id = int(payload.get("inboundId", 0))
        bind = payload.get("bind", False)
        if type(bind) is not bool:
            raise ValueError("绑定参数必须为布尔值")
        row = next((r for r in remote_manager().inbounds(server_id)["inbounds"] if r["id"] == inbound_id), None)
        if not row:
            raise ValueError("远端入站不存在，请刷新服务器节点列表")
        if any(b.get('scope') == 'user' and b.get('status') in ('active', 'provisioning')
               and (b.get('serverId'), b.get('inboundId')) == (server_id, inbound_id)
               for owner in load_profiles()['profiles'] for b in owner.get('remoteNodes', [])):
            return provision_subscription_user({'serverId': server_id, 'inboundId': inbound_id})
        links = row.get("shareLinks") or []
        if not links:
            raise ValueError("该入站没有可导入的兼容链接")
        indices = payload.get("indices", list(range(len(links))))
        if (not isinstance(indices, list) or not indices or any(type(i) is not int or i < 0 or i >= len(links) for i in indices)
                or len(indices) != len(set(indices))):
            raise ValueError("请选择有效且不重复的远端节点")
        parsed = [validate_node_config(parse_node_link(links[i])) for i in indices]
        own = None
        with LOCK:
            matches = [(owner, b) for owner in load_profiles()["profiles"] for b in owner.get("remoteNodes", [])
                       if (b["serverId"], b["inboundId"]) == (server_id, inbound_id)]
            active = [(owner, b) for owner, b in matches if b.get("status") == "active"]
            if any(owner["id"] != record["id"] for owner, _ in active):
                raise ValueError("该入站已归属其他订阅，请为当前订阅创建专属入站")
            if active:
                own = active[0][1]
                if own.get("identityHash") and own["identityHash"] != remote_node_identity(row):
                    raise ValueError("远端入站身份已变化，请核对后重新创建专属节点")
            elif matches:
                raise ValueError("该入站的订阅绑定已撤销，请创建新的专属节点")
        if bind and not own:
            if payload.get("confirmedDedicated") is not True:
                raise ValueError("请确认整个入站仅供当前订阅使用，到期或超额会删除整个入站")
            require_dedicated_inbound(row)
            own = bind_remote_node(server_id, inbound_id)
        if (record.get("traffic") or {}).get("enforce") and not own:
            raise ValueError("当前订阅已启用强制限制，必须绑定专属入站或新建节点，不能仅导入未受控链接")
        try:
            with LOCK:
                doc = read_config()
                nodes = doc.setdefault("proxies", [])
                def identity(node):
                    return json.dumps({k:v for k,v in node.items() if k != "name"}, sort_keys=True, ensure_ascii=False)
                existing = {identity(n):n["name"] for n in nodes}
                used = {n["name"] for n in nodes} | {g["name"] for g in doc.get("proxy-groups", [])} | BUILTINS
                names, added, updated = [], [], []
                for node in parsed:
                    key = identity(node)
                    if key in existing:
                        names.append(existing[key])
                        continue
                    # Recreating a dedicated inbound on the same endpoint must
                    # refresh its old named entry, not leave a dead primary node.
                    previous = next((i for i, old in enumerate(nodes) if own and len(parsed) == 1
                                     and old.get("name") == node.get("name")
                                     and all(old.get(k) == node.get(k) for k in ("server", "port", "type"))
                                     and not old.get("dialer-proxy")), None)
                    if previous is not None:
                        require_dedicated_inbound(row)
                        nodes[previous] = node
                        existing[key] = node["name"]
                        names.append(node["name"]); updated.append(node["name"])
                        continue
                    node["name"] = unique_node_name(str(node.get("name") or "服务器节点"), used)
                    used.add(node["name"])
                    nodes.append(node)
                    add_node_to_groups(doc, node["name"])
                    existing[key] = node["name"]
                    names.append(node["name"])
                    added.append(node["name"])
                if added or updated:
                    write_config(doc, "server-inbound-import")
                if own:
                    own["importedNames"] = names
                    save_profiles(load_profiles())
            return {"added": len(added), "updated": len(updated), "existing": len(names)-len(added), "names": names,
                    "bound": bool(own), "enforcementEnabled": bool((record.get("traffic") or {}).get("enforce"))}
        except Exception as exc:
            if own:
                raise ValueError(f"订阅导入失败，入站的专属绑定仍保留，请重试导入；未删除远端节点：{exc}") from exc
            raise


def binding_identity(row, binding):
    if binding.get('scope') == 'user':
        from shared_users import endpoint_identity
        return endpoint_identity(row)
    return remote_node_identity(row)


def import_owned_user_links(record, binding, links):
    """Only accept freshly read links of the UUID owned by this subscription."""
    parsed = [validate_node_config(parse_node_link(link)) for link in links]
    if len(parsed) != 1:
        raise ValueError('该用户未返回唯一兼容连接，绑定已保留，请核对后重试')
    with LOCK:
        doc = read_config()
        nodes = doc.setdefault('proxies', [])
        node = parsed[0]
        previous = next((n for n in nodes if n.get('name') in binding.get('importedNames', []) and
                         n.get('type') == node.get('type') and
                         n.get('uuid', n.get('password')) == node.get('uuid', node.get('password'))), None)
        existing = next((n for n in nodes if all(n.get(k) == node.get(k) for k in
                                              ('type', 'server', 'port', 'uuid', 'password'))), None)
        if previous or existing:
            node['name'] = (previous or existing)['name']
            index = next(i for i, n in enumerate(nodes) if n is (previous or existing))
            nodes[index] = node
            added = 0
        else:
            used = {n['name'] for n in nodes} | {g['name'] for g in doc.get('proxy-groups', [])} | BUILTINS
            node['name'] = unique_node_name(node['name'], used)
            nodes.append(node)
            add_node_to_groups(doc, node['name'])
            added = 1
        write_config(doc, 'subscription-user-import')
        binding['importedNames'] = [node['name']]
        save_profiles(load_profiles())
        return {'added': added, 'existing': 1-added, 'bound': True,
                'enforcementEnabled': bool((record.get('traffic') or {}).get('enforce'))}


def provision_subscription_user(payload):
    from shared_users import settings
    from remote_manager import positive_id
    with ENFORCEMENT_LOCK:
        record = profile_record()
        if subscription_blocked(record):
            raise ValueError('订阅已到期或流量用尽，请先续期或调整额度')
        if (record.get('traffic') or {}).get('speedMbps'):
            raise ValueError('共用入站暂不支持按用户限速，请先将套餐限速设为不限速')
        manager = remote_manager()
        server_id = str(payload.get('serverId', ''))
        inbound_id = positive_id(payload.get('inboundId')) if payload.get('inboundId') is not None else None
        if inbound_id is None:
            manager.preflight_user_support(server_id)
            if payload.get('template') == 'shadowsocks':
                raise ValueError('此 Shadowsocks 模板不是多用户协议，请选择 VLESS / VMess / Trojan')
            created = manager.create_inbound(server_id, payload)
            row = created['inbound']
            inbound_id = row['id']
            initial = settings(row).get('clients', [])
            if len(initial) != 1:
                raise ValueError('入站已创建但初始用户不唯一，请在服务器列表核对，不要重复创建')
            client = initial[0]
        else:
            row = next((r for r in manager.inbounds(server_id)['inbounds'] if r['id'] == inbound_id), None)
            if not row:
                raise ValueError('远端入站不存在')
            client = None
        try:
            return _provision_user_at_inbound(record, manager, server_id, row, client)
        except Exception as exc:
            if payload.get('inboundId') is None:
                raise ValueError(f'共用入站已创建（ID {inbound_id}），后续用户绑定或导入未完成：{exc}。请从此入站重试，不要重复创建') from None
            raise


def _enable_batch_user_enforcement(record):
    """Persist subscription protection before granting any remote UUID."""
    with LOCK:
        previous = record.get('traffic')
        if (previous or {}).get('enabled') and (previous or {}).get('enforce'):
            return
        stored = dict(previous or {})
        stored.update(enabled=True, enforce=True, updatedAt=int(time.time()))
        for key, value in {'upload': 0, 'download': 0, 'total': None, 'expire': None,
                           'rawUpload': 0, 'rawDownload': 0, 'multiplierUnits': 1000}.items():
            stored.setdefault(key, value)
        record['traffic'] = stored
        try:
            save_profiles(load_profiles())
        except Exception:
            if previous is None:
                record.pop('traffic', None)
            else:
                record['traffic'] = previous
            raise ValueError('订阅限制设置保存失败，未创建远端用户，请修复存储后重试') from None
    ENFORCEMENT_WAKE.set()


def batch_subscription_users(payload):
    """Import selected live inbounds; partial success is durable and retryable."""
    from remote_manager import positive_id
    from shared_users import PROTOCOLS
    server_id, ids = payload.get('serverId'), payload.get('inboundIds')
    if not isinstance(server_id, str) or not server_id.strip():
        raise ValueError('请选择服务器')
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 50 or
            any(type(i) is not int or i <= 0 for i in ids) or len(set(ids)) != len(ids)):
        raise ValueError('请选择 1–50 个不重复的有效入站 ID')
    ids = [positive_id(i) for i in ids]
    with ENFORCEMENT_LOCK:
        record = profile_record()
        info = traffic_info({**record, 'traffic': {**(record.get('traffic') or {}), 'enabled': True}})
        if record.get('accessRevoked') or info.get('expired') or info.get('exhausted'):
            raise ValueError('订阅已到期或流量用尽，请先续期或调整额度；批量导入不会重置用量或续期')
        if (record.get('traffic') or {}).get('speedMbps'):
            raise ValueError('共用入站暂不支持按用户限速，请先选择不限速套餐')
        previous = record.get('traffic') or {}
        if not (previous.get('enabled') and previous.get('enforce')) and any(
                b.get('scope') != 'user' and b.get('status') == 'active' for b in record.get('remoteNodes', [])):
            raise ValueError('当前订阅还有未启用计量的旧版专属绑定，请先迁移独立用户后再批量导入')
        manager = remote_manager()
        rows = {r['id']: r for r in manager.inbounds(server_id)['inbounds']}
        if any(i in rows and rows[i].get('protocol') in PROTOCOLS and rows[i].get('enable') is not False for i in ids):
            manager.preflight_user_support(server_id)
    results = []
    for identity in ids:
        with ENFORCEMENT_LOCK:
            record = profile_record()
            row = rows.get(identity)
            item = {'inboundId': identity, 'name': row.get('remark', '') if row else ''}
            try:
                info = traffic_info({**record, 'traffic': {**(record.get('traffic') or {}), 'enabled': True}})
                if record.get('accessRevoked') or info.get('expired') or info.get('exhausted'):
                    raise ValueError('订阅已到期或流量用尽，剩余节点未导入')
                if (record.get('traffic') or {}).get('speedMbps'):
                    raise ValueError('订阅已设置带宽限制，请先调整为不限速')
                if not row:
                    raise ValueError('远端入站不存在，请重新加载列表')
                if row.get('protocol') not in PROTOCOLS:
                    raise ValueError('此协议不支持独立订阅用户')
                if row.get('enable') is False:
                    raise ValueError('入站已停用，请先在服务器恢复')
                _enable_batch_user_enforcement(record)
                result = _provision_user_at_inbound(record, manager, server_id, row, None)
                item.update(ok=True, added=result['added'], existing=result['existing'])
                if result.get('runtimeVerified', True) is None:
                    item['warning'] = '此 X-Panel 内核不支持运行用户核验，请测试客户端连接'
                elif result.get('runtimeRepaired'):
                    item['warning'] = '已补同步到运行内核'
            except Exception as exc:
                item.update(ok=False, error=str(exc)[:500])
            results.append(item)
    return {'results': results, 'succeeded': sum(bool(x['ok']) for x in results),
            'failed': sum(not x['ok'] for x in results),
            'added': sum(x.get('added', 0) for x in results if x['ok']),
            'existing': sum(x.get('existing', 0) for x in results if x['ok']),
            'traffic': traffic_info(profile_record())}


def _provision_user_at_inbound(record, manager, server_id, row, client):
    """Called under ENFORCEMENT_LOCK; all ownership changes are user-scoped."""
    from shared_users import new_user, endpoint_identity, user_identity, find_user, settings, counters
    inbound_id = row['id']
    matches = [(owner, b) for owner in load_profiles()['profiles'] for b in owner.get('remoteNodes', [])
               if (b.get('serverId'), b.get('inboundId')) == (server_id, inbound_id)
               and b.get('status') in ('active', 'provisioning')]
    legacy = [(o, b) for o, b in matches if b.get('scope') != 'user']
    if legacy:
        # Upgrade only the current owner's dedicated record. Never migrate
        # another owner's permissions or change a live port policing rule.
        if len(legacy) != 1 or legacy[0][0]['id'] != record['id']:
            raise ValueError('该入站仍有其他订阅的旧版专属绑定，请由原订阅先迁移用户绑定')
        binding = legacy[0][1]
        if binding.get('monthlyPaused') or row.get('enable') is False:
            raise ValueError('旧入站处于暂停或停用状态，请先恢复后再迁移')
        if binding.get('bandwidth', {}).get('uploadKbps') or binding.get('bandwidth', {}).get('downloadKbps'):
            raise ValueError('请先清除旧版端口限速后迁移用户绑定')
        require_dedicated_inbound(row)
        if binding.get('identityHash') and binding['identityHash'] != remote_node_identity(row):
            raise ValueError('旧版入站身份已变化，不能自动迁移')
        if (record.get('traffic') or {}).get('enforce') and not enforce_profile(record['id'], revoke=False, only_binding=(server_id, inbound_id)):
            raise ValueError('迁移前旧用量结算失败，绑定未修改')
        clients = settings(row).get('clients', [])
        if len(clients) != 1 or not clients[0].get('email'):
            raise ValueError('旧入站缺少唯一用户身份，不能迁移')
        client = clients[0]
        manager.prepare_user_meter(server_id, inbound_id, client['email'])
        # Do not interpret historic user totals as newly used traffic.
        fresh = next(r for r in manager.inbounds(server_id)['inbounds'] if r['id'] == inbound_id)
        proposed = {**binding, 'scope': 'user', 'userEmail': client['email'],
                    'userHash': user_identity(client), 'identityHash': endpoint_identity(row)}
        reading = counters(fresh, proposed)
        with LOCK:
            binding.update(proposed, up=reading['up'], down=reading['down'], counterSource=reading['source'])
            save_profiles(load_profiles())
    else:
        own = [b for owner, b in matches if owner['id'] == record['id'] and b.get('scope') == 'user']
        if own:
            binding = own[0]
            current = find_user(row, binding, missing_ok=binding.get('status') == 'provisioning')
            if current is None:
                raise ValueError('上次创建未在远端找到用户，请删除该待核对绑定记录后重试；不会重复创建 UUID')
            with LOCK:
                binding.update(status='active', error='')
                save_profiles(load_profiles())
        else:
            client = client or new_user(row)
            manager.prepare_user_meter(server_id, inbound_id, client['email'])
            binding = {'scope': 'user', 'serverId': server_id, 'inboundId': inbound_id,
                       'userEmail': client['email'], 'userHash': user_identity(client),
                       'identityHash': endpoint_identity(row), 'name': row.get('remark', ''),
                       'port': row['port'], 'status': 'provisioning', 'boundAt': int(time.time()),
                       'up': 0, 'down': 0, 'counterSource': 'pending',
                       'multiplierUnits': (record.get('traffic') or {}).get('multiplierUnits', 1000), 'error': ''}
            # Durable ownership before an ambiguous remote mutation. A retry
            # recovers by email + fingerprint instead of allocating another UUID.
            with LOCK:
                record.setdefault('remoteNodes', []).append(binding)
                try:
                    save_profiles(load_profiles())
                except Exception:
                    record['remoteNodes'].remove(binding)
                    raise
            try:
                manager.subscription_user(server_id, binding, 'add', client)
            except Exception as exc:
                detail = str(exc)
                binding['error'] = detail if detail.startswith(('X-Panel ', '无法连接 X-Panel ')) else '用户创建结果待核对，请重试添加；总控已保留身份记录'
                save_profiles(load_profiles())
                raise ValueError(binding['error']) from None
            with LOCK:
                binding.update(status='active', error='')
                save_profiles(load_profiles())
    try:
        runtime_result = manager.subscription_user(server_id, binding, 'read')
        links = runtime_result['shareLinks']
        result = import_owned_user_links(record, binding, links)
    except Exception as exc:
        detail = str(exc)
        message = '独立用户绑定已保留，但订阅导入未完成；请在同一入站重试添加，不要重新创建入站'
        if detail.startswith(('X-Panel ', '无法连接 X-Panel ')):
            message += '：' + detail
        raise ValueError(message) from None
    ENFORCEMENT_WAKE.set()
    return {**result, 'binding': copy.deepcopy(binding), 'inbound': row, 'shareLinks': links,
            **{key: runtime_result[key] for key in ('runtimeVerified', 'runtimeRepaired') if key in runtime_result}}


def set_node_bandwidth(payload):
    from bandwidth import rate_kbps
    from remote_manager import positive_id
    with ENFORCEMENT_LOCK:
        server_id, inbound_id = str(payload.get("serverId", "")), positive_id(payload.get("inboundId"))
        upload, download = rate_kbps(payload.get("uploadMbps")), rate_kbps(payload.get("downloadMbps"))
        record = profile_record()
        binding = next((b for b in record.get("remoteNodes", []) if b["serverId"] == server_id
                        and b["inboundId"] == inbound_id and b.get("status") == "active"), None)
        if not binding:
            raise ValueError("请先将该专属入站绑定当前订阅，不能限制其他订阅或未绑定节点")
        if binding.get('scope') == 'user':
            raise ValueError('共用入站暂不支持按用户限速，不能对整个端口下发限速')
        if upload or download:
            if subscription_blocked(record):
                raise ValueError("订阅已到期或流量用尽，请先续期")
            row = next((r for r in remote_manager().inbounds(server_id)["inbounds"] if r["id"] == inbound_id), None)
            if not row or row["port"] != binding["port"]:
                raise ValueError("入站缺失或端口发生变化，请核对服务器节点")
            require_dedicated_inbound(row)
            if binding.get("identityHash") and binding["identityHash"] != remote_node_identity(row):
                raise ValueError("入站身份已变化，不能对可能复用的节点限速")
        result = remote_manager().set_bandwidth(server_id, inbound_id, upload, download)
        with LOCK:
            binding["bandwidth"] = result
            save_profiles(load_profiles())
        return result


def set_node_multiplier(payload):
    from bandwidth import multiplier_units
    from remote_manager import positive_id
    units = multiplier_units(payload.get("multiplier"))
    server_id, inbound_id = str(payload.get("serverId", "")), positive_id(payload.get("inboundId"))
    with ENFORCEMENT_LOCK:
        record = profile_record()
        binding = next((b for b in record.get("remoteNodes", []) if b.get("serverId") == server_id
                        and b.get("inboundId") == inbound_id and b.get("status") == "active"), None)
        if not binding:
            raise ValueError("只能为当前订阅绑定的有效节点设置倍率")
        old = binding.get("multiplierUnits", (record.get("traffic") or {}).get("multiplierUnits", 1000))
        if old != units and (record.get("traffic") or {}).get("enforce"):
            if not enforce_profile(record["id"], revoke=False, only_binding=(server_id, inbound_id)):
                raise ValueError("该节点原倍率用量结算失败，倍率未修改，请恢复服务器连接后重试")
            if binding.get("status") != "active":
                raise ValueError("节点已失效，请刷新节点列表")
        with LOCK:
            binding["multiplierUnits"] = units
            save_profiles(load_profiles())
        return {"serverId": server_id, "inboundId": inbound_id, "multiplier": units / 1000}


def sync_monthly_pause(manager, record, binding, row):
    pause = traffic_info(record).get("exhausted", False)
    if binding.get('scope') == 'user':
        from shared_users import find_user
        user = find_user(row, binding)
        if not pause and not binding.get('monthlyPaused'):
            return
        if pause and not binding.get('monthlyPaused'):
            if user.get('enable', True) is False:
                raise ValueError('用户已被手动停用，不接管自动恢复')
            with LOCK:
                binding['monthlyPaused'] = True
                save_profiles(load_profiles())
        if user.get('enable', True) != (not pause):
            manager.subscription_user(binding['serverId'], binding, 'pause' if pause else 'resume')
        if not pause:
            with LOCK:
                binding.pop('monthlyPaused', None)
                save_profiles(load_profiles())
        return

    if not pause and not binding.get("monthlyPaused"):
        return
    with LOCK:
        if pause and not binding.get("monthlyPaused"):
            if row.get("enable", True) is False:
                raise ValueError("入站已被手动停用，不接管自动恢复")
            binding["monthlyPaused"] = True
            save_profiles(load_profiles())
    if row.get("enable", True) != (not pause):
        manager.update_inbound(binding["serverId"], binding["inboundId"], {**row, "enable": not pause})
    if pause:
        manager.disconnect_port(binding["serverId"], binding["port"])
    else:
        with LOCK:
            binding.pop("monthlyPaused", None)
            save_profiles(load_profiles())


def enforce_profile(profile_id, revoke=True, only_binding=None):
    """Accumulate deltas and retry remote revocation, including after restart.

    No global config lock is held while SSH/network operations are in progress.
    The enforcement lock serializes quota edits, creation and sweeps.
    """
    with ENFORCEMENT_LOCK:
        with LOCK:
            record = profile_record(profile_id)
            if reset_monthly_traffic(record):
                save_profiles(load_profiles())
            bindings = [b for b in record.get("remoteNodes", []) if b.get("status") in ("active", "provisioning")]
            if only_binding is not None:
                bindings = [b for b in bindings if (b["serverId"], b["inboundId"]) == only_binding]
            enabled = bool((record.get("traffic") or {}).get("enforce"))
        if not enabled:
            return True
        manager, snapshots, errors = remote_manager(), {}, []
        mismatches = set()
        # Expiry must still revoke nodes when usage retrieval fails.
        for binding in bindings:
            server_id = binding["serverId"]
            if server_id not in snapshots:
                try:
                    snapshots[server_id] = {r["id"]: r for r in manager.inbounds(server_id)["inbounds"]}
                except Exception as exc:
                    snapshots[server_id] = None
                    errors.append(str(exc)[:300])
            rows = snapshots[server_id]
            if rows is None:
                continue
            row = rows.get(binding["inboundId"])
            if row is not None and binding.get('scope') == 'user':
                from shared_users import find_user, check_email_namespace
                try:
                    check_email_namespace(rows.values(), binding['userEmail'])
                    user = find_user(row, binding, missing_ok=True)
                    if user is None:
                        with LOCK:
                            binding.update(status='missing', error='远端订阅用户已不存在')
                        continue
                    binding.update(status='active', error='')
                except ValueError as exc:
                    with LOCK:
                        binding.update(status='identity_changed', invalidatedAt=int(time.time()), error=str(exc))
                    errors.append(str(exc))
                    mismatches.add((server_id, binding['inboundId']))
                    continue

            if (row is not None and (not binding.get("identityHash") or binding["identityHash"] == binding_identity(row, binding))
                    and (record.get("traffic") or {}).get("resetPeriod") == "monthly"
                    and not traffic_info(record).get("expired")):
                try:
                    sync_monthly_pause(manager, record, binding, row)
                except Exception as exc:
                    with LOCK:
                        binding["error"] = str(exc)[:300]
                    errors.append(str(exc)[:300])
                    continue
            cleanup_error = ""
            if row is None and binding.get("bandwidth") and (binding["bandwidth"].get("uploadKbps") or binding["bandwidth"].get("downloadKbps")):
                try:
                    manager.set_bandwidth(server_id, binding["inboundId"], 0, 0)
                    binding["bandwidth"] = {"uploadKbps": 0, "downloadKbps": 0}
                except Exception as exc:
                    cleanup_error = "入站已不存在，限速清理待重试：" + str(exc)[:200]
                    errors.append(cleanup_error)
            with LOCK:
                current = binding
                if row is None:
                    if cleanup_error:
                        current.update(status="active", error=cleanup_error)
                    else:
                        current.update(status="missing", error="远端入站已不存在")
                        if binding.get("bandwidth"):
                            current["bandwidth"] = copy.deepcopy(binding["bandwidth"])
                    continue
                if current.get("identityHash") and current["identityHash"] != binding_identity(row, binding):
                    message = "远端入站身份已变化，已停止自动删除，避免误删复用 ID 的节点"
                    current.update(status="identity_changed", invalidatedAt=int(time.time()), error=message)
                    errors.append(message)
                    mismatches.add((server_id, binding["inboundId"]))
                    continue
                stored = profile_record(profile_id)["traffic"]
                try:
                    if binding.get('scope') == 'user':
                        from shared_users import counters
                        reading = counters(row, binding)
                    else:
                        reading = metered_counters(row)
                except ValueError as exc:
                    current['error'] = str(exc); errors.append(str(exc)); continue
                old_source = current.get('counterSource', 'inbound')
                current['error'] = ''
                current['lastSampleAt'] = int(time.time())
                current['lastRawDelta'] = 0
                if current.pop("monthlyBaselinePending", False):
                    if any(type(reading[k]) is not int or reading[k] < 0 for k in ("up", "down")):
                        current["monthlyBaselinePending"] = True
                        current["error"] = "服务器流量计数无效，跨月基线等待重试"
                        errors.append(current["error"])
                        continue
                    current.update(up=reading['up'], down=reading['down'], counterSource=reading['source'])
                    continue
                if old_source not in (reading['source'], 'pending'):
                    # Counter namespaces have different baselines. Switching must
                    # never interpret a lower user total as a reset and bill it again.
                    current.update(up=reading['up'], down=reading['down'], counterSource=reading['source'])
                    continue
                current['counterSource'] = reading['source']
                for remote_key, local_key in (("up", "upload"), ("down", "download")):
                    value = reading[remote_key]
                    if type(value) is not int or value < 0:
                        raise ValueError("服务器流量计数无效")
                    previous = current.get(remote_key, 0)
                    delta = value - previous if value >= previous else value
                    current['lastRawDelta'] += delta
                    units = current.get("multiplierUnits", stored.get("multiplierUnits", 1000))
                    billed, remainder = divmod(delta * units + current.get(local_key + "Remainder", 0), 1000)
                    stored[local_key] = stored.get(local_key, 0) + min(billed, max(0, 9_007_199_254_740_991 - stored.get("upload", 0) - stored.get("download", 0)))
                    raw_key = "rawUpload" if local_key == "upload" else "rawDownload"
                    stored[raw_key] = stored.get(raw_key, 0) + min(delta, max(0, 9_007_199_254_740_991 - stored.get("rawUpload", 0) - stored.get("rawDownload", 0)))
                    current[local_key + "Remainder"] = remainder
                    current[remote_key] = value
                stored["updatedAt"] = int(time.time())
        with LOCK:
            record = profile_record(profile_id)
            if not revoke:
                record["enforcementError"] = "；".join(dict.fromkeys(errors))[:1500]
                save_profiles(load_profiles())
                return not errors
            blocked = subscription_blocked(record)
            monthly_pause = ((record.get("traffic") or {}).get("resetPeriod") == "monthly"
                             and not traffic_info(record).get("expired"))
            if blocked and not monthly_pause:
                # Durable before remote deletion, so a crash cannot re-enable access.
                record["accessRevoked"] = True
            record["lastEnforcedAt"] = int(time.time())
            save_profiles(load_profiles())
        if blocked:
            for binding in bindings:
                if (binding["serverId"], binding["inboundId"]) in mismatches:
                    continue
                try:
                    rows = snapshots.get(binding["serverId"])
                    if monthly_pause:
                        row = rows.get(binding["inboundId"]) if rows is not None else None
                        if row is None:
                            raise ValueError("月额度用尽，服务器离线或入站缺失，暂停待重试")
                        sync_monthly_pause(manager, record, binding, row)
                        continue
                    if binding.get('scope') == 'user':
                        manager.subscription_user(binding['serverId'], binding, 'remove')
                        with LOCK:
                            binding.update(status='revoked', revokedAt=int(time.time()), error='')
                        continue
                    if rows is None or binding["inboundId"] in rows:
                        manager.delete_inbound(binding["serverId"], binding["inboundId"])
                    if binding.get("bandwidth") and (binding["bandwidth"].get("uploadKbps") or binding["bandwidth"].get("downloadKbps")):
                        manager.set_bandwidth(binding["serverId"], binding["inboundId"], 0, 0)
                    manager.disconnect_port(binding["serverId"], binding["port"])
                    with LOCK:
                        current = binding
                        current.update(status="revoked", revokedAt=int(time.time()), error="")
                        if binding.get("bandwidth"):
                            current["bandwidth"] = {"uploadKbps": 0, "downloadKbps": 0}
                except Exception as exc:
                    message = str(exc)[:300]
                    errors.append(message)
                    with LOCK:
                        current = binding
                        current.update(status="active", error=message)
        with LOCK:
            profile_record(profile_id)["enforcementError"] = "；".join(dict.fromkeys(errors))[:1500]
            save_profiles(load_profiles())


def enforcement_loop():
    while True:
        with ENFORCEMENT_LOCK, LOCK:
            changed = any([reset_monthly_traffic(r) for r in load_profiles()["profiles"]])
            if changed:
                save_profiles(load_profiles())
            identities = [r["id"] for r in load_profiles()["profiles"] if (r.get("traffic") or {}).get("enforce")]
        for identity in identities:
            try:
                enforce_profile(identity)
            except Exception as exc:
                with LOCK:
                    try:
                        profile_record(identity)["enforcementError"] = str(exc)[:500]
                        save_profiles(load_profiles())
                    except ValueError:
                        pass
        ENFORCEMENT_WAKE.wait(ENFORCEMENT_INTERVAL)
        ENFORCEMENT_WAKE.clear()


def create_owned_remote(payload, relay=False):
    with ENFORCEMENT_LOCK:
        profile_id = profile_record()["id"]
        if subscription_blocked(profile_record(profile_id)):
            raise ValueError("订阅已到期或流量用尽，请先续期或调整额度")
        server_id = str(payload.get("serverId", ""))
        manager = remote_manager()
        result = (manager.create_relay if relay else manager.create_inbound)(server_id, payload)
        try:
            # Creation always records ownership. Metering is explicitly enabled on binding.
            row = result["inbound"]
            with LOCK:
                binding = {
                    "serverId": server_id, "inboundId": row["id"], "name": row.get("remark", ""),
                    "port": row["port"], "status": "active", "up": 0, "down": 0, "counterSource": "pending",
                    "multiplierUnits": 1000, "boundAt": int(time.time()), "identityHash": remote_node_identity(row), "error": ""}
                profile_record(profile_id).setdefault("remoteNodes", []).append(binding)
                save_profiles(load_profiles())
            if (profile_record(profile_id).get("traffic") or {}).get("enforce"):
                manager.ensure_meter(server_id, row["id"])
            inherit_plan_binding(profile_record(profile_id), binding)
            with LOCK:
                save_profiles(load_profiles())
        except Exception as exc:
            try:
                manager.delete_inbound(server_id, result["inbound"]["id"])
                with LOCK:
                    record = profile_record(profile_id)
                    record["remoteNodes"] = [b for b in record.get("remoteNodes", []) if
                                             (b["serverId"], b["inboundId"]) != (server_id, result["inbound"]["id"])]
                    save_profiles(load_profiles())
            except Exception as cleanup:
                raise ValueError("节点创建后绑定失败，撤回也失败，请手动核对远端：" + str(cleanup)) from exc
            raise
        return result


def server_chain(payload):
    with ENFORCEMENT_LOCK:
        doc = read_config()
        nodes = doc.setdefault("proxies", [])
        entry = next((n for n in nodes if n.get("name") == payload.get("entry")), None)
        exit_node = next((n for n in nodes if n.get("name") == payload.get("exit")), None)
        if not entry or not exit_node or entry is exit_node or entry.get("dialer-proxy") or exit_node.get("dialer-proxy"):
            raise ValueError("请选择两个不同的普通节点")
        name = str(payload.get("name", "")).strip()
        if not name or any(n.get("name") == name for n in nodes):
            raise ValueError("链式代理名称为空或已存在")
        # Match by an explicit managed address/domain; never trust client-supplied serverId.
        servers = remote_manager().list()
        def match(node):
            found = [s for s in servers if str(node.get("server", "")).strip('[]').lower() in
                     {str(s["host"]).lower(), str(s.get("domain") or "").lower(),
                      str(s.get("nodeAddress") or "").strip("[]").lower()}]
            if len(found) != 1:
                raise ValueError("节点未唯一匹配总控中的服务器，请选择 Mihomo 客户端专用链式代理模式")
            return found[0]
        ingress, egress = match(entry), match(exit_node)
        if ingress["id"] == egress["id"]:
            raise ValueError("入口和出口请选择不同服务器，避免本机循环")
        for node, host in ((entry, ingress), (exit_node, egress)):
            rows = remote_manager().inbounds(host["id"])["inbounds"]
            def matches(row):
                if row.get("port") != node.get("port"):
                    return False
                for link in row.get("shareLinks", []):
                    candidate = parse_node_link(link)
                    if candidate.get("type") == node.get("type") and all(candidate.get(k) == node.get(k) for k in ("uuid", "password")):
                        return True
                return False
            if not any(matches(row) for row in rows):
                raise ValueError("节点未匹配服务器中的真实入站，请选择 Mihomo 客户端专用链式代理模式")
        result = create_owned_remote({**payload, "serverId": ingress["id"], "remark": name,
                                      "landingLink": node_to_uri(exit_node)}, relay=True)
        try:
            if not result.get("shareLinks"):
                raise ValueError("未返回可导出的中转节点链接")
            node = parse_node_link(result["shareLinks"][0])
            node["name"] = name
            nodes.append(node)
            set_node_groups(doc, name, payload.get("groups"))
            write_config(doc, "server-chain")
            with LOCK:
                profile_record().setdefault("serverChains", []).append({"name": name, "entry": entry["name"],
                    "exit": exit_node["name"], "serverId": ingress["id"], "inboundId": result["inbound"]["id"]})
                save_profiles(load_profiles())
        except Exception:
            remote_manager().delete_inbound(ingress["id"], result["inbound"]["id"])
            with LOCK:
                profile_record()["remoteNodes"] = [b for b in profile_record().get("remoteNodes", [])
                    if (b["serverId"], b["inboundId"]) != (ingress["id"], result["inbound"]["id"])]
                save_profiles(load_profiles())
            raise
        return result


def remove_server_chain(name):
    protect_failover_component(name)
    with ENFORCEMENT_LOCK:
        record = profile_record()
        chain = next((c for c in record.get("serverChains", []) if c["name"] == name), None)
        if not chain:
            raise ValueError("服务器链路不存在")
        binding = next((b for b in record.get("remoteNodes", []) if
                        (b["serverId"], b["inboundId"]) == (chain["serverId"], chain["inboundId"])), None)
        if binding and binding.get("status") == "active":
            remote_manager().delete_inbound(chain["serverId"], chain["inboundId"])
        doc = read_config()
        if any(n.get("name") == name for n in doc.get("proxies", [])):
            delete_nodes_from_doc(doc, [name])
            write_config(doc, "delete-server-chain")
        with LOCK:
            if binding:
                binding.update(status="revoked", revokedAt=int(time.time()))
            record["serverChains"] = [c for c in record.get("serverChains", []) if c["name"] != name]
            save_profiles(load_profiles())


def protect_failover_component(name):
    if getattr(CTX, "failover_cleanup", False):
        return
    for item in profile_record().get("failovers", []):
        if name == item["name"] or name in item.get("paths", []):
            raise ValueError("此项由多入口主备管理，请在链式代理页删除整组后重新配置")


def failover_group(name, paths, interval):
    return {"name": name, "type": "fallback", "proxies": list(paths),
            "url": "https://www.gstatic.com/generate_204", "interval": interval,
            "timeout": 5000, "lazy": False, "max-failed-times": 1}


def create_failover(payload):
    # Provisioning and quota revocation must not race each other.
    with ENFORCEMENT_LOCK:
        name = str(payload.get("name", "")).strip()
        entries = payload.get("entries")
        exit_name = str(payload.get("exit", ""))
        if not isinstance(entries, list) or not 2 <= len(entries) <= 8 or len(set(entries)) != len(entries):
            raise ValueError("请选择 2–8 个不重复的入口，按主用到备用排序")
        interval = int(payload.get("interval", 30))
        port = int(payload.get("port", 24443))
        if not 10 <= interval <= 600 or not 1 <= port <= 65535:
            raise ValueError("检测间隔须为 10–600 秒，端口须为 1–65535")
        doc = read_config()
        known = {n["name"] for n in doc.get("proxies", []) + doc.get("proxy-groups", [])}
        paths = [f"{name} / {i + 1}" for i in range(len(entries))]
        if not name or any(n in known or n in BUILTINS for n in [name] + paths):
            raise ValueError("主备组或自动生成的路径名称已存在或为空")
        if any(f["name"] == name for f in profile_record().get("failovers", [])):
            raise ValueError("同名主备任务已存在，请先删除")
        nodes = {n["name"]: n for n in doc.get("proxies", [])}
        if exit_name in entries or any(n not in nodes or nodes[n].get("dialer-proxy") for n in entries + [exit_name]):
            raise ValueError("入口与出口必须是不同的普通节点")
        servers = remote_manager().list()
        hosts = []
        for node_name in entries + [exit_name]:
            node = nodes[node_name]
            matches = [s for s in servers if str(node["server"]).strip("[]").lower() in
                       {str(s["host"]).lower(), str(s.get("domain") or "").lower(),
                      str(s.get("nodeAddress") or "").strip("[]").lower()}]
            if len(matches) != 1:
                raise ValueError("节点未唯一匹配总控中的服务器，请选择 Mihomo 客户端专用链式代理模式")
            hosts.append(matches[0]["id"])
        if len(set(hosts)) != len(hosts):
            raise ValueError("每个入口及固定出口必须使用不同服务器")
        item = {"name": name, "entries": list(entries), "exit": exit_name, "paths": [],
                "interval": interval, "status": "creating"}
        with LOCK:
            profile_record().setdefault("failovers", []).append(item)
            save_profiles(load_profiles())
        try:
            for entry, path in zip(entries, paths):
                server_chain({**payload, "name": path, "entry": entry, "exit": exit_name,
                              "groups": [], "port": port})
                with LOCK:
                    item["paths"].append(path)
                    save_profiles(load_profiles())
            with LOCK:
                doc = read_config()
                # Include the group in business selectors, never individual relay paths.
                set_node_groups(doc, name, payload.get("groups"))
                doc.setdefault("proxy-groups", []).append(failover_group(name, paths, interval))
                write_config(doc, "multi-entry-failover")
                item["status"] = "active"
                save_profiles(load_profiles())
            return copy.deepcopy(item)
        except Exception as exc:
            item.update(status="cleanup-required", error=str(exc))
            save_profiles(load_profiles())
            try:
                remove_failover(name)
            except Exception as cleanup_error:
                raise ValueError(f"创建失败：{exc}；部分服务器待清理，请删除该主备组重试：{cleanup_error}") from exc
            raise


def remove_failover(name):
    with ENFORCEMENT_LOCK:
        item = next((f for f in profile_record().get("failovers", []) if f["name"] == name), None)
        if not item:
            raise ValueError("主备组不存在")
        CTX.failover_cleanup = True
        try:
            with LOCK:
                doc = read_config()
                doc["proxy-groups"] = [g for g in doc.get("proxy-groups", []) if g["name"] != name]
                replace_references(doc, name, "REJECT")
                write_config(doc, "detach-failover")
            # Keep failed paths recorded, so remote cleanup can be retried.
            for path in list(item["paths"]):
                remove_server_chain(path)
                with LOCK:
                    item["paths"].remove(path)
                    save_profiles(load_profiles())
            with LOCK:
                doc = read_config()
                doc["proxy-groups"] = [g for g in doc.get("proxy-groups", []) if g["name"] != name]
                replace_references(doc, name, "REJECT")
                write_config(doc, "remove-failover")
                profile_record()["failovers"].remove(item)
                save_profiles(load_profiles())
        except Exception as exc:
            item.update(status="cleanup-required", error=str(exc))
            save_profiles(load_profiles())
            raise
        finally:
            CTX.failover_cleanup = False


def save_remote_server(payload):
    with ENFORCEMENT_LOCK:
        identity = str(payload.get("id", ""))
        if identity:
            bindings = [b for r in load_profiles()["profiles"] for b in r.get("remoteNodes", [])
                        if b["serverId"] == identity and b.get("status") == "active"]
            if bindings:
                old = remote_manager().record(identity)
                for key in ("host", "sshPort", "installType", "connectionMode", "domain", "panelAddress"):
                    if str(payload.get(key, old.get(key, "3x-ui" if key == "installType" else ""))) != str(old.get(key, "3x-ui" if key == "installType" else "")):
                        raise ValueError("服务器仍有订阅专属入站，不能变更地址、内核类型或接入模式")
                if payload.get("coreConfig") or payload.get("clearCoreConfig"):
                    raise ValueError("已有订阅专属入站，请通过节点管理修改，避免覆盖计量关联")
        return remote_manager().save(payload)


def detach_remote_server(server_id, confirmed=False):
    """Forget this controller's ownership only; never contact or delete remote nodes."""
    with ENFORCEMENT_LOCK, LOCK:
        manager = remote_manager()
        record = manager.record(server_id)
        data = load_profiles()
        bindings = [b for p in data["profiles"] for b in p.get("remoteNodes", [])
                    if b.get("serverId") == server_id and b.get("status") == "active"]
        if (bindings or record.get("bandwidths")) and confirmed is not True:
            raise ValueError("请确认解除本总控的订阅绑定；远端节点与限速规则将保留，不再由本总控计量或到期撤销")
        original = copy.deepcopy(data)
        for binding in bindings:
            binding.update(status="detached", detachedAt=int(time.time()))
        save_profiles(data)
        try:
            manager.remove(server_id, detach=True)
        except Exception:
            save_profiles(original)
            raise
        return {"detachedBindings": len(bindings), "remotePreserved": True}


def subscription_userinfo(record):
    info = traffic_info(record)
    if not info["configured"]:
        return None
    fields = [f"upload={info['upload']}", f"download={info['download']}",
              f"total={info['total'] if info['total'] is not None else 0}"]
    if info["expire"] is not None:
        fields.append(f"expire={info['expire']}")
    return "; ".join(fields)


def list_profiles():
    return [public_profile(x) for x in load_profiles()["profiles"]]


def valid_profile_slug(value):
    value = str(value or "").strip().strip("/")
    if not re.fullmatch(r"[A-Za-z0-9._~!*'()@:-]{32,80}", value):
        raise ValueError("自定义链接标识必须使用 32–80 位 URL 安全字符")
    if value.lower() in {".", "..", "admin", "api", "sub", "convert", "clash"}:
        raise ValueError("该链接标识已被系统保留")
    return value


def profile_locked(function):
    from functools import wraps
    @wraps(function)
    def wrapped(*args, **kwargs):
        with LOCK:
            return function(*args, **kwargs)
    return wrapped


@profile_locked
def create_profile(payload):
    data = load_profiles()
    profile_id = unique_profile_id(data)
    name = str(payload.get("name", "")).strip()
    if not name:
        raise ValueError("订阅名称不能为空")
    custom_slug = bool(payload.get("customSlug"))
    slug = valid_profile_slug(payload.get("slug")) if custom_slug else unique_slug(data)
    if any(record_slug(item) == slug for item in data["profiles"]):
        raise ValueError("订阅链接标识已经存在")
    template_id = str(payload.get("templateId", "blank"))
    if template_id == "blank":
        doc = empty_profile_config()
    else:
        if any(b.get("status") == "active" for b in profile_record(template_id).get("remoteNodes", [])):
            raise ValueError("该模板拥有服务器专属节点，不能复制凭证供其他订阅共用；请创建空白订阅并创建新专属节点")
        doc = copy.deepcopy(get_cached_config(current_files(template_id)[0])[0])
    path = PROFILES_DIR / f"{profile_id}.yaml"
    validate_config(doc)
    text = yaml_dump(doc)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)
    stat = path.stat()
    with CONFIG_CACHE_LOCK:
        cache_config_entry(str(path.resolve()), {
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
            "doc": copy.deepcopy(doc),
            "text": text,
        })
    data["profiles"].append({"id": profile_id, "name": name, "protected": False,
                             "slug": slug, "customSlug": custom_slug, "files": [str(path)]})
    save_profiles(data)
    return public_profile(data["profiles"][-1])


@profile_locked
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
    custom_slug = bool(payload.get("customSlug"))
    if custom_slug:
        new_slug = valid_profile_slug(payload.get("slug"))
    elif record.get("customSlug", "slug" not in record) or not record.get("slug"):
        new_slug = unique_slug(data)
    else:
        new_slug = record_slug(record)
    if any(item["id"] != old_id and record_slug(item) == new_slug for item in data["profiles"]):
        raise ValueError("新的链接标识已经存在")
    record["slug"] = new_slug
    record["customSlug"] = custom_slug
    save_profiles(data)
    return public_profile(record)


@profile_locked
def delete_profile(profile_id):
    if any(b.get("status") == "active" for b in profile_record(profile_id).get("remoteNodes", [])):
        raise ValueError("订阅仍拥有服务器节点，请先删除专属入站，不能丢弃限制关联")
    data = load_profiles()
    record = next((x for x in data["profiles"] if x["id"] == profile_id), None)
    if not record:
        raise ValueError("订阅配置不存在")
    if record.get("protected"):
        raise ValueError("主订阅不能删除")
    for path in current_files(profile_id):
        with CONFIG_CACHE_LOCK:
            CONFIG_CACHE.pop(str(path.resolve()), None)
        path.unlink(missing_ok=True)
    data["profiles"] = [x for x in data["profiles"] if x["id"] != profile_id]
    save_profiles(data)



def password_hash(password, salt=None, iterations=PBKDF2_ITERATIONS):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
    return salt, digest.hex()


def load_auth():
    if AUTH.exists():
        return json.loads(AUTH.read_text(encoding="utf-8"))
    if LEGACY_AUTH.exists():
        username, password = LEGACY_AUTH.read_text(encoding="utf-8").strip().split(":", 1)
        salt, digest = password_hash(password)
        save_auth(username, salt, digest, PBKDF2_ITERATIONS)
        return {"username": username, "salt": salt, "hash": digest,
                "iterations": PBKDF2_ITERATIONS}
    password = secrets.token_urlsafe(15)
    salt, digest = password_hash(password)
    save_auth("admin", salt, digest, PBKDF2_ITERATIONS)
    (ROOT / "initial-password.txt").write_text("admin:" + password + "\n", encoding="utf-8")
    os.chmod(ROOT / "initial-password.txt", 0o600)
    return {"username": "admin", "salt": salt, "hash": digest,
            "iterations": PBKDF2_ITERATIONS}


def save_auth(username, salt, digest, iterations=PBKDF2_ITERATIONS):
    AUTH.write_text(json.dumps({"username": username, "salt": salt, "hash": digest,
                                "iterations": int(iterations)}), encoding="utf-8")
    os.chmod(AUTH, 0o600)


def update_auth(current_username, current_password, new_username="", new_password=""):
    if not authenticate(current_username, current_password):
        raise ValueError("当前用户名或密码错误")
    auth = load_auth()
    username = str(new_username or auth["username"]).strip()
    if not 3 <= len(username) <= 64 or ":" in username or any(char.isspace() for char in username):
        raise ValueError("新用户名需要为 3–64 位，且不能包含空格或冒号")
    password = str(new_password or "")
    if password and len(password) < 12:
        raise ValueError("新密码至少需要 12 位")
    if password:
        salt, digest = password_hash(password)
    else:
        salt, digest = auth["salt"], auth["hash"]
    save_auth(username, salt, digest)
    clear_sessions()
    return username


def authenticate(username, password):
    auth = load_auth()
    iterations = int(auth.get("iterations") or LEGACY_PBKDF2_ITERATIONS)
    _, digest = password_hash(password, auth["salt"], iterations)
    username_ok = hmac.compare_digest(str(username), str(auth["username"]))
    password_ok = hmac.compare_digest(digest, str(auth["hash"]))
    valid = username_ok and password_ok
    if valid and iterations < PBKDF2_ITERATIONS:
        salt, digest = password_hash(password)
        save_auth(auth["username"], salt, digest, PBKDF2_ITERATIONS)
    return valid


def login_retry_after(client, now=None):
    now = float(now if now is not None else time.time())
    cutoff = now - LOGIN_WINDOW
    with LOGIN_LOCK:
        attempts = [stamp for stamp in LOGIN_FAILURES.get(str(client), []) if stamp > cutoff]
        if attempts:
            LOGIN_FAILURES[str(client)] = attempts
        else:
            LOGIN_FAILURES.pop(str(client), None)
        if len(attempts) < LOGIN_MAX_FAILURES:
            return 0
        return max(1, int(attempts[0] + LOGIN_WINDOW - now) + 1)


def record_login_failure(client, now=None):
    now = float(now if now is not None else time.time())
    with LOGIN_LOCK:
        LOGIN_FAILURES.setdefault(str(client), []).append(now)
        if len(LOGIN_FAILURES) > 4096:
            oldest = min(LOGIN_FAILURES, key=lambda key: LOGIN_FAILURES[key][-1])
            LOGIN_FAILURES.pop(oldest, None)
    return login_retry_after(client, now)


def clear_login_failures(client):
    with LOGIN_LOCK:
        LOGIN_FAILURES.pop(str(client), None)


def session_digest(token):
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def load_sessions_locked():
    global SESSIONS
    if SESSIONS is not None:
        return SESSIONS
    try:
        data = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
        SESSIONS = {str(key): float(value) for key, value in data.items()}
    except (FileNotFoundError, ValueError, TypeError, json.JSONDecodeError):
        SESSIONS = {}
    return SESSIONS


def save_sessions_locked():
    ROOT.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".sessions.", dir=ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(SESSIONS or {}, handle, ensure_ascii=False, separators=(",", ":"))
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, SESSIONS_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def request_session_token(header="", cookie_header=""):
    if str(header).startswith("Bearer "):
        return str(header)[7:].strip()
    try:
        cookie = SimpleCookie()
        cookie.load(str(cookie_header or ""))
        morsel = cookie.get("mxioc_session")
        return morsel.value if morsel else ""
    except Exception:
        return ""


def create_session():
    token = secrets.token_urlsafe(32)
    now = time.time()
    with SESSION_LOCK:
        sessions = load_sessions_locked()
        sessions[session_digest(token)] = now + SESSION_TTL
        for key, expires in list(sessions.items()):
            if expires <= now:
                sessions.pop(key, None)
        if len(sessions) > MAX_SESSIONS:
            for key, _ in sorted(sessions.items(), key=lambda item: item[1])[:-MAX_SESSIONS]:
                sessions.pop(key, None)
        save_sessions_locked()
    return token


def session_valid(header="", cookie_header=""):
    token = request_session_token(header, cookie_header)
    if not token:
        return False
    now = time.time()
    digest = session_digest(token)
    with SESSION_LOCK:
        sessions = load_sessions_locked()
        expires = sessions.get(digest, 0)
        if expires <= now:
            if digest in sessions:
                sessions.pop(digest, None)
                save_sessions_locked()
            return False
    return True


def revoke_session(header="", cookie_header=""):
    token = request_session_token(header, cookie_header)
    if not token:
        return
    with SESSION_LOCK:
        sessions = load_sessions_locked()
        if sessions.pop(session_digest(token), None) is not None:
            save_sessions_locked()


def clear_sessions():
    global SESSIONS
    with SESSION_LOCK:
        SESSIONS = {}
        save_sessions_locked()


def session_cookie(token, secure=True):
    flags = "HttpOnly; SameSite=Strict"
    if secure:
        flags += "; Secure"
    return f"mxioc_session={token}; Path=/admin; Max-Age={SESSION_TTL}; {flags}"


def expired_session_cookie(secure=True):
    flags = "HttpOnly; SameSite=Strict"
    if secure:
        flags += "; Secure"
    return f"mxioc_session=; Path=/admin; Max-Age=0; {flags}"


CONFIG_CACHE = {}
CONFIG_CACHE_LOCK = threading.Lock()
FRONT_CACHE = None
FRONT_MTIME = 0


def get_front_html():
    global FRONT_CACHE, FRONT_MTIME
    try:
        mtime = FRONT.stat().st_mtime_ns
        if FRONT_CACHE is not None and FRONT_MTIME == mtime:
            return FRONT_CACHE
        FRONT_CACHE = FRONT.read_bytes()
        FRONT_MTIME = mtime
        return FRONT_CACHE
    except Exception:
        return FRONT.read_bytes()


def cache_config_entry(key, entry):
    """Called with CONFIG_CACHE_LOCK held; bound parsed configs and derived views."""
    CONFIG_CACHE.pop(key, None)
    CONFIG_CACHE[key] = entry
    while len(CONFIG_CACHE) > 8:
        CONFIG_CACHE.pop(next(iter(CONFIG_CACHE)))


def get_cached_config(path):
    p = Path(path)
    stat = p.stat()
    key = str(p.resolve())
    with CONFIG_CACHE_LOCK:
        entry = CONFIG_CACHE.get(key)
        if entry and entry["mtime_ns"] == stat.st_mtime_ns and entry["size"] == stat.st_size:
            CONFIG_CACHE.pop(key)
            CONFIG_CACHE[key] = entry
            return entry["doc"], entry["text"]

    text = p.read_text(encoding="utf-8")
    doc = yaml_load(text)
    if not isinstance(doc, dict):
        raise ValueError("配置文件不是有效的 YAML 对象")
    # A subscription read must preserve imported transport/handshake choices.
    # Controller-created nodes carry explicit compatibility options in their links.

    with CONFIG_CACHE_LOCK:
        cache_config_entry(key, {
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
            "doc": doc,
            "text": text,
        })
    return doc, text


def read_config(copy_doc=True):
    files = current_files()
    doc, _ = get_cached_config(files[0])
    return copy.deepcopy(doc) if copy_doc else doc


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
    if set(node_names) & (set(group_names) | BUILTINS):
        raise ValueError("节点、策略组和内置策略不能使用相同名称")
    known = set(node_names) | set(group_names) | BUILTINS
    for group in groups:
        for ref in group.get("proxies", []) or []:
            if ref not in known:
                raise ValueError(f"策略组 {group['name']} 引用了不存在的项目：{ref}")
    for node in proxies:
        if not node.get("type") or not node.get("server") or not (node.get("port") or (node.get("type") == "mieru" and node.get("port-range"))):
            raise ValueError(f"节点 {node.get('name', '?')} 缺少 type、server 或 port")
        if node.get("type") == "mieru":
            from mieru_adapter import validate as validate_mieru
            validate_mieru(node)
            if node.get("transport") not in ("TCP", "UDP"):
                raise ValueError("Mieru YAML 必须明确设置 transport: TCP 或 UDP")
        if node.get("type") == "snell":
            validate_node_config(node)
        dialer = node.get("dialer-proxy")
        if dialer and dialer not in known:
            raise ValueError(f"链式节点 {node.get('name', '?')} 引用了不存在的前置中转：{dialer}")


def write_config(doc, reason="manual", unchanged_base=None):
    validate_config(doc)
    fragments = None
    if unchanged_base is not None:
        # Only the node editor uses immutable, copy-on-write documents.
        key = str(current_files()[0].resolve())
        with CONFIG_CACHE_LOCK:
            previous = CONFIG_CACHE.get(key, {}).get("fragments", {})
        fragments = {}
        for key, value in doc.items():
            if key in previous and key in unchanged_base and value is unchanged_base[key]:
                fragments[key] = previous[key]
            else:
                fragments[key] = yaml_dump({key: value})
        text = "".join(fragments.values())
    else:
        text = yaml_dump(doc)
    profile_id = profile_record()["id"]
    files = current_files()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with LOCK:
        backup_path = BACKUP_DIR / f"{profile_id}.{stamp}.{reason}.yaml"
        shutil.copy2(files[0], backup_path)
        os.chmod(backup_path, 0o600)
        for path in files:
            fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(text)
                    handle.flush()
                os.chmod(temp_name, 0o600)
                os.replace(temp_name, path)
                stat = path.stat()
                key = str(path.resolve())
                with CONFIG_CACHE_LOCK:
                    cache_config_entry(key, {
                        "mtime_ns": stat.st_mtime_ns,
                        "size": stat.st_size,
                        "doc": doc if unchanged_base is not None else copy.deepcopy(doc),
                        "text": text,
                        "fragments": fragments or {},
                    })
            finally:
                if os.path.exists(temp_name):
                    try:
                        os.unlink(temp_name)
                    except OSError:
                        pass
    prune_backups_async()


def prune_backups():
    try:
        items = sorted(BACKUP_DIR.glob("*.yaml"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in items[100:]:
            old.unlink(missing_ok=True)
    except Exception:
        pass


def prune_backups_async():
    threading.Thread(target=prune_backups, daemon=True).start()



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


def normalize_reality_options(node):
    options = node.get("reality-opts")
    if not isinstance(options, dict):
        return node
    options = dict(options)
    if "support-x25519mlkem768" in options and type(options["support-x25519mlkem768"]) is not bool:
        raise ValueError("Reality 混合密钥握手选项必须为布尔值")
    if "short-id" not in options:
        return node
    raw = options.get("short-id")
    short_id = "" if raw is None else str(raw).strip()
    if not short_id or short_id.lower() in ("null", "none"):
        options.pop("short-id", None)
    elif (len(short_id) > 16 or len(short_id) % 2
          or not re.fullmatch(r"[0-9a-fA-F]+", short_id)):
        raise ValueError("Reality short ID 必须是 2–16 位、长度为偶数的十六进制字符")
    else:
        options["short-id"] = short_id
    node["reality-opts"] = options
    return node


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


def normalize_ipv6_authority(link):
    """Accept share links that omit the RFC-required brackets around an IPv6 host."""
    prefix, separator, remainder = str(link).partition("://")
    if not separator:
        return link
    boundaries = [position for position in (remainder.find("?"), remainder.find("#")) if position >= 0]
    end = min(boundaries) if boundaries else len(remainder)
    authority, suffix = remainder[:end], remainder[end:]
    userinfo, at, endpoint = authority.rpartition("@")
    if not at:
        endpoint = authority
    if endpoint.startswith("[") or endpoint.count(":") < 2:
        return link
    host, colon, port = endpoint.rpartition(":")
    if not colon or not port.isdigit():
        return link
    normalized = f"[{host}]:{port}"
    authority = f"{userinfo}@{normalized}" if at else normalized
    return f"{prefix}://{authority}{suffix}"


SHARE_LINK_PATTERN = re.compile(
    r"(?i)(?:snell|mierus|mieru|vless|tuic|hysteria2|hy2|trojan|ss|vmess|socks5|socks|https?)://[^\s<>]+"
)


def extract_node_links(value):
    """Extract node share links from a multiline paste without splitting query data."""
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        raise ValueError("请至少粘贴一条节点链接")
    links = []
    for line in text.splitlines():
        if re.match(r'^\s*[^=\r\n]+\s*=\s*snell\s*,', line, re.I):
            links.append(line.strip())
            continue
        for link in SHARE_LINK_PATTERN.findall(line.strip().strip("`")):
            # A link copied from Markdown may retain the closing parenthesis or punctuation.
            links.append(link.rstrip("，；;。]}>)]\"'"))
    if not links:
        raise ValueError("没有找到可识别的节点分享链接")
    return links


def parse_node_link(link):
    link = str(link or "").strip().strip('"\'').replace("\\://", "://").replace("\\@", "@").replace("\\.", ".")
    if re.match(r'^[^=\r\n]+\s*=\s*snell\s*,', link, re.I):
        from snell_adapter import parse_policy
        return validate_node_config(parse_policy(link))
    if not link or "://" not in link:
        raise ValueError("请输入完整的节点链接")
    scheme = link.split("://", 1)[0].lower()
    if scheme == "snell":
        from snell_adapter import parse
        return validate_node_config(parse(link))
    if scheme in ("mierus", "mieru"):
        from mieru_adapter import parse_nodes
        nodes = [validate_node_config(node) for node in parse_nodes(link)]
        if len(nodes) != 1:
            raise ValueError("此 Mieru 链接含多组端口，请使用批量导入以保留全部节点")
        return nodes[0]
    if scheme == "hy2":
        link = "hysteria2://" + link.split("://", 1)[1]
        scheme = "hysteria2"
    link = normalize_ipv6_authority(link)
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
    if scheme in ("http", "https"):
        parsed = urlsplit(link)
        query = parse_qs(parsed.query, keep_blank_values=True)
        config = {
            "name": unquote(parsed.fragment) or f"导入的 {scheme.upper()} 节点",
            "type": "http",
            "server": parsed.hostname or "",
            "port": parsed.port or (443 if scheme == "https" else 80),
            "udp": False,
        }
        if scheme == "https":
            config["tls"] = True
        if parsed.username is not None:
            config["username"] = unquote(parsed.username)
        if parsed.password is not None:
            config["password"] = unquote(parsed.password)
        if bool_value(first(query, "skip-cert-verify", "allowInsecure", "insecure")):
            config["skip-cert-verify"] = True
        for query_name, config_name in (("sni", "sni"), ("fingerprint", "fingerprint"),
                                        ("name-cert-verify", "name-cert-verify")):
            value = first(query, query_name)
            if value:
                config[config_name] = value
        headers = {}
        host = first(query, "host")
        user_agent = first(query, "user-agent", "ua")
        if host:
            headers["Host"] = host
        if user_agent:
            headers["User-Agent"] = user_agent
        if headers:
            config["headers"] = headers
        if not config["server"] or not config["port"]:
            raise ValueError("HTTP/HTTPS 链接中缺少服务器地址或端口")
        return config
    if scheme in ("socks5", "socks"):
        parsed = urlsplit(link)
        query = parse_qs(parsed.query, keep_blank_values=True)
        config = {
            "name": unquote(parsed.fragment) or "导入的 SOCKS5 节点",
            "type": "socks5",
            "server": parsed.hostname or "",
            "port": parsed.port or 1080,
            "udp": bool_value(first(query, "udp"), True),
        }
        if parsed.username is not None:
            config["username"] = unquote(parsed.username)
        if parsed.password is not None:
            config["password"] = unquote(parsed.password)
        if bool_value(first(query, "tls")):
            config["tls"] = True
        if bool_value(first(query, "skip-cert-verify", "allowInsecure", "insecure")):
            config["skip-cert-verify"] = True
        servername = first(query, "sni", "servername")
        if servername:
            config["servername"] = servername
        if not config["server"] or not config["port"]:
            raise ValueError("SOCKS5 链接中缺少服务器地址或端口")
        return config
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
            config["reality-opts"] = {"public-key": public_key}
            if short_id:
                config["reality-opts"]["short-id"] = short_id
            hybrid = first(query, "support-x25519mlkem768")
            if hybrid:
                if hybrid.lower() not in ("true", "false", "1", "0"):
                    raise ValueError("Reality 混合密钥握手选项须为 true 或 false")
                config["reality-opts"]["support-x25519mlkem768"] = hybrid.lower() in ("true", "1")
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
    return normalize_reality_options(config)


def parse_node_links(link):
    if str(link).lower().startswith(('mierus://', 'mieru://')):
        from mieru_adapter import parse_nodes
        return [validate_node_config(node) for node in parse_nodes(link)]
    return [parse_node_link(link)]


def eligible_group_names(doc):
    return [group.get("name") for group in doc.get("proxy-groups", [])
            if isinstance(group, dict) and group.get("name")
            and group.get("name") not in NON_NODE_GROUPS
            and group.get("name") not in {f["name"] for f in profile_record().get("failovers", [])}]


def set_node_groups(doc, name, selected_groups, old_name=None):
    allowed = set(eligible_group_names(doc))
    selected = allowed if selected_groups is None else set(selected_groups) & allowed
    for group in doc.get("proxy-groups", []):
        refs = list(group.get("proxies", []) or [])
        if old_name:
            refs = [ref for ref in refs if ref != old_name]
        refs = [ref for ref in refs if ref != name]
        if group.get("name") in selected:
            refs.append(name)
        group["proxies"] = refs


@profile_locked
def mutate_node_membership(payload):
    name = payload.get("name")
    selected = payload.get("groups")
    if not isinstance(selected, list) or not all(isinstance(item, str) for item in selected):
        raise ValueError("请选择策略组")
    doc = read_config()
    if not any(node.get("name") == name for node in doc.get("proxies", [])):
        raise ValueError("节点不存在，请刷新")
    allowed = set(eligible_group_names(doc))
    if set(selected) - allowed:
        raise ValueError("策略组已变化，请刷新后重试")
    for group in doc.get("proxy-groups", []):
        if group.get("name") not in allowed:
            continue
        refs = list(group.get("proxies", []) or [])
        if group["name"] in selected:
            if name not in refs:
                refs.append(name)
        else:
            refs = [ref for ref in refs if ref != name]
        group["proxies"] = refs
    write_config(doc, "node-groups")


def mutate_chain(method, payload):
    protect_failover_component(str(payload.get("oldName", "")))
    mode = payload.get("mode", "mihomo")
    if mode == "server":
        if method != "POST":
            raise ValueError("服务器链路请新建，避免原有用户连接被修改")
        return server_chain(payload)
    if mode != "mihomo":
        raise ValueError("链式代理模式无效")
    doc = read_config()
    nodes = doc.setdefault("proxies", [])
    name = str(payload.get("name", "")).strip()
    old_name = str(payload.get("oldName", "")).strip()
    entry_name = str(payload.get("entry", "")).strip()
    exit_name = str(payload.get("exit", "")).strip()
    selected_groups = payload.get("groups")
    if not name or not entry_name or not exit_name:
        raise ValueError("链式代理名称、入口节点和出口节点不能为空")
    if entry_name == exit_name:
        raise ValueError("入口节点和出口节点不能相同")
    entry = next((node for node in nodes if node.get("name") == entry_name), None)
    exit_node = next((node for node in nodes if node.get("name") == exit_name), None)
    if not entry or not exit_node:
        raise ValueError("入口节点或出口节点不存在")
    if entry.get("dialer-proxy") or exit_node.get("dialer-proxy"):
        raise ValueError("入口和出口请选择普通节点，避免产生循环或多级链路")
    if method == "POST":
        if any(node.get("name") == name for node in nodes):
            raise ValueError("节点名称已经存在")
        chain = copy.deepcopy(exit_node)
        chain["name"] = name
        chain["dialer-proxy"] = entry_name
        nodes.append(chain)
        set_node_groups(doc, name, selected_groups)
    else:
        index = next((i for i, node in enumerate(nodes) if node.get("name") == old_name), -1)
        if index < 0 or not nodes[index].get("dialer-proxy"):
            raise ValueError("原链式代理不存在")
        if name != old_name and any(node.get("name") == name for node in nodes):
            raise ValueError("新的节点名称已经存在")
        chain = copy.deepcopy(exit_node)
        chain["name"] = name
        chain["dialer-proxy"] = entry_name
        nodes[index] = chain
        if name != old_name:
            replace_references(doc, old_name, name)
        set_node_groups(doc, name, selected_groups, old_name if name != old_name else None)
    write_config(doc, "chain")


def fetch_subscription(url):
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("订阅地址必须是完整的 HTTP 或 HTTPS 链接")
    request = Request(parsed.geturl(), headers={"User-Agent": "Mxioc-Subscription-Importer/1.0"})
    with urlopen(request, timeout=20) as response:
        content = response.read(MAX_SUBSCRIPTION + 1)
    if len(content) > MAX_SUBSCRIPTION:
        raise ValueError("订阅内容超过 8 MB，已停止读取")
    return content.decode("utf-8-sig", errors="strict").strip()


def parse_subscription_text(text):
    nodes, skipped = [], []
    try:
        doc = yaml_load(text)
    except Exception:
        doc = None
    if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
        for item in doc["proxies"]:
            if not isinstance(item, dict):
                skipped.append("无效的 Clash 节点")
                continue
            node = copy.deepcopy(item)
            node_type = str(node.get("type", "")).lower()
            if node_type == "hy2":
                node_type = "hysteria2"
                node["type"] = node_type
            elif node_type == "https":
                node_type = "http"
                node["type"] = node_type
                node["tls"] = True
            if node_type not in SUPPORTED_NODE_TYPES:
                skipped.append(str(node.get("name") or node_type or "未知协议"))
                continue
            node.pop("dialer-proxy", None)
            if not node.get("name") or not node.get("server") or not (node.get("port") or (node_type == "mieru" and node.get("port-range"))):
                skipped.append(str(node.get("name") or "信息不完整的节点"))
                continue
            try:
                nodes.append(validate_node_config(node) if node_type in ("mieru", "snell") else normalize_reality_options(node))
            except ValueError as error:
                skipped.append(f"{node.get('name', '未知节点')}（{error}）")
        return nodes, skipped
    candidates = text.splitlines()
    try:
        decoded = b64decode_text(text)
        if "://" in decoded or re.search(r'=\s*snell\s*,', decoded, re.I):
            candidates = decoded.splitlines()
    except Exception:
        if "\n" in text:
            candidates = text.splitlines()
    for line in candidates:
        line = line.strip()
        if not line:
            continue
        if line.lower() == '[proxy]':
            continue
        try:
            nodes.extend(parse_node_links(line))
        except Exception:
            if line.lower().startswith('snell://') or re.match(r'^[^=\r\n]+\s*=\s*snell\s*,', line, re.I):
                skipped.append("无法识别的 Snell 节点（参数无效）")
            else:
                skipped.append(line.split("#", 1)[-1][:80] if "#" in line else "无法识别的节点")
    if not nodes:
        raise ValueError("订阅中没有找到可导入的 Clash 或分享链接节点")
    return nodes, skipped


def subscription_preview(payload):
    nodes, skipped = parse_subscription_text(fetch_subscription(payload.get("url")))
    protocols = {}
    for node in nodes:
        protocol = "https" if node.get("type") == "http" and node.get("tls") else node["type"]
        protocols[protocol] = protocols.get(protocol, 0) + 1
    return {"total": len(nodes), "protocols": protocols, "skipped": skipped[:30],
            "groups": eligible_group_names(read_config())}


def unique_node_name(name, used):
    base = str(name or "导入节点").strip()
    if base not in used:
        return base
    number = 2
    while f"{base}-{number:02d}" in used:
        number += 1
    return f"{base}-{number:02d}"


def import_subscription(payload):
    imported, skipped = parse_subscription_text(fetch_subscription(payload.get("url")))
    doc = read_config()
    nodes = doc.setdefault("proxies", [])
    used = {node.get("name") for node in nodes}
    conflict = str(payload.get("conflict", "rename"))
    selected_groups = payload.get("groups")
    added, replaced = [], []
    for source in imported:
        node = copy.deepcopy(source)
        original_name = node["name"]
        existing = next((i for i, item in enumerate(nodes) if item.get("name") == original_name), -1)
        if existing >= 0 and conflict == "skip":
            skipped.append(original_name + "（名称重复）")
            continue
        if existing >= 0 and conflict == "replace":
            nodes[existing] = node
            set_node_groups(doc, original_name, selected_groups)
            replaced.append(original_name)
            continue
        node["name"] = unique_node_name(original_name, used)
        used.add(node["name"])
        nodes.append(node)
        set_node_groups(doc, node["name"], selected_groups)
        added.append(node["name"])
    if not added and not replaced:
        raise ValueError("没有节点被导入，请检查重复处理方式或订阅内容")
    write_config(doc, "subscription-import")
    return {"added": len(added), "replaced": len(replaced), "skipped": len(skipped),
            "names": (added + replaced)[:30]}


def add_node_to_groups(doc, name):
    for group in doc.get("proxy-groups", []):
        if (group.get("type") == "select"
                and group.get("name") not in NON_NODE_GROUPS
                and name not in (group.get("proxies", []) or [])):
            group.setdefault("proxies", []).append(name)


def import_node_links(payload):
    links = extract_node_links(payload.get("links") or payload.get("link", ""))
    doc = read_config()
    nodes = doc.setdefault("proxies", [])
    used = {str(node.get("name", "")) for node in nodes}
    added, renamed, failed = [], [], []
    add_to_groups = bool(payload.get("addToGroups", True))
    for number, link in enumerate(links, start=1):
        try:
            for node in parse_node_links(link):
                original_name = str(node.get("name") or "导入节点")
                node["name"] = unique_node_name(original_name, used)
                used.add(node["name"])
                if node["name"] != original_name:
                    renamed.append({"from": original_name, "to": node["name"]})
                nodes.append(node)
                if add_to_groups:
                    add_node_to_groups(doc, node["name"])
                added.append(node["name"])
        except Exception as exc:
            failed.append({"line": number, "reason": str(exc)})
    if added:
        write_config(doc, "node-link-batch-import")
    return {"total": len(links), "added": len(added), "failed": failed,
            "renamed": renamed, "names": added[:50]}


def endpoint(node):
    server = str(node.get("server", ""))
    if ":" in server and not server.startswith("["):
        server = "[" + server + "]"
    return f"{server}:{node.get('port', '')}"


def add_transport_query(node, query):
    network = str(node.get("network") or "tcp")
    query["type"] = network
    if network == "grpc":
        query["serviceName"] = (node.get("grpc-opts") or {}).get("grpc-service-name", "grpc")
    elif network == "ws":
        options = node.get("ws-opts") or {}
        query["path"] = options.get("path", "/")
        headers = options.get("headers") or {}
        if headers.get("Host") or headers.get("host"):
            query["host"] = headers.get("Host") or headers.get("host")


def node_to_uri(node):
    node_type = str(node.get("type", "")).lower()
    if node_type == "snell":
        from snell_adapter import to_uri
        return to_uri(validate_node_config(node))
    if node_type == "mieru":
        from mieru_adapter import to_uri
        return to_uri(node)
    name = quote(str(node.get("name", "节点")), safe="")
    address = endpoint(node)
    query = {}
    if node_type == "http":
        scheme = "https" if node.get("tls") else "http"
        if node.get("skip-cert-verify"):
            query["skip-cert-verify"] = "true"
        for config_name, query_name in (("sni", "sni"), ("fingerprint", "fingerprint"),
                                        ("name-cert-verify", "name-cert-verify")):
            if node.get(config_name):
                query[query_name] = node[config_name]
        headers = node.get("headers") or {}
        if headers.get("Host") or headers.get("host"):
            query["host"] = headers.get("Host") or headers.get("host")
        if headers.get("User-Agent") or headers.get("user-agent"):
            query["user-agent"] = headers.get("User-Agent") or headers.get("user-agent")
        username = node.get("username")
        password = node.get("password")
        auth = ""
        if username is not None or password is not None:
            auth = quote(str(username or ""), safe="")
            if password is not None:
                auth += ":" + quote(str(password), safe="")
            auth += "@"
        suffix = "?" + urlencode(query) if query else ""
        return f"{scheme}://{auth}{address}{suffix}#{name}"
    if node_type == "socks5":
        if node.get("udp") is False:
            query["udp"] = "false"
        if node.get("tls"):
            query["tls"] = "true"
        if node.get("skip-cert-verify"):
            query["skip-cert-verify"] = "true"
        if node.get("servername"):
            query["sni"] = node["servername"]
        username = node.get("username")
        password = node.get("password")
        auth = ""
        if username is not None or password is not None:
            auth = quote(str(username or ""), safe="")
            if password is not None:
                auth += ":" + quote(str(password), safe="")
            auth += "@"
        suffix = "?" + urlencode(query) if query else ""
        return f"socks5://{auth}{address}{suffix}#{name}"
    if node_type == "vless":
        query["encryption"] = node.get("encryption", "none")
        if node.get("flow"):
            query["flow"] = node["flow"]
        reality = node.get("reality-opts") or {}
        query["security"] = "reality" if reality else ("tls" if node.get("tls") else "none")
        if node.get("servername"):
            query["sni"] = node["servername"]
        if node.get("client-fingerprint"):
            query["fp"] = node["client-fingerprint"]
        if reality:
            query["pbk"] = reality.get("public-key", "")
            query["sid"] = reality.get("short-id", "")
            if "support-x25519mlkem768" in reality:
                flag = reality["support-x25519mlkem768"]
                if type(flag) is not bool:
                    raise ValueError("Reality 混合密钥握手选项必须为布尔值")
                query["support-x25519mlkem768"] = "true" if flag else "false"
        add_transport_query(node, query)
        return f"vless://{quote(str(node.get('uuid', '')), safe='')}@{address}?{urlencode(query)}#{name}"
    if node_type == "tuic":
        query = {"congestion_control": node.get("congestion-controller", "bbr"),
                 "udp_relay_mode": node.get("udp-relay-mode", "native"), "security": "tls"}
        if node.get("sni"): query["sni"] = node["sni"]
        if node.get("alpn"): query["alpn"] = ",".join(node["alpn"] if isinstance(node["alpn"], list) else [str(node["alpn"])])
        if node.get("skip-cert-verify"): query["allow_insecure"] = "1"
        if node.get("fingerprint"): query["pinned_certchain_sha256"] = node["fingerprint"].replace(":", "")
        auth = quote(str(node.get("uuid", "")), safe="") + ":" + quote(str(node.get("password", "")), safe="")
        return f"tuic://{auth}@{address}?{urlencode(query)}#{name}"
    if node_type == "hysteria2":
        if node.get("sni"): query["sni"] = node["sni"]
        if node.get("alpn"): query["alpn"] = ",".join(node["alpn"] if isinstance(node["alpn"], list) else [str(node["alpn"])])
        if node.get("skip-cert-verify"): query["insecure"] = "1"
        if node.get("obfs"): query["obfs"] = node["obfs"]
        if node.get("obfs-password"): query["obfs-password"] = node["obfs-password"]
        for source, target in (("up", "upmbps"), ("down", "downmbps")):
            if node.get(source): query[target] = re.sub(r"\s*[Mm][Bb][Pp][Ss]\s*$", "", str(node[source]))
        if node.get("fingerprint"): query["pinSHA256"] = node["fingerprint"].replace(":", "")
        suffix = "?" + urlencode(query) if query else ""
        return f"hysteria2://{quote(str(node.get('password') or node.get('auth') or ''), safe='')}@{address}{suffix}#{name}"
    if node_type == "trojan":
        if node.get("sni") or node.get("servername"): query["sni"] = node.get("sni") or node.get("servername")
        query["security"] = "tls"
        if node.get("client-fingerprint"): query["fp"] = node["client-fingerprint"]
        if node.get("skip-cert-verify"): query["allowInsecure"] = "1"
        add_transport_query(node, query)
        return f"trojan://{quote(str(node.get('password', '')), safe='')}@{address}?{urlencode(query)}#{name}"
    if node_type == "ss":
        auth = base64.urlsafe_b64encode(f"{node.get('cipher', '')}:{node.get('password', '')}".encode()).decode().rstrip("=")
        return f"ss://{auth}@{address}#{name}"
    if node_type == "vmess":
        transport = node.get("network") or "tcp"
        ws = node.get("ws-opts") or {}
        grpc = node.get("grpc-opts") or {}
        data = {"v": "2", "ps": node.get("name", "节点"), "add": node.get("server", ""),
                "port": str(node.get("port", "")), "id": node.get("uuid", ""),
                "aid": str(node.get("alterId", node.get("alter-id", 0))), "scy": node.get("cipher", "auto"),
                "net": transport, "type": "none", "host": (ws.get("headers") or {}).get("Host", ""),
                "path": grpc.get("grpc-service-name", "grpc") if transport == "grpc" else ws.get("path", ""),
                "tls": "tls" if node.get("tls") else "", "sni": node.get("servername", "")}
        encoded = base64.b64encode(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()).decode().rstrip("=")
        return "vmess://" + encoded
    raise ValueError("不支持转换该协议")


def exported_node_link(name):
    """Return one node as a standard client share link for the active profile."""
    name = str(name or "").strip()
    if not name:
        raise ValueError("节点名称不能为空")
    doc = read_config(copy_doc=False)
    node = next((item for item in doc.get("proxies", []) or []
                 if str(item.get("name", "")) == name), None)
    if not node:
        raise ValueError("节点不存在")
    if node.get("dialer-proxy"):
        raise ValueError("链式代理无法导出为单节点链接")
    return {
        "name": node.get("name", ""),
        "type": node.get("type", ""),
        "uri": node_to_uri(node),
    }


def client_configuration_export(profile_id, format_id):
    from client_adapter import managed_failovers, shadowrocket_config, shadowrocket_name, usage_label, xray_failover
    record = profile_record(profile_id)
    doc, _ = get_cached_config(current_files(profile_id)[0])
    groups, skipped = managed_failovers(doc, record)
    kind = CONVERSION_FORMATS[format_id]["kind"]
    label = usage_label(traffic_info(record))
    if kind == "xray-ha":
        configs = []
        for item, nodes in groups:
            try:
                configs.append(xray_failover(item["name"], nodes, item["interval"], label))
            except (ValueError, KeyError, TypeError) as exc:
                skipped.append({"name": item["name"], "type": "fallback", "reason": str(exc)})
        if not configs:
            raise ValueError("没有可导出的 Xray 主备组，请先创建有效的服务器多入口主备组并检查路径兼容性" + ("：" + "；".join(f"{x['name']}：{x['reason']}" for x in skipped) if skipped else ""))
        return json.dumps(configs, ensure_ascii=False, indent=2).encode(), skipped, len(configs)
    compatible = []
    for item, nodes in groups:
        try:
            for node in nodes:
                if node.get("type") not in SHADOWROCKET_LINK_TYPES:
                    raise ValueError("该客户端不支持 Mieru，请使用 Mihomo 完整订阅")
                node_to_uri(node)
            compatible.append((item, nodes))
        except (ValueError, KeyError, TypeError) as exc:
            skipped.append({"name": item["name"], "type": "fallback", "reason": str(exc)})
    groups = compatible
    if kind == "shadowrocket-config":
        return shadowrocket_config(groups, label, scope=record_slug(record)), skipped, len(groups)
    links, seen = [], set()
    for _, nodes in groups:
        for node in nodes:
            if node["name"] not in seen:
                seen.add(node["name"])
                node["name"] = shadowrocket_name(node["name"], scope=record_slug(record))
                links.append(node_to_uri(node))
    if not links:
        raise ValueError("请先创建有效的服务器多入口主备组，再导入小火箭主备节点订阅")
    return base64.b64encode("\n".join(links).encode()), skipped, len(links)


def conversion_report(profile_id=None):
    record = profile_record(profile_id)
    doc, _ = get_cached_config(current_files(profile_id)[0])
    nodes = doc.get("proxies", []) or []
    result = []
    for format_id, info in CONVERSION_FORMATS.items():
        if info.get("kind"):
            try:
                _, skipped, count = client_configuration_export(profile_id, format_id)
                error = ""
            except ValueError as exc:
                skipped, count, error = [], 0, str(exc)
            result.append({"id": format_id, "name": info["name"], "note": info["note"],
                           "supported": count, "unit": "主备组" if info["kind"] != "shadowrocket-nodes" else "节点",
                           "available": bool(count), "error": error, "skipped": skipped,
                           "url": f"/convert/{quote(record_slug(record), safe='')}/{format_id}"})
            continue
        supported, skipped = [], []
        for node in nodes:
            reason = ""
            if node.get("dialer-proxy"):
                reason = "链式代理无法用单节点分享链接表达"
            elif str(node.get("type", "")).lower() not in info["types"]:
                reason = "本导出格式未适配 Snell，请使用完整 Mihomo 订阅" if node.get("type") == "snell" else "客户端不支持该协议"
            if reason:
                skipped.append({"name": node.get("name", "未知节点"), "type": node.get("type", ""), "reason": reason})
            else:
                try:
                    node_to_uri(node)
                    supported.append(node.get("name", ""))
                except Exception as error:
                    skipped.append({"name": node.get("name", "未知节点"), "type": node.get("type", ""), "reason": str(error)})
        result.append({"id": format_id, "name": info["name"], "note": info["note"],
                       "supported": len(supported), "unit": "节点", "available": bool(supported), "skipped": skipped,
                       "url": f"/convert/{quote(record_slug(record), safe='')}/{format_id}"})
    return result


def converted_subscription(profile_id, format_id):
    if format_id not in CONVERSION_FORMATS:
        raise ValueError("不支持该转换格式")
    if CONVERSION_FORMATS[format_id].get("kind"):
        body, skipped, _ = client_configuration_export(profile_id, format_id)
        return body, [item["name"] for item in skipped]
    doc, _ = get_cached_config(current_files(profile_id)[0])
    info = CONVERSION_FORMATS[format_id]
    links, skipped = [], []
    from client_adapter import usage_nodes
    for node in doc.get("proxies", []) or []:
        if node.get("dialer-proxy") or str(node.get("type", "")).lower() not in info["types"]:
            skipped.append(str(node.get("name", "未知节点")))
            continue
        try:
            links.append(node_to_uri(node))
        except Exception:
            skipped.append(str(node.get("name", "未知节点")))
    if not links:
        raise ValueError("没有可转换的兼容节点")
    links = [node_to_uri(node) for node in usage_nodes(traffic_info(profile_record(profile_id)))] + links
    raw = "\n".join(links).encode("utf-8")
    return base64.b64encode(raw), skipped


def subscription_qr_svg(url):
    url = str(url or "").strip()
    if not url or len(url) > 4096:
        raise ValueError("订阅链接为空或过长")
    code = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
                         box_size=8, border=3)
    code.add_data(url)
    code.make(fit=True)
    image = code.make_image(image_factory=SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    svg = output.getvalue()
    position = svg.find(b">", svg.find(b"<svg"))
    if position >= 0:
        svg = svg[:position + 1] + b'<rect width="100%" height="100%" fill="#fff"/>' + svg[position + 1:]
    return svg


def snapshot_view():
    record = profile_record()
    files = [Path(x) for x in record.get("files", [])]
    doc, _ = get_cached_config(files[0])
    key = str(files[0].resolve())
    with CONFIG_CACHE_LOCK:
        entry = CONFIG_CACHE.get(key)
        # write_config replaces the complete entry, invalidating all derived views.
        if entry and entry.get("doc") is doc and entry.get("view") is not None:
            return entry["view"]
        proxies = []
        for index, node in enumerate(doc.get("proxies", [])):
            proxies.append({"index": index, "name": node.get("name", ""), "type": node.get("type", ""),
                            "server": node.get("server", ""), "port": node.get("port-range") or node.get("port", ""), "config": node})
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
        base = {"nodes": proxies, "groups": groups, "rules": rules, "dnsPolicies": dns_policies,
                "updated": datetime.fromtimestamp(files[0].stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")}
        view = {"data": base, "prefix": json.dumps(base, ensure_ascii=False).encode("utf-8")[:-1],
                "profileWire": None, "compressed": None}
        if entry and entry.get("doc") is doc:
            entry["view"] = view
        return view


def snapshot():
    return {**snapshot_view()["data"], "profile": public_profile(profile_record())}


def snapshot_json(compressed=False):
    view = snapshot_view()
    profile = json.dumps(public_profile(profile_record()), ensure_ascii=False).encode("utf-8")
    if compressed:
        with CONFIG_CACHE_LOCK:
            if view["profileWire"] == profile and view["compressed"] is not None:
                return view["compressed"]
            body = view["prefix"] + b', "profile": ' + profile + b'}'
            wire = gzip.compress(body, compresslevel=1, mtime=0)
            view.update(profileWire=profile, compressed=wire)
            return wire
    return view["prefix"] + b', "profile": ' + profile + b'}'


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


LEADING_FLAGS = re.compile(r"^(?:[\U0001F1E6-\U0001F1FF]{2}\s*)+")


def country_flag(country_code):
    code = str(country_code or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", code):
        return ""
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


def name_with_country_flag(name, flag):
    clean = LEADING_FLAGS.sub("", str(name or "")).strip()
    return f"{flag} {clean}" if flag and clean else clean


def public_ip_for_server(server):
    value = str(server or "").strip().strip("[]")
    if not value:
        raise ValueError("服务器地址为空")
    try:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError("服务器地址不是公网 IP")
        return str(address)
    except ValueError as direct_error:
        if any(char.isalpha() for char in value):
            candidates = []
            for item in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM):
                candidate = item[4][0]
                try:
                    address = ipaddress.ip_address(candidate)
                    if address.is_global and str(address) not in candidates:
                        candidates.append(str(address))
                except ValueError:
                    continue
            if candidates:
                return candidates[0]
            raise ValueError("域名没有解析到公网 IP")
        raise direct_error


def country_for_server(server):
    global GEO_NEXT_REQUEST
    address = public_ip_for_server(server)
    with GEO_LOCK:
        cached = GEO_CACHE.get(address)
        if cached and time.time() - cached[0] < 7 * 24 * 3600:
            return cached[1], address
    request = Request(f"https://api.country.is/{quote(address, safe=':')}", headers={
        "Accept": "application/json", "User-Agent": "mxioc-vpn-manager-geoip",
    })
    with GEO_RATE_LOCK:
        delay = GEO_NEXT_REQUEST - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        GEO_NEXT_REQUEST = time.monotonic() + 0.12
    with urlopen(request, timeout=10) as response:
        payload = json.loads(response.read(64 * 1024).decode("utf-8"))
    code = str(payload.get("country") or "").upper()
    flag = country_flag(code)
    if not flag:
        raise ValueError("IP 国家识别服务未返回有效国家")
    with GEO_LOCK:
        GEO_CACHE[address] = (time.time(), code)
    return code, address


def add_country_flags(payload, protected_names=()):
    doc = read_config()
    nodes = doc.setdefault("proxies", [])
    requested = payload.get("names") or []
    if not isinstance(requested, list):
        raise ValueError("节点选择格式不正确")
    selected = {str(name) for name in requested if str(name).strip()}
    targets = [node for node in nodes if (not selected or node.get("name") in selected)
               and node.get("name") not in protected_names]
    if not targets:
        raise ValueError("没有可处理的节点")

    results = {}
    servers = sorted({str(node.get("server", "")) for node in targets})
    with ThreadPoolExecutor(max_workers=min(8, len(servers))) as executor:
        futures = {executor.submit(country_for_server, server): server for server in servers}
        for future in as_completed(futures):
            server = futures[future]
            try:
                results[server] = future.result()
            except Exception as exc:
                results[server] = exc

    existing = {node.get("name") for node in nodes}
    renamed = []
    skipped = []
    for node in targets:
        old = str(node.get("name", ""))
        result = results.get(str(node.get("server", "")))
        if isinstance(result, Exception):
            skipped.append({"name": old, "reason": str(result)})
            continue
        code, address = result
        new = name_with_country_flag(old, country_flag(code))
        if new == old:
            continue
        if new in existing and new != old:
            skipped.append({"name": old, "reason": f"添加国旗后名称与 {new} 重复"})
            continue
        existing.discard(old)
        existing.add(new)
        node["name"] = new
        replace_references(doc, old, new)
        renamed.append({"old": old, "new": new, "country": code, "ip": address})
    if renamed:
        write_config(doc, "country-flags")
    return {"updated": len(renamed), "unchanged": len(targets) - len(renamed) - len(skipped),
            "renamed": renamed, "skipped": skipped}


def delete_nodes_from_doc(doc, names):
    if not isinstance(names, list):
        raise ValueError("请选择需要删除的节点")
    requested = []
    for value in names:
        name = str(value or "").strip()
        if name and name not in requested:
            requested.append(name)
    if not requested:
        raise ValueError("请至少选择一个节点")

    nodes = doc.setdefault("proxies", [])
    existing = {node.get("name") for node in nodes}
    missing = [name for name in requested if name not in existing]
    if missing:
        raise ValueError("节点不存在：" + "、".join(missing))

    selected = set(requested)
    dependants = [
        node.get("name") for node in nodes
        if node.get("dialer-proxy") in selected and node.get("name") not in selected
    ]
    if dependants:
        raise ValueError("选中的入口节点仍被以下链式代理使用，请同时勾选它们：" + "、".join(dependants))

    deleted = [node.get("name") for node in nodes if node.get("name") in selected]
    doc["proxies"] = [node for node in nodes if node.get("name") not in selected]
    for name in deleted:
        replace_references(doc, name)
    return deleted


def bulk_delete_nodes(payload):
    for name in payload.get("names", []):
        protect_failover_component(name)
    doc = read_config()
    deleted = delete_nodes_from_doc(doc, payload.get("names"))
    write_config(doc, "node-bulk-delete")
    return {"deleted": len(deleted), "names": deleted}


def validate_node_config(config):
    from remote_manager import valid_port, valid_domain
    if not isinstance(config, dict):
        raise ValueError("节点配置必须是 JSON 对象")
    node = copy.deepcopy(config)
    kind = str(node.get("type", "")).lower()
    if kind == "https":
        kind, node["tls"] = "http", True
    if kind not in SUPPORTED_NODE_TYPES:
        raise ValueError("暂不支持该节点协议")
    node["type"] = kind
    if kind == "mieru":
        from mieru_adapter import validate as validate_mieru
        node = validate_mieru(node)
    else:
        node["port"] = valid_port(node.get("port"))
    if kind == "snell":
        from snell_adapter import validate as validate_snell
        node = validate_snell(node)
    name = str(node.get("name") or "").strip()
    if not name or len(name) > 200 or any(c in name for c in "\r\n\0"):
        raise ValueError("节点名称须为 1–200 字符且不能含换行")
    node["name"] = name
    host = str(node.get("server") or "").strip().strip("[]")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = valid_domain(host)
        if not host:
            raise ValueError("请填写服务器 IP 或完整域名")
    node["server"] = host
    if kind in ("vless", "vmess", "tuic"):
        try:
            node["uuid"] = str(uuid.UUID(str(node.get("uuid", ""))))
        except ValueError as exc:
            raise ValueError("UUID 格式无效，请使用完整的 UUID") from exc
    if kind in ("ss", "trojan", "hysteria2", "tuic") and not str(node.get("password") or ""):
        raise ValueError("该协议必须填写密码")
    if kind == "ss":
        cipher = str(node.get("cipher") or "")
        if not cipher:
            raise ValueError("Shadowsocks 必须选择加密方式")
        if cipher.startswith("2022-blake3-"):
            length = 16 if cipher == "2022-blake3-aes-128-gcm" else 32
            try:
                keys = str(node["password"]).split(":")
                if any(len(base64.b64decode(key, validate=True)) != length for key in keys):
                    raise ValueError("invalid key length")
            except ValueError as exc:
                raise ValueError(f"该 Shadowsocks 2022 加密方式要求 {length} 字节的 Base64 密钥") from exc
    normalize_reality_options(node)
    reality = node.get("reality-opts") or {}
    if reality:
        if kind != "vless" or not node.get("tls"):
            raise ValueError("Reality 需要 VLESS 协议并启用 TLS")
        key = str(reality.get("public-key") or "")
        try:
            decoded = base64.b64decode(key + "="*(-len(key) % 4), altchars=b'-_', validate=True)
        except ValueError as exc:
            raise ValueError("Reality 公钥必须为 32 字节的 Base64URL") from exc
        if len(decoded) != 32:
            raise ValueError("Reality 公钥必须为 32 字节的 Base64URL")
        sid = str(reality.get("short-id", ""))
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", sid):
            raise ValueError("Reality Short ID 必须为至多 16 位、偶数长度的十六进制字符串")
    if node.get("flow") == "xtls-rprx-vision" and (kind != "vless" or not node.get("tls") or node.get("network", "tcp") != "tcp"):
        raise ValueError("Vision 流控要求 VLESS、TLS / Reality 和 TCP 传输")
    if node.get("dialer-proxy") == name:
        raise ValueError("节点不能以前置中转引用自身")
    return node


@profile_locked
def mutate_node(method, payload):
    old_name = str(payload.get("oldName", ""))
    protect_failover_component(old_name if method == "PUT" else str(payload.get("name", "")))
    if method == "PUT":
        config = validate_node_config(payload.get("config"))
        if config.get("type") == "https":
            config.update(type="http", tls=True)
        if config.get("type") == "http":
            config["udp"] = False
        base = read_config(copy_doc=False)
        index = next((i for i, n in enumerate(base.get("proxies", [])) if n.get("name") == old_name), -1)
        if index < 0:
            raise ValueError("原节点不存在")
        if config.get("name") == old_name:
            if config == base["proxies"][index]:
                return {"unchanged": True}
            doc = dict(base)
            doc["proxies"] = list(base["proxies"])
            doc["proxies"][index] = config
            write_config(doc, "node", unchanged_base=base)
            return {"unchanged": False}
    doc = read_config()
    nodes = doc.setdefault("proxies", [])
    old_name = str(payload.get("oldName", ""))
    if method == "DELETE":
        name = str(payload.get("name", ""))
        delete_nodes_from_doc(doc, [name])
    else:
        config = payload.get("config")
        if not isinstance(config, dict):
            raise ValueError("节点配置必须是 JSON 对象")
        config = validate_node_config(config)
        node_type = str(config.get("type", "")).lower()
        if node_type == "https":
            node_type = "http"
            config["type"] = "http"
            config["tls"] = True
        if node_type not in SUPPORTED_NODE_TYPES:
            raise ValueError("暂不支持该节点协议")
        if node_type == "http":
            config["udp"] = False
        name = str(config.get("name", "")).strip()
        if not name:
            raise ValueError("节点名称不能为空")
        if method == "POST":
            if any(x.get("name") == name for x in nodes):
                raise ValueError("节点名称已存在")
            nodes.append(config)
            if payload.get("addToGroups", True):
                add_node_to_groups(doc, name)
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


def reorder_nodes(nodes, payload):
    name = str(payload.get("name", ""))
    index = next((i for i, node in enumerate(nodes) if node.get("name") == name), -1)
    if index < 0:
        raise ValueError("节点不存在")

    if payload.get("targetName"):
        target_name = str(payload["targetName"])
        if target_name == name:
            return False
        node = nodes.pop(index)
        target = next((i for i, item in enumerate(nodes) if item.get("name") == target_name), -1)
        if target < 0:
            nodes.insert(index, node)
            raise ValueError("目标节点不存在")
        if str(payload.get("position", "before")) == "after":
            target += 1
        nodes.insert(target, node)
        return True

    direction = int(payload.get("direction", 0))
    if direction not in (-1, 1):
        raise ValueError("排序方向无效")
    target = max(0, min(len(nodes) - 1, index + direction))
    if target == index:
        return False
    nodes[index], nodes[target] = nodes[target], nodes[index]
    return True


def sync_group_node_order(doc, excluded_groups=()):
    order = {node.get("name"): index for index, node in enumerate(doc.get("proxies", []))}
    for group in doc.get("proxy-groups", []):
        if group.get("name") in excluded_groups:
            continue
        refs = group.get("proxies")
        if not isinstance(refs, list):
            continue
        positions = [index for index, ref in enumerate(refs) if ref in order]
        sorted_refs = sorted((refs[index] for index in positions), key=order.get)
        for index, ref in zip(positions, sorted_refs):
            refs[index] = ref


def move_node(payload):
    doc = read_config()
    nodes = doc.setdefault("proxies", [])
    if reorder_nodes(nodes, payload):
        sync_group_node_order(doc, {f["name"] for f in profile_record().get("failovers", [])})
        write_config(doc, "node-order")


def mutate_group(method, payload):
    protect_failover_component(str(payload.get("oldName") or payload.get("name") or payload.get("config", {}).get("name", "")))
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
    server_version = "MxiocManager/3"

    def subscription_headers(self, record):
        self.send_header("Profile-Update-Interval", "6")
        self.send_header("Profile-Title", "base64:" + base64.b64encode(
            str(record.get("name", record["id"])).encode("utf-8")).decode("ascii"))
        userinfo = subscription_userinfo(record)
        if userinfo is not None:
            self.send_header("Subscription-Userinfo", userinfo)

    def secure_request(self):
        forwarded = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        if forwarded:
            return forwarded == "https"
        if getattr(self.connection, "cipher", None):
            return True
        # The service only listens on loopback.  A few existing Nginx configs
        # predate X-Forwarded-Proto, so accepting a loopback peer here keeps
        # those HTTPS-terminating proxies working while the backend remains
        # unreachable from the network.
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except (ValueError, IndexError, TypeError):
            return False

    def client_ip(self):
        peer = str(self.client_address[0] if self.client_address else "")
        try:
            peer_ip = ipaddress.ip_address(peer)
        except ValueError:
            return "unknown"
        if peer_ip.is_loopback:
            forwarded = self.headers.get("X-Real-IP", "").strip()
            try:
                return str(ipaddress.ip_address(forwarded)) if forwarded else str(peer_ip)
            except ValueError:
                return str(peer_ip)
        return str(peer_ip)

    def same_origin_request(self):
        expected_host = self.headers.get("Host", "").strip().lower()
        expected_scheme = "https" if self.secure_request() else "http"
        for source in (self.headers.get("Origin", ""), self.headers.get("Referer", "")):
            if not source:
                continue
            parsed = urlparse(source)
            return parsed.scheme.lower() == expected_scheme and parsed.netloc.lower() == expected_host
        return False

    def secure_admin_transport(self):
        if self.secure_request():
            return True
        host = (urlsplit("//" + self.headers.get("Host", "")).hostname or "").lower()
        return host in {"127.0.0.1", "::1", "localhost"}

    def security_headers(self):
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        if self.secure_request():
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def json_out(self, value, status=200, headers=None):
        return self.json_bytes(json.dumps(value, ensure_ascii=False).encode("utf-8"), status, headers)

    def json_bytes(self, body, status=200, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.security_headers()
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def svg_out(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        raw_length = self.headers.get("Content-Length", "0")
        if not re.fullmatch(r"[0-9]+", raw_length):
            raise ValueError("请求 Content-Length 必须为非负整数")
        length = int(raw_length)
        if length > MAX_BODY:
            raise ValueError("请求内容过大")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if length and content_type != "application/json":
            raise ValueError("管理接口只接受 application/json 请求")
        value = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(value, dict):
            raise ValueError("请求 JSON 必须为对象")
        return value

    def authorized(self):
        if not self.secure_admin_transport():
            self.json_out({"error": "管理后台必须通过 HTTPS 访问"}, 426)
            return False
        if session_valid(self.headers.get("Authorization", ""), self.headers.get("Cookie", "")):
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
            if subscription_blocked(record):
                return self.json_out({"error": "订阅已过期或流量已用尽，服务器节点正在撤销"}, 403)
            _, text = get_cached_config(current_files(profile_id)[0])
            body = text.encode("utf-8")
            filename = quote(record.get("name", profile_id) + ".yaml")
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + filename)
            self.subscription_headers(record)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except Exception:
            self.send_error(404)

    def converted(self, profile_id, format_id):
        try:
            record = profile_record(profile_id)
            if subscription_blocked(record):
                return self.json_out({"error": "订阅已过期或流量已用尽，服务器节点正在撤销"}, 403)
            body, skipped = converted_subscription(profile_id, format_id)
            info = CONVERSION_FORMATS[format_id]
            filename = quote(record.get("name", profile_id) + "-" + format_id + info.get("extension", ".txt"))
            self.send_response(200)
            self.send_header("Content-Type", info.get("contentType", "text/plain; charset=utf-8"))
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + filename)
            self.subscription_headers(record)
            self.send_header("X-Mxioc-Skipped-Nodes", str(len(skipped)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except Exception:
            self.send_error(404)

    def page(self):
        body = get_front_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/admin", "/admin/"):
            return self.page()
        if path == "/clash":
            return self.send_error(404)
        if path.startswith("/sub/"):
            try:
                return self.subscription(public_profile_record(unquote(path[5:]))["id"])
            except Exception:
                return self.send_error(404)
        if path.startswith("/convert/"):
            parts = path.strip("/").split("/")
            if len(parts) == 3:
                try:
                    record = public_profile_record(unquote(parts[1]))
                    return self.converted(record["id"], unquote(parts[2]))
                except Exception:
                    return self.send_error(404)
            return self.send_error(404)
        if not self.authorized():
            return
        try:
            if path == "/admin/api/profiles":
                self.json_out({"profiles": list_profiles()})
                return
            if path == "/admin/api/servers":
                return self.json_out({"servers": remote_manager().list()})
            if path == "/admin/api/servers/metrics":
                query = parse_qs(urlparse(self.path).query)
                return self.json_out(host_metrics((query.get("id") or [""])[0]))
            if path in ("/admin/api/servers/jobs", "/admin/api/servers/inbounds"):
                query = parse_qs(urlparse(self.path).query)
                identity = (query.get("id") or [""])[0]
                return self.json_out(remote_manager().job(identity) if path.endswith("/jobs") else remote_manager().inbounds(identity))
            if path == "/admin/api/account":
                self.json_out({"username": load_auth()["username"]})
                return
            if path == "/admin/api/updates":
                self.json_out(update_status())
                return
            if path == "/admin/api/qrcode":
                query = parse_qs(urlparse(self.path).query)
                self.svg_out(subscription_qr_svg((query.get("url") or [""])[0]))
                return
            self.select_profile()
            if path == "/admin/api/nodes/group-options":
                self.json_out({"groups": eligible_group_names(read_config())})
                return
            if path == "/admin/api/snapshot":
                accepts_gzip = any(part.split(";", 1)[0].strip() == "gzip" and not re.search(r";\s*q=0(?:\.0*)?(?:\s|$)", part)
                                   for part in self.headers.get("Accept-Encoding", "").split(","))
                headers = {"Content-Encoding": "gzip", "Vary": "Accept-Encoding"} if accepts_gzip else {"Vary": "Accept-Encoding"}
                self.json_bytes(snapshot_json(accepts_gzip), headers=headers)
            elif path == "/admin/api/nodes/share":
                query = parse_qs(urlparse(self.path).query)
                self.json_out(exported_node_link((query.get("name") or [""])[0]))
            elif path == "/admin/api/nodes/qrcode":
                query = parse_qs(urlparse(self.path).query)
                node = exported_node_link((query.get("name") or [""])[0])
                self.svg_out(subscription_qr_svg(node["uri"]))
            elif path == "/admin/api/failovers":
                self.json_out({"failovers": copy.deepcopy(profile_record().get("failovers", []))})
            elif path == "/admin/api/server-chains":
                self.json_out({"chains": copy.deepcopy(profile_record().get("serverChains", []))})
            elif path == "/admin/api/traffic":
                self.json_out(traffic_info(profile_record()))
            elif path == "/admin/api/conversions":
                self.json_out({"formats": conversion_report()})
            elif path == "/admin/api/raw":
                _, text = get_cached_config(current_files()[0])
                self.json_out({"yaml": text})
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
        if not self.same_origin_request():
            return self.json_out({"error": "请求来源校验失败，请刷新页面后重试"}, 403)
        if path == "/admin/api/login":
            try:
                if not self.secure_admin_transport():
                    return self.json_out({"error": "登录必须通过 HTTPS 访问"}, 426)
                client = self.client_ip()
                retry_after = login_retry_after(client)
                if retry_after:
                    return self.json_out({"error": "登录失败次数过多，请稍后再试",
                                          "retryAfter": retry_after}, 429,
                                         {"Retry-After": str(retry_after)})
                data = self.body()
                username = str(data.get("username", ""))
                password = str(data.get("password", ""))
                account_key = "account:" + hashlib.sha256(username.lower().encode()).hexdigest()
                retry_after = login_retry_after(account_key)
                if retry_after:
                    return self.json_out({"error": "登录失败次数过多，请稍后再试",
                                          "retryAfter": retry_after}, 429,
                                         {"Retry-After": str(retry_after)})
                credentials_valid = (1 <= len(username) <= 64 and 1 <= len(password) <= 256 and
                                     authenticate(username, password))
                if not credentials_valid:
                    retry_after = max(record_login_failure(client), record_login_failure(account_key))
                    time.sleep(0.5)
                    if retry_after:
                        return self.json_out({"error": "登录失败次数过多，请稍后再试",
                                              "retryAfter": retry_after}, 429,
                                             {"Retry-After": str(retry_after)})
                    return self.json_out({"error": "用户名或密码错误"}, 401)
                clear_login_failures(client)
                clear_login_failures(account_key)
                token = create_session()
                return self.json_out({"ok": True}, headers={"Set-Cookie": session_cookie(token, self.secure_request())})
            except Exception as exc:
                return self.json_out({"error": str(exc)}, 400)
        if not self.authorized():
            return
        try:
            if path == "/admin/api/logout":
                revoke_session(self.headers.get("Authorization", ""), self.headers.get("Cookie", ""))
                return self.json_out({"ok": True}, headers={"Set-Cookie": expired_session_cookie(self.secure_request())})
            data = self.body()
            if path == "/admin/api/profiles":
                return self.json_out({"ok": True, "profile": create_profile(data)})
            if path == "/admin/api/servers":
                return self.json_out({"ok": True, "server": save_remote_server(data)})
            if path == "/admin/api/servers/probe":
                return self.json_out(remote_manager().probe(data))
            if path == "/admin/api/servers/test":
                return self.json_out(remote_manager().test(str(data.get("id", ""))))
            if path == "/admin/api/servers/attach":
                return self.json_out(remote_manager().attach_existing(str(data.get("id", ""))))
            if path == "/admin/api/servers/sni":
                return self.json_out(remote_manager().test_sni(str(data.get("serverId", "")), data.get("candidates"), force=data.get("force") is True))
            if path == "/admin/api/servers/users/batch":
                self.select_profile()
                return self.json_out({"ok": True, **batch_subscription_users(data)})
            if path == "/admin/api/servers/users":
                self.select_profile()
                return self.json_out({"ok": True, **provision_subscription_user(data)})
            if path == "/admin/api/servers/import":
                self.select_profile()
                return self.json_out({"ok": True, **import_server_inbound(data)})
            if path == "/admin/api/servers/bind":
                self.select_profile()
                return self.json_out({"ok": True, "binding": bind_remote_node(str(data.get("serverId", "")), data.get("inboundId"))})
            if path == "/admin/api/traffic/sync":
                self.select_profile()
                enforce_profile(profile_record()["id"])
                return self.json_out({"ok": True, "traffic": traffic_info(profile_record())})
            if path == "/admin/api/servers/install":
                return self.json_out({"ok": True, "job": remote_manager().start_install(str(data.get("id", "")), data.get("confirmed"))}, 202)
            if path == "/admin/api/servers/diagnose":
                manager = remote_manager()
                return self.json_out({"log": manager.diagnostics(copy.deepcopy(manager.record(str(data.get("id", "")))))})
            if path == "/admin/api/servers/inbounds":
                self.select_profile()
                return self.json_out({"ok": True, **create_owned_remote(data)})
            if path == "/admin/api/servers/relay":
                self.select_profile()
                return self.json_out({"ok": True, **create_owned_remote(data, relay=True)})
            if path == "/admin/api/updates/check":
                return self.json_out({"ok": True, **update_status(force=True)})
            if path == "/admin/api/updates/dismiss":
                return self.json_out({"ok": True, **dismiss_update()})
            if path == "/admin/api/updates/apply":
                return self.json_out({"ok": True, "task": start_update(bool(data.get("force")))}, status=202)
            if path == "/admin/api/account":
                username = update_auth(
                    str(data.get("username", "")), str(data.get("current", "")),
                    str(data.get("newUsername", "")), str(data.get("newPassword", "")),
                )
                return self.json_out({"ok": True, "username": username}, headers={
                    "Set-Cookie": expired_session_cookie(self.secure_request())
                })
            if path == "/admin/api/uninstall":
                if str(data.get("confirmation", "")) != "UNINSTALL":
                    raise ValueError("请输入 UNINSTALL 确认卸载")
                if not authenticate(str(data.get("username", "")), str(data.get("password", ""))):
                    raise ValueError("当前用户名或密码错误")
                return self.json_out({"ok": True, **start_uninstall(bool(data.get("purgeData")))}, status=202)
            self.select_profile()
            if path == "/admin/api/nodes/validate":
                config = validate_node_config(data.get("config"))
                try:
                    uri = node_to_uri(config) if not config.get("dialer-proxy") else None
                except ValueError:
                    uri = None
                return self.json_out({"ok": True, "config": config, "uri": uri})
            if path == "/admin/api/failovers":
                return self.json_out({"ok": True, "failover": create_failover(data)})
            if path == "/admin/api/nodes": mutate_node("POST", data)
            elif path == "/admin/api/nodes/move": move_node(data)
            elif path == "/admin/api/nodes/flags":
                return self.json_out({"ok": True, **add_country_flags(data, {p for f in profile_record().get("failovers", []) for p in f.get("paths", [])})})
            elif path == "/admin/api/chains": mutate_chain("POST", data)
            elif path == "/admin/api/import-node":
                return self.json_out({"ok": True, **import_node_links(data)})
            elif path == "/admin/api/import-subscription/preview":
                return self.json_out(subscription_preview(data))
            elif path == "/admin/api/import-subscription":
                return self.json_out({"ok": True, **import_subscription(data)})
            elif path == "/admin/api/nodes/groups": mutate_node_membership(data)
            elif path == "/admin/api/groups": mutate_group("POST", data)
            elif path == "/admin/api/rules": mutate_rule("POST", data)
            elif path == "/admin/api/rules/move": move_rule(data)
            elif path == "/admin/api/dns": mutate_dns("POST", data)
            elif path == "/admin/api/password":
                username = update_auth(str(data.get("username", "")), str(data.get("current", "")),
                                       "", str(data.get("new", "")))
                return self.json_out({"ok": True, "username": username}, headers={
                    "Set-Cookie": expired_session_cookie(self.secure_request())
                })
            elif path == "/admin/api/backups/restore":
                name = Path(str(data.get("name", ""))).name
                backup = BACKUP_DIR / name
                if not backup.exists():
                    raise ValueError("备份不存在")
                doc = yaml_load(backup.read_text(encoding="utf-8"))
                write_config(doc, "before-restore")
            else:
                return self.send_error(404)
            self.json_out({"ok": True})
        except Exception as exc:
            self.json_out({"error": str(exc)}, 400)

    def do_PUT(self):
        if not self.same_origin_request():
            return self.json_out({"error": "请求来源校验失败，请刷新页面后重试"}, 403)
        if not self.authorized():
            return
        path = urlparse(self.path).path
        try:
            data = self.body()
            if path == "/admin/api/profiles":
                return self.json_out({"ok": True, "profile": update_profile(data)})
            if path == "/admin/api/servers":
                return self.json_out({"ok": True, "server": save_remote_server(data)})
            if path == "/admin/api/servers/inbounds":
                with ENFORCEMENT_LOCK:
                    for record in load_profiles()["profiles"]:
                        for binding in record.get("remoteNodes", []):
                            if binding.get("status") == "active" and (binding["serverId"], binding["inboundId"]) == (str(data.get("serverId", "")), data.get("inboundId")):
                                if binding.get('scope') == 'user':
                                    from shared_users import find_user
                                    find_user(data.get('inbound') or {}, binding)
                                    continue
                                if binding.get("identityHash") and binding["identityHash"] != remote_node_identity(data.get("inbound") or {}):
                                    raise ValueError("专属入站的协议、端口或认证配置不能替换，请创建新入站以保持订阅归属")
                    remote_manager().update_inbound(str(data.get("serverId", "")), data.get("inboundId"), data.get("inbound"))
                return self.json_out({"ok": True})
            self.select_profile()
            if path == "/admin/api/servers/bandwidth":
                return self.json_out({"ok": True, "bandwidth": set_node_bandwidth(data)})
            if path == "/admin/api/servers/multiplier":
                result = set_node_multiplier(data)
                return self.json_out({"ok": True, "node": result, "traffic": traffic_info(profile_record())})
            if path == "/admin/api/traffic":
                return self.json_out({"ok": True, "traffic": update_traffic(data)})
            if path == "/admin/api/traffic/plan":
                return self.json_out({"ok": True, "traffic": apply_subscription_plan(data)})
            if path == "/admin/api/traffic/plans":
                plan = save_subscription_plan(data)
                return self.json_out({"ok": True, "plan": plan, "traffic": traffic_info(profile_record())})
            if path == "/admin/api/traffic/plans/delete":
                delete_subscription_plan(data)
                return self.json_out({"ok": True, "traffic": traffic_info(profile_record())})
            if path == "/admin/api/traffic/bindings/cleanup":
                return self.json_out({"ok": True, **cleanup_traffic_bindings(data)})
            if path == "/admin/api/traffic/bindings/remove":
                return self.json_out({"ok": True, **remove_traffic_binding(data)})
            if path == "/admin/api/nodes":
                return self.json_out({"ok": True, **(mutate_node("PUT", data) or {})})
            elif path == "/admin/api/chains": mutate_chain("PUT", data)
            elif path == "/admin/api/groups": mutate_group("PUT", data)
            elif path == "/admin/api/rules": mutate_rule("PUT", data)
            elif path == "/admin/api/dns": mutate_dns("PUT", data)
            elif path == "/admin/api/raw":
                doc = yaml_load(str(data.get("yaml", "")))
                write_config(doc, "raw")
            else:
                return self.send_error(404)
            self.json_out({"ok": True})
        except Exception as exc:
            self.json_out({"error": str(exc)}, 400)

    def do_DELETE(self):
        if not self.same_origin_request():
            return self.json_out({"error": "请求来源校验失败，请刷新页面后重试"}, 403)
        if not self.authorized():
            return
        path = urlparse(self.path).path
        try:
            data = self.body()
            if path == "/admin/api/profiles":
                delete_profile(str(data.get("id", "")))
                return self.json_out({"ok": True})
            if path == "/admin/api/servers":
                return self.json_out({"ok": True, **detach_remote_server(str(data.get("id", "")), data.get("detach", False))})
            if path == "/admin/api/servers/inbounds":
                with ENFORCEMENT_LOCK:
                    server_id, identity = str(data.get("serverId", "")), int(data.get("inboundId"))
                    result = remote_manager().delete_inbound(server_id, identity)
                    with LOCK:
                        for record in load_profiles()["profiles"]:
                            for binding in record.get("remoteNodes", []):
                                if (binding["serverId"], binding["inboundId"]) == (server_id, identity):
                                    binding.update(status="revoked", revokedAt=int(time.time()))
                        save_profiles(load_profiles())
                    return self.json_out({"ok": True, **result})
            self.select_profile()
            if path == "/admin/api/failovers":
                remove_failover(str(data.get("name", "")))
                return self.json_out({"ok": True})
            if path == "/admin/api/server-chains":
                protect_failover_component(str(data.get("name", "")))
                remove_server_chain(str(data.get("name", "")))
                return self.json_out({"ok": True})
            if path == "/admin/api/nodes": mutate_node("DELETE", data)
            elif path == "/admin/api/nodes/bulk":
                return self.json_out({"ok": True, **bulk_delete_nodes(data)})
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


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, max_workers=32, **kwargs):
        self.request_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        self.request_slots.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


if __name__ == "__main__":
    load_profiles()
    load_auth()
    threading.Thread(target=update_checker_loop, daemon=True).start()
    threading.Thread(target=enforcement_loop, daemon=True).start()
    LimitedThreadingHTTPServer(("127.0.0.1", 62577), Handler).serve_forever()
