#!/usr/bin/env python3
import hashlib
import hmac
import base64
import json
import os
import copy
import ipaddress
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlsplit
from urllib.request import Request, urlopen

import yaml
try:
    from yaml import CSafeLoader as YamlLoader, CSafeDumper as YamlDumper
except ImportError:
    from yaml import SafeLoader as YamlLoader, SafeDumper as YamlDumper


def yaml_load(stream):
    return yaml.load(stream, Loader=YamlLoader)


def yaml_dump(data):
    return yaml.dump(data, Dumper=YamlDumper, allow_unicode=True, sort_keys=False, width=4096)


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
SESSION_TTL = 30 * 24 * 3600
LOCK = threading.RLock()
UPDATE_LOCK = threading.RLock()
GEO_LOCK = threading.RLock()
GEO_RATE_LOCK = threading.Lock()
GEO_CACHE = {}
GEO_NEXT_REQUEST = 0.0
CTX = threading.local()
MAX_BODY = 2 * 1024 * 1024
MAX_SUBSCRIPTION = 8 * 1024 * 1024
BUILTINS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
NON_NODE_GROUPS = {"🛑 广告拦截", "🛡️ 基础广告拦截", "🔥 强力广告拦截"}
SUPPORTED_NODE_TYPES = {"vless", "tuic", "hysteria2", "trojan", "ss", "vmess", "socks5", "http"}
CONVERSION_FORMATS = {
    "v2ray": {
        "name": "V2Ray / v2rayN 通用订阅",
        "types": SUPPORTED_NODE_TYPES,
        "note": "适合新版 v2rayN；旧版 V2Ray/v2rayNG 可能不支持 TUIC、Hysteria2 或 Reality。",
    },
    "shadowrocket": {
        "name": "Shadowrocket（小火箭）订阅",
        "types": SUPPORTED_NODE_TYPES,
        "note": "适合新版 Shadowrocket；旧版本可能无法识别 TUIC、Hysteria2 或 Reality。",
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


def start_update():
    with UPDATE_LOCK:
        status = update_status(force=True)
        if status["updating"]:
            raise ValueError("更新任务正在执行，请稍候")
        sha = status["latestSha"]
        if not sha:
            raise ValueError("暂时无法获取仓库最新版本")
        if sha == status["currentSha"]:
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
                              "files": [str(path) for path in FILES]}]}
        save_profiles(data)
        return data
    try:
        mtime = PROFILES_FILE.stat().st_mtime_ns
        if PROFILES_CACHE is not None and PROFILES_MTIME == mtime:
            return PROFILES_CACHE
        data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        if not isinstance(data.get("profiles"), list):
            raise ValueError("订阅配置索引损坏")
        PROFILES_CACHE = data
        PROFILES_MTIME = mtime
        return data
    except Exception:
        data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        return data


def save_profiles(data):
    global PROFILES_CACHE, PROFILES_MTIME
    text = json.dumps(data, ensure_ascii=False, indent=2)
    PROFILES_FILE.write_text(text, encoding="utf-8")
    os.chmod(PROFILES_FILE, 0o600)
    PROFILES_CACHE = data
    PROFILES_MTIME = PROFILES_FILE.stat().st_mtime_ns



def profile_record(profile_id=None):
    profile_id = profile_id or getattr(CTX, "profile", "clash") or "clash"
    record = next((x for x in load_profiles()["profiles"] if x.get("id") == profile_id), None)
    if not record:
        raise ValueError("所选订阅配置不存在")
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
        doc = copy.deepcopy(get_cached_config(current_files(template_id)[0])[0])
    path = PROFILES_DIR / f"{profile_id}.yaml"
    validate_config(doc)
    text = yaml_dump(doc)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o644)
    stat = path.stat()
    with CONFIG_CACHE_LOCK:
        CONFIG_CACHE[str(path.resolve())] = {
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
            "doc": copy.deepcopy(doc),
            "text": text,
        }
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
            with CONFIG_CACHE_LOCK:
                CONFIG_CACHE.pop(str(old_path.resolve()), None)
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
        with CONFIG_CACHE_LOCK:
            CONFIG_CACHE.pop(str(path.resolve()), None)
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
        if expires < now + SESSION_TTL - 24 * 3600:
            sessions[digest] = now + SESSION_TTL
            save_sessions_locked()
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


def session_cookie(token):
    return (f"mxioc_session={token}; Path=/admin; Max-Age={SESSION_TTL}; "
            "HttpOnly; Secure; SameSite=Strict")


def expired_session_cookie():
    return "mxioc_session=; Path=/admin; Max-Age=0; HttpOnly; Secure; SameSite=Strict"


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


def get_cached_config(path):
    p = Path(path)
    stat = p.stat()
    key = str(p.resolve())
    with CONFIG_CACHE_LOCK:
        entry = CONFIG_CACHE.get(key)
        if entry and entry["mtime_ns"] == stat.st_mtime_ns and entry["size"] == stat.st_size:
            return entry["doc"], entry["text"]

    text = p.read_text(encoding="utf-8")
    doc = yaml_load(text)
    if not isinstance(doc, dict):
        raise ValueError("配置文件不是有效的 YAML 对象")

    with CONFIG_CACHE_LOCK:
        CONFIG_CACHE[key] = {
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
            "doc": doc,
            "text": text,
        }
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


def write_config(doc, reason="manual"):
    validate_config(doc)
    text = yaml_dump(doc)
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
                os.chmod(temp_name, 0o644)
                os.replace(temp_name, path)
                stat = path.stat()
                key = str(path.resolve())
                with CONFIG_CACHE_LOCK:
                    CONFIG_CACHE[key] = {
                        "mtime_ns": stat.st_mtime_ns,
                        "size": stat.st_size,
                        "doc": copy.deepcopy(doc),
                        "text": text,
                    }
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


def parse_node_link(link):
    link = str(link or "").strip().strip('"\'').replace("\\://", "://").replace("\\@", "@").replace("\\.", ".")
    if not link or "://" not in link:
        raise ValueError("请输入完整的节点链接")
    scheme = link.split("://", 1)[0].lower()
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


def eligible_group_names(doc):
    return [group.get("name") for group in doc.get("proxy-groups", [])
            if isinstance(group, dict) and group.get("name")
            and group.get("name") not in NON_NODE_GROUPS]


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


def mutate_chain(method, payload):
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
            if not node.get("name") or not node.get("server") or not node.get("port"):
                skipped.append(str(node.get("name") or "信息不完整的节点"))
                continue
            nodes.append(node)
        return nodes, skipped
    candidates = [text]
    try:
        decoded = b64decode_text(text)
        if "://" in decoded:
            candidates = decoded.splitlines()
    except Exception:
        if "\n" in text:
            candidates = text.splitlines()
    for line in candidates:
        line = line.strip()
        if not line:
            continue
        try:
            nodes.append(parse_node_link(line))
        except Exception:
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


def conversion_report(profile_id=None):
    record = profile_record(profile_id)
    doc, _ = get_cached_config(current_files(profile_id)[0])
    nodes = doc.get("proxies", []) or []
    result = []
    for format_id, info in CONVERSION_FORMATS.items():
        supported, skipped = [], []
        for node in nodes:
            reason = ""
            if node.get("dialer-proxy"):
                reason = "链式代理无法用单节点分享链接表达"
            elif str(node.get("type", "")).lower() not in info["types"]:
                reason = "客户端不支持该协议"
            if reason:
                skipped.append({"name": node.get("name", "未知节点"), "type": node.get("type", ""), "reason": reason})
            else:
                try:
                    node_to_uri(node)
                    supported.append(node.get("name", ""))
                except Exception as error:
                    skipped.append({"name": node.get("name", "未知节点"), "type": node.get("type", ""), "reason": str(error)})
        result.append({"id": format_id, "name": info["name"], "note": info["note"],
                       "supported": len(supported), "skipped": skipped,
                       "url": f"/convert/{record['id']}/{format_id}"})
    return result


def converted_subscription(profile_id, format_id):
    if format_id not in CONVERSION_FORMATS:
        raise ValueError("不支持该转换格式")
    doc, _ = get_cached_config(current_files(profile_id)[0])
    info = CONVERSION_FORMATS[format_id]
    links, skipped = [], []
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
    raw = "\n".join(links).encode("utf-8")
    return base64.b64encode(raw), skipped


def snapshot():
    doc = read_config(copy_doc=False)
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


def add_country_flags(payload):
    doc = read_config()
    nodes = doc.setdefault("proxies", [])
    requested = payload.get("names") or []
    if not isinstance(requested, list):
        raise ValueError("节点选择格式不正确")
    selected = {str(name) for name in requested if str(name).strip()}
    targets = [node for node in nodes if not selected or node.get("name") in selected]
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
    doc = read_config()
    deleted = delete_nodes_from_doc(doc, payload.get("names"))
    write_config(doc, "node-bulk-delete")
    return {"deleted": len(deleted), "names": deleted}


def mutate_node(method, payload):
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
        config = dict(config)
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


def sync_group_node_order(doc):
    order = {node.get("name"): index for index, node in enumerate(doc.get("proxies", []))}
    for group in doc.get("proxy-groups", []):
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
        sync_group_node_order(doc)
        write_config(doc, "node-order")


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
    server_version = "MxiocManager/3"

    def json_out(self, value, status=200, headers=None):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY:
            raise ValueError("请求内容过大")
        return json.loads(self.rfile.read(length) or b"{}")

    def authorized(self):
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
            _, text = get_cached_config(current_files(profile_id)[0])
            body = text.encode("utf-8")
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

    def converted(self, profile_id, format_id):
        try:
            record = profile_record(profile_id)
            body, skipped = converted_subscription(profile_id, format_id)
            filename = quote(record.get("name", profile_id) + "-" + format_id + ".txt")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + filename)
            self.send_header("Profile-Update-Interval", "24")
            self.send_header("Subscription-Userinfo", "upload=0; download=0; total=1125899906842624; expire=4102444800")
            self.send_header("X-Mxioc-Skipped-Nodes", str(len(skipped)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
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
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/admin", "/admin/"):
            return self.page()
        if path.startswith("/sub/"):
            return self.subscription(unquote(path[5:]))
        if path.startswith("/convert/"):
            parts = path.strip("/").split("/")
            if len(parts) == 3:
                return self.converted(unquote(parts[1]), unquote(parts[2]))
            return self.send_error(404)
        if not self.authorized():
            return
        try:
            if path == "/admin/api/profiles":
                self.json_out({"profiles": list_profiles()})
                return
            if path == "/admin/api/updates":
                self.json_out(update_status())
                return
            self.select_profile()
            if path == "/admin/api/snapshot":
                self.json_out(snapshot())
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
        if path == "/admin/api/login":
            try:
                data = self.body()
                if not authenticate(str(data.get("username", "")), str(data.get("password", ""))):
                    time.sleep(0.35)
                    return self.json_out({"error": "用户名或密码错误"}, 401)
                token = create_session()
                return self.json_out({"ok": True}, headers={"Set-Cookie": session_cookie(token)})
            except Exception as exc:
                return self.json_out({"error": str(exc)}, 400)
        if not self.authorized():
            return
        try:
            if path == "/admin/api/logout":
                revoke_session(self.headers.get("Authorization", ""), self.headers.get("Cookie", ""))
                return self.json_out({"ok": True}, headers={"Set-Cookie": expired_session_cookie()})
            data = self.body()
            if path == "/admin/api/profiles":
                return self.json_out({"ok": True, "profile": create_profile(data)})
            if path == "/admin/api/updates/check":
                return self.json_out({"ok": True, **update_status(force=True)})
            if path == "/admin/api/updates/dismiss":
                return self.json_out({"ok": True, **dismiss_update()})
            if path == "/admin/api/updates/apply":
                return self.json_out({"ok": True, "task": start_update()}, status=202)
            self.select_profile()
            if path == "/admin/api/nodes": mutate_node("POST", data)
            elif path == "/admin/api/nodes/move": move_node(data)
            elif path == "/admin/api/nodes/flags":
                return self.json_out({"ok": True, **add_country_flags(data)})
            elif path == "/admin/api/chains": mutate_chain("POST", data)
            elif path == "/admin/api/import-node":
                config = parse_node_link(data.get("link", ""))
                mutate_node("POST", {"config": config, "addToGroups": data.get("addToGroups", True)})
            elif path == "/admin/api/import-subscription/preview":
                return self.json_out(subscription_preview(data))
            elif path == "/admin/api/import-subscription":
                return self.json_out({"ok": True, **import_subscription(data)})
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
                clear_sessions()
                return self.json_out({"ok": True}, headers={"Set-Cookie": expired_session_cookie()})
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
        if not self.authorized():
            return
        path = urlparse(self.path).path
        try:
            data = self.body()
            if path == "/admin/api/profiles":
                return self.json_out({"ok": True, "profile": update_profile(data)})
            self.select_profile()
            if path == "/admin/api/nodes": mutate_node("PUT", data)
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


if __name__ == "__main__":
    load_profiles()
    load_auth()
    threading.Thread(target=update_checker_loop, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 62577), Handler).serve_forever()
