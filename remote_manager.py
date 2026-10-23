"""Pinned-SSH provisioning, panel APIs and standalone core control."""

import base64
import copy
import hashlib
import http.client
from http.cookies import SimpleCookie
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit, quote, unquote

INSTALL_URL = "https://raw.githubusercontent.com/Teminuosi/3x-ui/main/install.sh"
MAX_LOG = 64 * 1024
INBOUND_FIELDS = {"up", "down", "total", "remark", "enable", "expiryTime", "listen",
                  "port", "protocol", "settings", "streamSettings", "sniffing", "allocate"}


def libraries():
    try:
        import paramiko
        from cryptography.fernet import Fernet
        return paramiko, Fernet
    except ImportError as exc:
        raise ValueError("服务器管理需要 Python 3.9+ 和 Paramiko，请先运行 vpn --update-only 安装依赖") from exc


def valid_ip(value):
    try:
        address = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError as exc:
        raise ValueError("请输入服务器 IPv4 或 IPv6 地址") from exc
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        raise ValueError("服务器地址不能是回环、链路本地、多播或未指定地址")
    return str(address)


def valid_port(value):
    if isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError("端口必须是 1–65535 的整数")
    return int(value)


def valid_domain(value):
    value = str(value or "").strip().lower().rstrip(".")
    if not value:
        return ""
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("绑定域名格式无效") from exc
    if len(value) > 253 or "." not in value or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")
    ):
        raise ValueError("域名只填写主机名，例如 panel.example.com，不包含协议、端口或路径")
    return value


def parse_panel_address(value):
    value = text(value, "面板完整地址", maximum=2048).strip()
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("面板地址不能含空白、控制字符或反斜线")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError()
        port = valid_port(parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80))
    except ValueError as exc:
        raise ValueError("请填写完整面板地址，例如 https://panel.example.com:13145/riben/，不要在地址中包含账号密码") from exc
    if parsed.query or parsed.fragment:
        raise ValueError("面板地址只填写协议、主机、端口和访问路径，不包含查询参数或片段")
    try:
        host = str(ipaddress.ip_address(parsed.hostname))
        if "%" in host:
            raise ValueError("不支持带区域标识的面板地址")
    except ValueError:
        host = valid_domain(parsed.hostname)
    path = parsed.path or "/"
    decoded = unquote(path)
    if (any(ord(c) < 32 or ord(c) == 127 for c in decoded) or "\\" in decoded
            or any(segment in (".", "..") for segment in decoded.split("/"))
            or re.search(r"%(?![0-9a-fA-F]{2})", path)):
        raise ValueError("面板访问路径包含无效字符或上级路径")
    path = quote(path, safe="/%:@!$&'()*+,;=-._~").rstrip("/") + "/"
    authority = f"[{host}]" if ":" in host else host
    if parsed.port is not None:
        authority += f":{port}"
    return {"panelPort": port, "panelPath": path, "panelTLS": parsed.scheme == "https",
            "panelUrl": urlunsplit((parsed.scheme, authority, path, "", ""))}


def text(value, name, minimum=1, maximum=256):
    value = str(value or "")
    if not minimum <= len(value) <= maximum or any(c in value for c in "\r\n\0"):
        raise ValueError(f"{name}需要 {minimum}–{maximum} 个字符，且不能包含换行")
    return value


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def clean_log(value, secret_values=()):
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value)).replace("\r", "\n")
    for secret in sorted((str(x) for x in secret_values if x), key=len, reverse=True):
        value = value.replace(secret, "[已隐藏]")
    value = re.sub(r"(?im)^.*?(?:password|passwd|api\s*token|private.?key|secret)[\"'\s]*[:=].*$",
                   "[凭证信息已隐藏]", value)
    return value


def installation_error(log, stage, code):
    lines = [line.strip() for line in log.splitlines() if line.strip() and not line.startswith("MXIOC_")]
    errors = [line for line in lines if re.search(r"error|failed|fatal|curl:|失败|拒绝|无法|NXDOMAIN|timed out|not found", line, re.I)]
    detail = "；".join((errors or lines)[-3:])[-700:]
    return f"安装在 {stage} 阶段失败（退出码 {code}）" + ("：" + detail if detail else "，请查看安装日志")


PANEL_TYPES = {"3x-ui", "x-ui", "x-panel"}
INSTALL_TYPES = PANEL_TYPES | {"xray", "sing-box"}


def install_type(record):
    value = record.get("installType", "3x-ui")
    if not isinstance(value, str) or value not in INSTALL_TYPES:
        raise ValueError("不支持的安装类型，请选择支持的面板或内核")
    return value


def core_install_script(record):
    kind = install_type(record)
    xray = kind == "xray"
    service = "xray" if xray else "sing-box"
    config = "/usr/local/etc/xray/config.json" if xray else "/etc/sing-box/config.json"
    binary = "/usr/local/bin/xray" if xray else "/usr/bin/sing-box"
    check = f"{binary} run -test -config" if xray else f"{binary} check -c"
    url = ("https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh" if xray
           else "https://sing-box.app/install.sh")
    argument = "install" if xray else ""
    encoded = base64.b64encode(record.get("coreConfig", "").encode()).decode()
    # Only the validated enum and base64 data enter the script. Never print configuration.
    return f"""set -Eeuo pipefail
stage=preflight
printf 'MXIOC_STAGE=preflight\\n'
trap 'rc=$?; printf "MXIOC_FAILURE_STAGE=%s EXIT=%s\\n" "$stage" "$rc"; exit "$rc"' ERR
test "$(id -u)" = 0
command -v systemctl >/dev/null || {{ echo 'Standalone cores require systemd'; exit 12; }}
if ! command -v curl >/dev/null || ! command -v flock >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update && apt-get install -y curl util-linux
  elif command -v dnf >/dev/null; then dnf install -y curl util-linux
  elif command -v yum >/dev/null; then yum install -y curl util-linux
  else echo 'Missing curl/flock or unsupported package manager'; exit 12; fi
fi
mkdir -p /var/lock
exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || {{ echo 'Another MXIOC installation is running'; exit 75; }}
workdir=$(mktemp -d /tmp/mxioc-core.XXXXXXXX)
installer="$workdir/install.sh"
backup=$(mktemp /tmp/mxioc-config.XXXXXXXX)
candidate=''
had_config=0
applied=0
cleanup() {{
  rc=$?
  if [ "$rc" != 0 ] && [ "$applied" = 1 ]; then
    if [ "$had_config" = 1 ]; then cp -p "$backup" {config}; else rm -f {config}; fi
    systemctl restart {service} >/dev/null 2>&1 || true
  fi
  rm -rf -- "$workdir"
  rm -f "$backup"
  [ -z "$candidate" ] || rm -f "$candidate"
}}
trap cleanup EXIT
if [ -f {config} ]; then cp -p {config} "$backup"; had_config=1; fi
stage=download
printf 'MXIOC_STAGE=download\\n'
curl -fLsS --retry 2 --connect-timeout 20 --max-time 180 {shlex.quote(url)} -o "$installer"
test -s "$installer"
stage=install
printf 'MXIOC_STAGE=install\\n'
applied=1
(cd "$workdir" && bash -e "$installer" {argument} </dev/null)
if [ "$had_config" = 1 ]; then cp -p "$backup" {config}; fi
stage=config
printf 'MXIOC_STAGE=config\\n'
if [ -n '{encoded}' ]; then
  mkdir -p $(dirname {config})
  candidate=$(mktemp {config}.mxioc.XXXXXXXX)
  printf '%s' '{encoded}' | base64 -d > "$candidate"
  chmod 600 "$candidate"
  {check} "$candidate" >/dev/null 2>&1 || {{ echo 'Core configuration validation failed; configuration was not applied'; exit 22; }}
  applied=1
  if [ "$had_config" = 1 ]; then cp -p "$backup" {config}.mxioc-backup; fi
  # Preserve permissions needed by the vendor service user.
  if [ -f {config} ]; then chown --reference={config} "$candidate"; chmod --reference={config} "$candidate"; else chmod 644 "$candidate"; fi
  mv "$candidate" {config}
  candidate=''
fi
{check} {config} >/dev/null 2>&1 || {{ echo 'Core configuration validation failed'; exit 22; }}
stage=service
printf 'MXIOC_STAGE=service\\n'
systemctl enable {service}
systemctl restart {service}
sleep 2
systemctl is-active --quiet {service}
{binary} version
printf 'MXIOC_STAGE=installed\\n'
"""


def install_script(record, password):
    if install_type(record) not in PANEL_TYPES:
        return core_install_script(record)
    env = "XUI_DOMAIN=" + shlex.quote(record["domain"]) if record["domain"] else "XUI_AUTO=1"
    return f"""set -Eeuo pipefail
stage=preflight
printf 'MXIOC_STAGE=preflight\\n'
trap 'rc=$?; printf "\\nMXIOC_FAILURE_STAGE=%s EXIT=%s\\n" "$stage" "$rc"; exit "$rc"' ERR
test "$(id -u)" = 0
command -v bash >/dev/null
if ! command -v curl >/dev/null || ! command -v flock >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update && apt-get install -y curl util-linux
  elif command -v dnf >/dev/null; then dnf install -y curl util-linux
  elif command -v yum >/dev/null; then yum install -y curl util-linux
  elif command -v apk >/dev/null; then apk add --no-cache curl util-linux
  else echo 'Missing curl/flock and no supported package manager'; exit 12; fi
fi
mkdir -p /var/lock
exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || {{ echo 'Another MXIOC 3x-ui installation is still running'; exit 75; }}
stage=download
printf 'MXIOC_STAGE=download\\n'
installer=$(mktemp /tmp/mxioc-xui.XXXXXXXX)
chmod 700 "$installer"
trap 'rm -f -- "$installer"' EXIT
curl -fLsS --retry 2 --connect-timeout 20 --max-time 180 {shlex.quote(INSTALL_URL)} -o "$installer"
test -s "$installer"
stage=install
printf 'MXIOC_STAGE=install\\n'
{env} bash "$installer" </dev/null
stage=credentials
printf 'MXIOC_STAGE=credentials\\n'
cd /usr/local/x-ui
./x-ui setting -username {shlex.quote(record['panelUser'])} -password {shlex.quote(password)} >/dev/null
stage=service
printf 'MXIOC_STAGE=service\\n'
if command -v systemctl >/dev/null; then
  systemctl restart x-ui
  for attempt in $(seq 1 20); do systemctl is-active --quiet x-ui && break; sleep 1; done
  systemctl is-active --quiet x-ui
else
  rc-service x-ui restart
  rc-service x-ui status
fi
printf 'MXIOC_STAGE=installed\\n'
"""


def parse_panel_settings(output, record):
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    port = re.search(r"(?m)^port(?:（[^\n]*?）)?:[ \t]*(\d+)[ \t]*$", output)
    path = re.search(r"(?m)^webBasePath(?:（[^\n]*?）)?:[ \t]*(\S+)[ \t]*$", output)
    if not port or not path:
        raise ValueError("无法读取 3x-ui 面板端口或访问路径，请查看诊断日志")
    port = valid_port(port.group(1))
    segment = path.group(1).strip("/")
    base = "/" + segment + "/" if segment else "/"
    if not re.fullmatch(r"/(?:[A-Za-z0-9_.~-]+/)*", base) or ".." in base:
        raise ValueError("面板访问路径格式无效")
    cert = re.search(r"(?m)^cert:[ \t]*(\S+)[ \t]*$", output)
    secure = bool(cert and cert.group(1) not in ("<nil>", "null"))
    host = record["domain"] if secure and record.get("domain") else record["host"]
    authority = f"[{host}]" if ":" in host else host
    return {"panelPort": port, "panelPath": base, "panelTLS": secure,
            "panelUrl": f"{'https' if secure else 'http'}://{authority}:{port}{base}"}


class PanelAPI:
    """HTTP runs inside a host-key-verified SSH channel to remote loopback only."""

    def __init__(self, ssh, record, token, password="", session=None):
        self.ssh, self.record, self.token = ssh, record, token
        self.session = session if session is not None else {}
        self.cookies, self.csrf = dict(self.session.get("cookies", {})), self.session.get("csrf", "")
        self.password, self.logged_in = password, self.session.get("logged_in", False)
        self.legacy_csrf = self.session.get("legacy_csrf", False)
        self.api_prefix = self.session.get("api_prefix", "panel/api")
        self.web_prefix = self.session.get("web_prefix", "panel")

    def request(self, path, payload=None, *, method=None, bearer=True):
        try:
            return self._request(path, payload, method=method, bearer=bearer)
        except PanelSessionExpired:
            # Retry only an explicit authentication rejection, never a timeout,
            # HTML response, CSRF error or an ambiguous mutation failure.
            if path in ("login", "csrf-token"):
                raise ValueError("远端面板认证失败，请核对账号、密码和双因素验证设置") from None
            return self._request(path, payload, method=method, bearer=bearer)

    def _request(self, path, payload=None, *, method=None, bearer=True):
        if path == "login" and self.session.get("login_blocked_until", 0) > time.monotonic():
            raise ValueError("远端面板登录失败后已暂停重试 60 秒，请检查账号、密码及双因素验证；更新连接凭证可立即重试")
        if path == "login" and self.logged_in and payload == {"username": self.record["panelUser"], "password": self.password}:
            return None
        # Xray configuration routes are session-only, unlike /panel/api.
        if path.lstrip("/").startswith("panel/xray/") or (not self.token and path not in ("login", "csrf-token")):
            if not self.logged_in:
                self.request("login", {"username": self.record["panelUser"],
                                       "password": self.password}, bearer=False)
            bearer = False
        if not bearer and payload is not None and not self.csrf and not self.legacy_csrf:
            self.request("csrf-token", bearer=False)
            if not self.csrf and not self.legacy_csrf:
                raise ValueError("3x-ui 未返回登录 CSRF 令牌，暂不能验证预设账号")
        channel = self.ssh.get_transport().open_channel(
            "direct-tcpip", ("127.0.0.1", self.record["panelPort"]), ("127.0.0.1", 0), timeout=20)
        client, bridge = socket.socketpair()
        client.settimeout(30)

        def forward(source, destination):
            try:
                while True:
                    chunk = source.recv(32768)
                    if not chunk:
                        break
                    destination.sendall(chunk)
            except (OSError, EOFError):
                pass
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except (OSError, AttributeError):
                    pass

        threads = [threading.Thread(target=forward, args=(bridge, channel), daemon=True),
                   threading.Thread(target=forward, args=(channel, bridge), daemon=True)]
        for thread in threads:
            thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", self.record["panelPort"], timeout=30)
        try:
            if self.record.get("panelTLS"):
                # Peer authenticity comes from pinned SSH. TLS is only on the
                # authenticated remote loopback hop, never on an arbitrary URL.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                client = context.wrap_socket(client, server_hostname=(urlsplit(self.record["panelAddress"]).hostname if self.record.get("panelAddress") else self.record.get("domain") or self.record["host"]))
            connection.sock = client
            headers = {"X-Requested-With": "XMLHttpRequest", "Connection": "close"}
            hostname = urlsplit(self.record["panelAddress"]).hostname if self.record.get("panelAddress") else self.record.get("domain") or self.record["host"]
            headers["Host"] = (f"[{hostname}]" if ":" in hostname else hostname) + ":" + str(self.record["panelPort"])
            if self.cookies:
                headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in self.cookies.items())
            if self.csrf and not bearer:
                headers["X-CSRF-Token"] = self.csrf
            if bearer:
                headers["Authorization"] = "Bearer " + self.token
            body = None
            if payload is not None:
                body = urlencode({key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list))
                                  else str(value).lower() if isinstance(value, bool) else value
                                  for key, value in payload.items()}).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            remote_path = path.lstrip("/")
            if remote_path.startswith("panel/api/"):
                remote_path = self.api_prefix + remote_path[len("panel/api"):]
            elif remote_path.startswith("panel/xray/"):
                remote_path = self.web_prefix + remote_path[len("panel"):]
            connection.request(method or ("POST" if payload is not None else "GET"),
                               self.record["panelPath"].rstrip("/") + "/" + remote_path, body, headers)
            response = connection.getresponse()
            for header in response.headers.get_all("Set-Cookie", []):
                cookie = SimpleCookie()
                cookie.load(header)
                self.cookies.update({key: morsel.value for key, morsel in cookie.items()})
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("3x-ui 返回的数据超过 4 MB，请减少单面板入站数量")
            if response.status != 200:
                if response.status == 401 and not bearer:
                    self.cookies, self.csrf, self.logged_in = {}, "", False
                    if path == "login":
                        self.session["login_blocked_until"] = time.monotonic() + 60
                    raise PanelSessionExpired("远端面板登录会话已过期")
                if response.status == 404 and path == "csrf-token" and self.record.get("connectionMode") == "existing":
                    self.legacy_csrf = True
                    return None
                if response.status == 404 and path == "panel/api/inbounds/list" and install_type(self.record) == "x-ui" and self.api_prefix == "panel/api":
                    self.api_prefix, self.web_prefix = "xui/API", "xui"
                    return self.request(path, payload, method=method, bearer=False)
                raise ValueError(f"3x-ui 接口 HTTP {response.status}，请检查面板状态、访问路径和 API 令牌")
            try:
                result = json.loads(raw)
            except ValueError as exc:
                raise ValueError("3x-ui 返回非 JSON 内容，请确认面板版本和访问路径") from exc
            if not isinstance(result, dict) or result.get("success") is not True:
                if path == "login":
                    self.logged_in = False
                    self.session["login_blocked_until"] = time.monotonic() + 60
                message = str(result.get("msg", "接口操作未成功") if isinstance(result, dict) else "响应无效")
                raise ValueError("3x-ui：" + clean_log(message, [self.password, self.token, self.csrf, *self.cookies.values()])[:500])
            value = result.get("obj")
            if path == "csrf-token" and isinstance(value, str) and len(value) <= 256:
                self.csrf = value
            if path == "login":
                self.logged_in = True
                self.session.pop("login_blocked_until", None)
            return value
        finally:
            self.session.update(cookies=dict(self.cookies), csrf=self.csrf, logged_in=self.logged_in,
                                legacy_csrf=self.legacy_csrf, api_prefix=self.api_prefix, web_prefix=self.web_prefix)
            connection.close()
            client.close()
            channel.close()
            bridge.close()


class PanelSessionExpired(ValueError):
    pass


class RemoteManager:
    def __init__(self, root, parse_link, node_uri):
        self.panel_sessions = {}
        self.sni_cache, self.sni_slots = {}, {}
        _, Fernet = libraries()
        self.root = Path(root) / "remote"
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.path = self.root / "servers.json"
        key = self.root / "credentials.key"
        try:
            descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(Fernet.generate_key())
        self.cipher = Fernet(key.read_bytes())
        self.lock = threading.RLock()
        self.server_locks = {}
        self.parse_link, self.node_uri = parse_link, node_uri
        self.data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {"servers": [], "jobs": []}
        for job in self.data["jobs"]:
            if job["status"] == "running":
                job.update(status="interrupted", error="总面板已重启。远端安装进程可能仍在运行，请先诊断后再重试。", finishedAt=int(time.time()))
        self.flush()

    def flush(self):
        temporary = self.path.with_name(".servers-" + secrets.token_hex(6))
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(self.data, stream, ensure_ascii=False)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def seal(self, value):
        return self.cipher.encrypt(str(value).encode()).decode()

    def secret(self, record, key):
        try:
            return self.cipher.decrypt(record[key].encode()).decode()
        except Exception as exc:
            raise ValueError("服务器凭证解密失败，请检查 credentials.key 或重新填写凭证") from exc

    def record(self, server_id):
        item = next((x for x in self.data["servers"] if x["id"] == str(server_id)), None)
        if not item:
            raise ValueError("服务器不存在")
        return item

    def public(self, record):
        keys = ("id", "name", "host", "sshPort", "sshUser", "fingerprint", "domain", "panelUser",
                "panelAddress", "panelUrl", "panelPort", "panelPath", "panelTLS", "createdAt", "lastError", "connectionMode", "existingVerifiedAt")
        result = {key: record.get(key) for key in keys}
        result["installType"] = install_type(record)
        result["hasCoreConfig"] = bool(record.get("coreConfig"))
        jobs = [x for x in self.data["jobs"] if x["serverId"] == record["id"]
                and x.get("installType", "3x-ui") == install_type(record)]
        if jobs:
            result["job"] = {k: jobs[-1].get(k) for k in ("id", "status", "stage", "error", "startedAt", "finishedAt")}
        result["hasSSHPassword"] = bool(record.get("sshPassword"))
        result["hasPanelPassword"] = install_type(record) in PANEL_TYPES and bool(record.get("panelPassword"))
        return result

    def list(self):
        with self.lock:
            return [self.public(record) for record in self.data["servers"]]

    def save(self, payload):
        with self.lock:
            existing = self.record(payload["id"]) if payload.get("id") else None
            if existing and self.server_locks.get(existing["id"], threading.Lock()).locked():
                raise ValueError("该服务器正在处理节点操作，请稍后修改连接信息")
            if existing and any(j["serverId"] == existing["id"] and j["status"] == "running" for j in self.data["jobs"]):
                raise ValueError("安装过程中不能修改服务器连接信息")
            record = copy.deepcopy(existing) if existing else {"id": secrets.token_hex(12), "createdAt": int(time.time())}
            record["connectionMode"] = payload.get("connectionMode", record.get("connectionMode", "install"))
            if record["connectionMode"] not in ("install", "existing"):
                raise ValueError("服务器接入模式无效")
            if existing and existing.get("bandwidths"):
                if (str(payload.get("host", existing["host"])) != existing["host"]
                        or int(payload.get("sshPort", existing["sshPort"])) != existing["sshPort"]
                        or payload.get("installType", install_type(existing)) != install_type(existing)):
                    raise ValueError("服务器仍有节点限速，请先取消限速再修改地址或内核类型")
            previous_type = install_type(record)
            record["installType"] = payload.get("installType", previous_type)
            kind = install_type(record)
            if kind in ("x-ui", "x-panel") and record["connectionMode"] != "existing":
                raise ValueError("X-ui / X-Panel 请使用接入现有面板模式，不运行交互式第三方安装器")
            if kind != previous_type:
                for key in ("panelAddress", "panelUrl", "panelPort", "panelPath", "panelTLS", "managed", "lastXrayBackup", "coreConfig", "coreState", "meters", "bandwidths", "relays"):
                    record.pop(key, None)
            panel_address = payload.get("panelAddress", record.get("panelAddress", ""))
            if panel_address:
                if record["connectionMode"] != "existing" or kind not in PANEL_TYPES:
                    raise ValueError("面板完整地址仅用于接入已安装的面板")
                settings = parse_panel_address(panel_address)
                record.update(settings)
                record["panelAddress"] = settings["panelUrl"]
            else:
                record.pop("panelAddress", None)
            if kind not in PANEL_TYPES:
                if payload.get("domain"):
                    raise ValueError("独立内核的域名和 TLS 请在内核 JSON 配置中设置")
                raw = payload.get("coreConfig", "")
                if not isinstance(raw, str) or len(raw.encode()) > 128 * 1024:
                    raise ValueError("内核配置必须是 128 KB 以内的 JSON")
                if raw.strip():
                    if record["connectionMode"] == "existing":
                        raise ValueError("接入已有内核时读取远端现有配置，请勿提交安装用 JSON 配置")
                    try:
                        config = json.loads(raw)
                    except ValueError as exc:
                        raise ValueError("内核配置不是有效 JSON") from exc
                    if not isinstance(config, dict) or not isinstance(config.get("inbounds"), list) or not isinstance(config.get("outbounds"), list):
                        raise ValueError("内核配置需包含 inbounds 和 outbounds 数组")
                    record["coreConfig"] = self.seal(raw)
                elif payload.get("clearCoreConfig") is True:
                    record.pop("coreConfig", None)
            record.pop("existingVerifiedAt", None)
            for key, value in {"host": valid_ip(payload.get("host")), "sshPort": valid_port(payload.get("sshPort", 22)),
                               "name": text(payload.get("name"), "服务器名称", maximum=80),
                               "sshUser": text(payload.get("sshUser"), "SSH 用户名", maximum=64),
                               "domain": valid_domain(payload.get("domain")),
                               "panelUser": text(payload.get("panelUser") if kind in PANEL_TYPES else "unused", "面板用户名", 1 if record["connectionMode"] == "existing" else 3, 64)}.items():
                record[key] = value
            pin = str(payload.get("fingerprint", ""))
            if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", pin):
                raise ValueError("请先检测并核对 SSH 主机指纹")
            record["fingerprint"] = pin
            if existing and (existing["host"], existing["sshPort"]) != (record["host"], record["sshPort"]):
                for key in ("panelUrl", "panelPort", "panelPath", "panelTLS", "managed", "lastXrayBackup"):
                    record.pop(key, None)
            if any(item["id"] != record["id"] and (item["host"], item["sshPort"]) == (record["host"], record["sshPort"])
                   for item in self.data["servers"]):
                raise ValueError("该 IP 与 SSH 端口已登记，请编辑现有服务器")
            for key, label, minimum in (("sshPassword", "SSH 密码", 1), ("panelPassword", "面板密码", 12)):
                if key == "panelPassword" and kind not in PANEL_TYPES:
                    record[key] = self.seal("")
                    continue
                if key == "panelPassword" and record["connectionMode"] == "existing":
                    minimum = 1
                if payload.get(key):
                    record[key] = self.seal(text(payload[key], label, minimum))
                elif not record.get(key):
                    raise ValueError(f"请填写{label}")
            if existing:
                existing.clear()
                existing.update(record)
            else:
                self.data["servers"].append(record)
            self.flush()
            return self.public(record)

    def remove(self, server_id, *, detach=False):
        with self.lock:
            if self.record(server_id).get("bandwidths") and not detach:
                raise ValueError("服务器仍有节点限速，请先取消限速再移除服务器")
            if self.server_locks.get(server_id, threading.Lock()).locked():
                raise ValueError("该服务器正在处理节点操作，请稍后移除")
            if any(j["serverId"] == server_id and j["status"] == "running" for j in self.data["jobs"]):
                raise ValueError("请等待安装任务结束再移除管理")
            self.data["servers"] = [x for x in self.data["servers"] if x["id"] != server_id]
            self.data["jobs"] = [x for x in self.data["jobs"] if x["serverId"] != server_id]
            self.panel_sessions.pop(server_id, None)
            self.flush()

    def probe(self, payload):
        paramiko, _ = libraries()
        connection = socket.create_connection((valid_ip(payload.get("host")), valid_port(payload.get("sshPort", 22))), timeout=10)
        transport = paramiko.Transport(connection)
        try:
            transport.start_client(timeout=10)
            return {"fingerprint": fingerprint(transport.get_remote_server_key())}
        finally:
            transport.close()
            connection.close()

    def connect(self, record):
        paramiko, _ = libraries()

        class PinnedKey(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                if not secrets.compare_digest(fingerprint(key), record["fingerprint"]):
                    raise ValueError("SSH 主机指纹发生变化，已停止连接；请核对服务器后重新检测指纹")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(PinnedKey())
        try:
            ssh.connect(record["host"], port=record["sshPort"], username=record["sshUser"],
                        password=self.secret(record, "sshPassword"), look_for_keys=False, allow_agent=False,
                        timeout=12, auth_timeout=15, banner_timeout=15)
            ssh.get_transport().set_keepalive(25)
            return ssh
        except paramiko.AuthenticationException as exc:
            ssh.close()
            raise ValueError("SSH 认证失败，请检查账号、密码以及服务器是否允许密码登录") from exc
        except Exception:
            ssh.close()
            raise

    def execute(self, ssh, record, script, *, timeout=60, on_line=None, max_output=MAX_LOG * 2):
        sudo = record["sshUser"] != "root"
        stdin, stdout, _ = ssh.exec_command("sudo -S -p '' bash -s" if sudo else "bash -s", timeout=20)
        channel = stdout.channel
        channel.set_combine_stderr(True)
        write_error = None
        try:
            stdin.write((self.secret(record, "sshPassword") + "\n" if sudo else "") + script + "\n")
            stdin.flush()
            channel.shutdown_write()
        except (OSError, EOFError) as exc:
            write_error = exc
        deadline, pending, output = time.monotonic() + timeout, b"", bytearray()
        try:
            while True:
                if time.monotonic() > deadline:
                    raise ValueError("远端命令超时；安装可能仍在运行，请先读取诊断信息后再重试")
                if channel.recv_ready():
                    chunk = channel.recv(8192)
                    output.extend(chunk)
                    if len(output) > max_output:
                        if max_output != MAX_LOG * 2:
                            raise ValueError("远端配置超过支持的读取大小")
                        del output[:-max_output]
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        if on_line:
                            on_line(line.decode("utf-8", errors="replace") + "\n")
                    if len(pending) > MAX_LOG:
                        raise ValueError("远端输出单行异常过长，已停止读取")
                elif channel.exit_status_ready():
                    break
                else:
                    time.sleep(.08)
            if pending and on_line:
                on_line(pending.decode("utf-8", errors="replace"))
            code = channel.recv_exit_status()
            if code == 0 and write_error is not None:
                raise ValueError("SSH 在发送命令时断开，请检查远端 Shell 和 sudo 状态") from write_error
            return code, output.decode("utf-8", errors="replace")
        finally:
            channel.close()
            stdin.close()
            stdout.close()

    def diagnostics(self, record, ssh=None):
        own = ssh is None
        ssh = ssh or self.connect(record)
        try:
            service = "x-ui" if install_type(record) in PANEL_TYPES else install_type(record)
            _, output = self.execute(ssh, record, """set +e
echo '=== Service ==='
if command -v systemctl >/dev/null; then systemctl status x-ui --no-pager -l; journalctl -u x-ui -n 45 --no-pager; else rc-service x-ui status; fi
echo '=== Listeners ==='
ss -lntup 2>/dev/null | head -35
echo '=== DNS ==='
""".replace("x-ui", service) + ("getent ahosts " + shlex.quote(record["domain"]) if record.get("domain") else "true"), timeout=40)
            return clean_log(output, [self.secret(record, "sshPassword"), self.secret(record, "panelPassword")])[-MAX_LOG:]
        finally:
            if own:
                ssh.close()

    def panel(self, ssh, record):
        if install_type(record) not in PANEL_TYPES:
            from core_adapter import CoreAPI
            return CoreAPI(self, ssh, record)
        if record.get("connectionMode") == "existing" and record.get("panelAddress"):
            settings = parse_panel_address(record["panelAddress"])
        elif install_type(record) == "x-panel":
            # X-Panel's `setting` command initializes/migrates its database even
            # for queries. Never launch that CLI against a running panel.
            script = """python3 - <<'MXIOC_PANEL_READONLY'
import json, os, sqlite3
from pathlib import Path
paths = [Path(os.environ.get('XUI_DB_FOLDER', '/etc/x-ui')) / 'x-ui.db', Path('/usr/local/x-ui/x-ui.db')]
for path in paths:
    if not path.is_file():
        continue
    with sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5) as db:
        db.execute('PRAGMA query_only=ON')
        values = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('webPort','webBasePath','webCertFile','webKeyFile','webDomain')"))
    print(json.dumps(values))
    break
else:
    raise SystemExit('Panel database not found; configure the complete existing panel URL')
MXIOC_PANEL_READONLY"""
            code, raw = self.execute(ssh, record, script, timeout=20)
            if code:
                raise ValueError("X-Panel 只读配置读取失败，请在连接设置填写现有面板完整地址（含端口及路径）")
            values = json_object(raw)
            domain = valid_domain(values.get("webDomain") or record.get("domain"))
            record["domain"] = domain
            settings = parse_panel_settings("port: " + str(values.get("webPort", 13688)) + "\nwebBasePath: " +
                                            str(values.get("webBasePath", "/")) + "\ncert: " +
                                            str(values.get("webCertFile", "")) + "\n", record)
        else:
            code, output = self.execute(ssh, record, "cd /usr/local/x-ui && ./x-ui setting -show true && { ./x-ui setting -getCert true 2>/dev/null || true; }", timeout=30)
            if code:
                raise ValueError("未能读取 /usr/local/x-ui 面板设置，请检查安装位置、版本兼容性及 SSH 提权权限")
            settings = parse_panel_settings(output, record)
        with self.lock:
            self.record(record["id"]).update(settings)
            self.flush()
        record.update(settings)
        if install_type(record) == "x-panel":
            # Keep credentials/cookies exclusively in controller memory. Binding
            # includes SSH identity and the exact panel endpoint, not just IP.
            identity = hashlib.sha256(json.dumps([record.get(key) for key in (
                "host", "sshPort", "sshUser", "sshPassword", "fingerprint", "panelUser", "panelPassword",
                "panelPort", "panelPath", "panelTLS", "panelAddress", "domain")], sort_keys=True).encode()).hexdigest()
            with self.lock:
                cached = self.panel_sessions.get(record["id"])
                if not cached or cached["identity"] != identity:
                    cached = {"identity": identity, "state": {}}
                    self.panel_sessions[record["id"]] = cached
                self.panel_sessions[record["id"]] = self.panel_sessions.pop(record["id"])
                while len(self.panel_sessions) > 128:
                    self.panel_sessions.pop(next(iter(self.panel_sessions)))
            return PanelAPI(ssh, record, "", self.secret(record, "panelPassword"), cached["state"])
        code, output = self.execute(ssh, record, "cd /usr/local/x-ui && ./x-ui setting -getApiToken true", timeout=30)
        token = re.search(r"(?m)^apiToken:[ \t]*(\S+)", output)
        if (code or not token) and record.get("connectionMode") != "existing":
            raise ValueError("无法读取 3x-ui API 令牌，请确认使用指定的 Teminuosi/3x-ui 分支")
        api = PanelAPI(ssh, record, token.group(1) if token else "", self.secret(record, "panelPassword"))
        if install_type(record) == "x-ui":
            api.request("panel/api/inbounds/list")
        return api

    def attach_existing(self, server_id):
        def action(api, record):
            kind = install_type(record)
            if kind not in PANEL_TYPES:
                check = "run -test -config" if kind == "xray" else "check -c"
                script = f"{api.binary} version && {api.binary} {check} {api.path} && systemctl is-active --quiet {kind}"
                code, output = self.execute(api.ssh, record, script, timeout=30)
                if code:
                    raise ValueError(f"已有 {kind} 验证失败，请检查内核程序、配置 {api.path} 和 systemd 服务：{output[-2000:]}")
                rows = api.request("panel/api/inbounds/list")
                with self.lock:
                    self.record(server_id)["existingVerifiedAt"] = int(time.time())
                    self.flush()
                return {"server": self.public(self.record(server_id)),
                        "message": f"已有 {kind} 验证成功，发现 {len(api.native.get('inbounds', []))} 个原生入站、{len(rows)} 个总控受管入站；未安装、重启或修改远端配置。原生未受管入站不会自动导入"}
            api.request("login", {"username": record["panelUser"],
                                   "password": self.secret(record, "panelPassword")}, bearer=False)
            rows = api.request("panel/api/inbounds/list")
            if not isinstance(rows, list):
                raise ValueError("现有面板入站接口不兼容，未完成接入；请检查 X-ui 版本")
            with self.lock:
                self.record(server_id)["existingVerifiedAt"] = int(time.time())
                self.flush()
            return {"server": self.public(self.record(server_id)), "message": f"现有面板验证成功，发现 {len(rows)} 个入站；未执行安装或更改远端配置"}
        return self.with_panel(server_id, action)

    def test(self, server_id):
        record = copy.deepcopy(self.record(server_id))
        ssh = self.connect(record)
        try:
            code, _ = self.execute(ssh, record, "test $(id -u) = 0", timeout=20)
            if code:
                raise ValueError("SSH 已连接，但账号没有 root/sudo 执行权限")
            return {"connected": True, "message": "SSH 和提权权限检查通过"}
        finally:
            ssh.close()

    def job(self, job_id):
        with self.lock:
            item = next((j for j in self.data["jobs"] if j["id"] == job_id), None)
            if not item:
                raise ValueError("安装任务不存在")
            return copy.deepcopy(item)

    def start_install(self, server_id, confirmed):
        if confirmed is not True:
            raise ValueError("请确认在该服务器安装/更新所选软件")
        with self.lock:
            record = copy.deepcopy(self.record(server_id))
            if record.get("connectionMode") == "existing":
                raise ValueError("已有软件接入模式不会执行安装或更新脚本")
            self.secret(record, "sshPassword")
            self.secret(record, "panelPassword")
            if self.server_locks.get(server_id, threading.Lock()).locked():
                raise ValueError("该服务器正在处理节点操作，请稍后安装")
            running = [j for j in self.data["jobs"] if j["status"] == "running"]
            if any(j["serverId"] == server_id for j in running):
                raise ValueError("该服务器已有安装任务正在运行")
            if len(running) >= 2:
                raise ValueError("已有两个安装任务运行，请等待其中一个结束")
            job = {"id": secrets.token_hex(12), "serverId": server_id, "status": "running",
                   "installType": install_type(record), "stage": "connecting", "startedAt": int(time.time()), "log": "", "error": ""}
            self.data["jobs"] = [j for j in self.data["jobs"] if j["status"] == "running"] + [
                j for j in self.data["jobs"] if j["status"] != "running"][-47:]
            self.data["jobs"].append(job)
            self.flush()
            threading.Thread(target=self.install_worker, args=(record, job), daemon=True).start()
            return copy.deepcopy(job)

    def install_worker(self, record, job):
        ssh, last_flush = None, [0]
        secret_values = [self.secret(record, "sshPassword"), self.secret(record, "panelPassword")]

        def log(line):
            with self.lock:
                match = re.search(r"MXIOC_STAGE=(\w+)", line)
                if match:
                    job["stage"] = match.group(1)
                job["log"] = (job["log"] + clean_log(line, secret_values))[-MAX_LOG:]
                if time.monotonic() - last_flush[0] > 1:
                    self.flush()
                    last_flush[0] = time.monotonic()

        try:
            ssh = self.connect(record)
            log("SSH 已连接，开始安装。\n")
            script_record = copy.deepcopy(record)
            if script_record.get("coreConfig"):
                script_record["coreConfig"] = self.secret(record, "coreConfig")
                secret_values.append(script_record["coreConfig"])
            code, _ = self.execute(ssh, record, install_script(script_record, secret_values[1]), timeout=2700, on_line=log)
            job["exitCode"] = code
            if code:
                raise ValueError(installation_error(job["log"], job["stage"], code))
            if install_type(record) not in PANEL_TYPES:
                with self.lock:
                    job.update(status="succeeded", stage="complete")
                    self.record(record["id"])["lastError"] = ""
                log("内核安装、配置校验和 systemd 服务检查已通过。节点由内核 JSON 配置管理。\n")
                return
            job["stage"] = "api-check"
            for attempt in range(15):
                try:
                    api = self.panel(ssh, record)
                    api.request("login", {"username": record["panelUser"], "password": secret_values[1]}, bearer=False)
                    api.request("panel/api/inbounds/list")
                    break
                except (OSError, EOFError, http.client.HTTPException):
                    if attempt == 14:
                        raise
                    time.sleep(2)
            if record.get("domain") and not record.get("panelTLS"):
                raise ValueError("面板已安装，但域名 HTTPS 证书未配置成功；请检查域名解析、80 端口和证书日志")
            with self.lock:
                job.update(status="succeeded", stage="complete", panelUrl=record["panelUrl"])
                self.record(record["id"])["lastError"] = ""
            log("安装、预设凭证登录和 API 验证均已通过。\n")
        except Exception as exc:
            message = clean_log(str(exc), secret_values)
            with self.lock:
                job.update(stage="diagnostics", error=message)
                self.record(record["id"])["lastError"] = message
                if record.get("panelUrl"):
                    job["panelUrl"] = record["panelUrl"]
            log("\n失败原因：" + message + "\n")
            if ssh:
                if install_type(record) in PANEL_TYPES and not record.get("panelUrl"):
                    try:
                        self.panel(ssh, record)
                    except Exception:
                        pass
                    if record.get("panelUrl"):
                        job["panelUrl"] = record["panelUrl"]
                try:
                    log("\n=== 自动诊断 ===\n" + self.diagnostics(record, ssh))
                except Exception as diagnostic_error:
                    log("诊断读取失败：" + str(diagnostic_error) + "\n")
        finally:
            if ssh:
                ssh.close()
            with self.lock:
                if job["status"] == "running":
                    job["status"] = "failed"
                job["finishedAt"] = int(time.time())
                self.flush()

    def with_panel(self, server_id, action):
        with self.lock:
            record = copy.deepcopy(self.record(server_id))
            if any(j["serverId"] == server_id and j["status"] == "running" for j in self.data["jobs"]):
                raise ValueError("请等待安装任务完成后再操作节点")
            operation_lock = self.server_locks.setdefault(server_id, threading.Lock())
        if not operation_lock.acquire(blocking=False):
            raise ValueError("该服务器正在处理其他操作，请稍后重试")
        ssh = None
        try:
            ssh = self.connect(record)
            return action(self.panel(ssh, record), record)
        except Exception as exc:
            raise ValueError(clean_log(str(exc), [self.secret(record, "sshPassword"), self.secret(record, "panelPassword")])) from exc
        finally:
            if ssh:
                ssh.close()
            operation_lock.release()

    def inbounds(self, server_id):
        def action(api, record):
            rows = api.request("panel/api/inbounds/list") or []
            if not isinstance(rows, list):
                raise ValueError("3x-ui 入站列表格式无效")
            counts = self.meter_snapshot(record, api.ssh) if record.get("meters") else {}
            for row in rows:
                if row.get("id") in counts:
                    row.update(counts[row["id"]])
                if not isinstance(row, dict):
                    raise ValueError("3x-ui 入站记录格式无效")
                row["id"] = positive_id(row.get("id"))
                row["port"] = valid_port(row.get("port"))
                for field in ("up", "down"):
                    if type(row.get(field, 0)) is not int or row.get(field, 0) < 0:
                        raise ValueError("3x-ui 流量字段无效")
                row["shareLinks"] = []
                try:
                    row["shareLinks"] = [self.node_uri(n) for n in inbound_nodes(row, record)]
                except (ValueError, KeyError, TypeError):
                    pass
            return {"inbounds": rows, "server": self.public(self.record(server_id))}
        return self.with_panel(server_id, action)

    def disconnect_port(self, server_id, port):
        """Remove established TCP sockets for a dedicated revoked inbound."""
        port = valid_port(port)
        record = copy.deepcopy(self.record(server_id))
        ssh = self.connect(record)
        try:
            code, _ = self.execute(ssh, record, f"command -v ss >/dev/null && ss -K -t sport = :{port}", timeout=20)
            if code:
                raise ValueError("入站已删除，但清理存量 TCP 连接失败；请安装 iproute2 并检查 root/sudo 权限，后台会重试")
        finally:
            ssh.close()

    def _write_bandwidth(self, api, record, policies):
        from bandwidth import apply_script
        code, output = self.execute(api.ssh, record, apply_script(policies), timeout=45)
        if code:
            raise ValueError("服务器限速应用失败，请检查 nftables、systemd 和 root 权限；已有规则会尝试恢复：" + output[-1000:])
        with self.lock:
            self.record(record["id"])["bandwidths"] = copy.deepcopy(policies)
            try:
                self.flush()
            except Exception as exc:
                raise ValueError("远端限速已应用，但总控记录保存失败，请重试以同步状态") from exc
        record["bandwidths"] = copy.deepcopy(policies)

    def set_bandwidth(self, server_id, inbound_id, upload_kbps, download_kbps):
        from bandwidth import policy
        inbound_id = positive_id(inbound_id)
        def action(api, record):
            policies = copy.deepcopy(record.get("bandwidths", {}))
            if upload_kbps or download_kbps:
                rows = api.request("panel/api/inbounds/list") or []
                row = next((r for r in rows if r["id"] == inbound_id), None)
                if not row:
                    raise ValueError("待限速的入站不存在")
                settings = json_object(row.get("settings") or {})
                if len(settings.get("clients", [])) > 1:
                    raise ValueError("共用入站不能按单个用户限速，请创建专属入站")
                configured = policy(row, upload_kbps, download_kbps)
                if any(r["id"] != inbound_id and r.get("port") == row["port"] for r in rows):
                    raise ValueError("该端口有其他入站使用，不能对单个节点实施端口限速")
                if 'tcp' in configured['protocols'] and configured['port'] in (record['sshPort'], record.get('panelPort')):
                    raise ValueError("节点端口与 SSH 或面板管理端口重合，不能应用限速")
                policies[str(inbound_id)] = configured
            else:
                configured = {"uploadKbps": 0, "downloadKbps": 0}
                policies.pop(str(inbound_id), None)
            self._write_bandwidth(api, record, policies)
            return {**configured, "appliedAt": int(time.time()), "mode": "policing"}
        return self.with_panel(server_id, action)

    def ensure_meter(self, server_id, inbound_id):
        """Explicitly provision host counters before accepting a metered binding."""
        inbound_id = positive_id(inbound_id)
        # Panels already expose native counters; no remote setup or SSH is needed.
        with self.lock:
            if install_type(self.record(server_id)) in PANEL_TYPES:
                return
        def action(api, record):
            row = next((r for r in api.request("panel/api/inbounds/list") if r["id"] == inbound_id), None)
            if not row:
                raise ValueError("入站不存在")
            port = valid_port(row["port"])
            script = f"""set -Eeuo pipefail
command -v nft >/dev/null || {{ echo 'Install nftables first to enable standalone core traffic accounting'; exit 12; }}
exec 8>/var/lock/mxioc-meter.lock
flock -n 8 || exit 75
if ! nft list table inet mxioc_usage >/dev/null 2>&1; then
  nft -f - <<'NFT'
add table inet mxioc_usage
add chain inet mxioc_usage input {{ type filter hook input priority -10; policy accept; }}
add chain inet mxioc_usage output {{ type filter hook output priority -10; policy accept; }}
NFT
fi
if ! nft list counter inet mxioc_usage up_{inbound_id} >/dev/null 2>&1; then
  nft -f - <<'NFT'
add counter inet mxioc_usage up_{inbound_id}
add counter inet mxioc_usage down_{inbound_id}
add rule inet mxioc_usage input meta l4proto {{ tcp, udp }} th dport {port} counter name up_{inbound_id}
add rule inet mxioc_usage output meta l4proto {{ tcp, udp }} th sport {port} counter name down_{inbound_id}
NFT
fi
mkdir -p /etc/mxioc-meter
nft -s list table inet mxioc_usage > /etc/mxioc-meter/rules.nft.tmp
chmod 600 /etc/mxioc-meter/rules.nft.tmp
mv /etc/mxioc-meter/rules.nft.tmp /etc/mxioc-meter/rules.nft
cat > /etc/systemd/system/mxioc-meter-restore.service <<'UNIT'
[Unit]
Description=Restore MXIOC dedicated inbound accounting rules
Before=xray.service sing-box.service
After=nftables.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'nft list table inet mxioc_usage >/dev/null 2>&1 || nft -f /etc/mxioc-meter/rules.nft'
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable mxioc-meter-restore.service
"""
            code, _ = self.execute(api.ssh, record, script, timeout=30)
            if code:
                raise ValueError("独立内核计量初始化失败，请先安装 nftables；不能在无法计量时启用流量限制")
            with self.lock:
                self.record(server_id).setdefault("meters", {})[str(inbound_id)] = port
                self.flush()
        return self.with_panel(server_id, action)

    def meter_snapshot(self, record, ssh):
        code, raw = self.execute(ssh, record, "nft -j list table inet mxioc_usage", timeout=20)
        if code:
            raise ValueError("内核计量规则丢失，流量不可核实；请重新绑定节点以恢复计量")
        values = {}
        for entry in json.loads(raw).get("nftables", []):
            counter = entry.get("counter", {})
            match = re.fullmatch(r"(up|down)_(\d+)", counter.get("name", ""))
            if match and match.group(2) in record.get("meters", {}):
                values.setdefault(int(match.group(2)), {})[match.group(1)] = counter.get("bytes", 0)
        for identity in record.get("meters", {}):
            if set(values.get(int(identity), {})) != {"up", "down"}:
                raise ValueError("内核计量计数器缺失，不能将用量当作零")
        return values

    def test_sni(self, server_id, candidates, force=False):
        if not isinstance(candidates, list) or not 1 <= len(candidates) <= 20:
            raise ValueError("每次测试 1–20 个 SNI 域名")
        domains = list(dict.fromkeys(valid_domain(x) for x in candidates))
        if any(not x for x in domains):
            raise ValueError("SNI 域名不能为空")
        record = copy.deepcopy(self.record(server_id))
        ssh = self.connect(record)
        probe = r'''import concurrent.futures, ipaddress, json, socket, ssl, time
names = json.loads(__import__('base64').b64decode('CANDIDATES'))
def probe(name):
    start = time.monotonic()
    result = {"domain": name, "ok": False}
    try:
        addresses = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError("目标解析为非公网地址")
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2', 'http/1.1'])
        # Preserve the server resolver's route preference, but try another public
        # endpoint if its first IPv4/IPv6 address is unreachable.
        unique = list({(a[0], a[4][0]): a for a in addresses}.values())
        failure = None
        for family, socktype, proto, _, address in unique[:3]:
            try:
                attempt = time.monotonic()
                with socket.socket(family, socktype, proto) as raw:
                    raw.settimeout(4)
                    raw.connect(address)
                    with context.wrap_socket(raw, server_hostname=name) as tls:
                        result.update(ok=True, latencyMs=round((time.monotonic()-attempt)*1000, 1),
                                      tls=tls.version(), alpn=tls.selected_alpn_protocol(), address=address[0])
                break
            except Exception as exc:
                failure = exc
        if not result['ok']:
            raise failure or ValueError('目标没有可用的公网 TLS 地址')
    except Exception as exc:
        result['error'] = str(exc)[:180]
    return result
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
    rows = list(pool.map(probe, names))
print(json.dumps(sorted(rows, key=lambda x: x.get('latencyMs', 1e9))))
'''
        encoded = base64.b64encode(json.dumps(domains).encode()).decode()
        try:
            code, raw = self.execute(ssh, record, "python3 - <<'MXIOC_SNI'\n" + probe.replace('CANDIDATES', encoded) + "\nMXIOC_SNI", timeout=40)
            if code:
                result = self.test_sni_curl(ssh, record, domains)
            else:
                result = {"results": json.loads(raw)}
            return self.verify_reality_snis(ssh, record, result, force=True) if force else self.verify_reality_snis(ssh, record, result)
        finally:
            ssh.close()

    def test_sni_curl(self, ssh, record, domains):
        """Python-free fallback. Resolve on the server, validate and pin public IPs."""
        import concurrent.futures
        resolver = "command -v curl >/dev/null && command -v getent >/dev/null && command -v timeout >/dev/null || exit 12\n"
        for offset in range(0, len(domains), 4):
            resolver += "pids=''\n"
            for domain in domains[offset:offset + 4]:
                resolver += "timeout 3 getent ahosts " + shlex.quote(domain) + " | awk -v host=" + shlex.quote(domain) + " '{print host, $1}' &\npids=\"$pids $!\"\n"
            resolver += 'for pid in $pids; do wait "$pid" || true; done\n'
        code, raw = self.execute(ssh, record, resolver, timeout=25)
        if code:
            raise ValueError("无 Python 扫描需要 curl、getent 和系统 CA；请安装系统网络工具后重试")
        addresses = {name: set() for name in domains}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in addresses:
                try:
                    addresses[parts[0]].add(ipaddress.ip_address(parts[1]))
                except ValueError:
                    pass
        def probe(domain):
            result = {"domain": domain, "ok": False, "method": "curl"}
            values = addresses[domain]
            if not values or any(not address.is_global for address in values):
                result["error"] = "目标未解析到公网地址或解析含非公网地址"
                return result
            for candidate in sorted(values, key=lambda a: (a.version, int(a)))[:3]:
                address = str(candidate)
                pinned = '[' + address + ']' if ':' in address else address
                command = "curl --disable --silent --show-error --head --output /dev/null --noproxy '*' --proto '=https' --tlsv1.3 --tls-max 1.3 --connect-timeout 4 --max-time 6 --resolve " + shlex.quote(domain + ':443:' + pinned) + " --write-out '%{time_appconnect}' " + shlex.quote('https://' + domain + '/')
                try:
                    code, output = self.execute(ssh, record, command, timeout=10)
                    if code:
                        result["error"] = "TLS 1.3 握手或证书校验失败：" + output[:160]
                    else:
                        result.update(ok=True, tls="TLSv1.3", latencyMs=round(float(output.strip()) * 1000, 1), address=address)
                        result.pop('error', None)
                        break
                except Exception as exc:
                    result["error"] = str(exc)[:160]
            return result
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            rows = list(pool.map(probe, domains))
        return {"results": sorted(rows, key=lambda row: row.get("latencyMs", 1e9)), "method": "curl"}

    def verify_reality_snis(self, ssh, record, result, force=False):
        from reality_probe import probe_batch_script
        with self.lock:
            slots = self.sni_slots.setdefault(record['id'], threading.BoundedSemaphore(2))
            if force:
                domains = {row['domain'] for row in result['results']}
                for key in list(self.sni_cache):
                    if key[:2] == (record['id'], record.get('fingerprint')) and key[2] in domains:
                        del self.sni_cache[key]
        pending = []
        rows = [dict(row) for row in result['results']]
        for row in rows:
            row['realityVerified'] = False
            if not row.get('ok'):
                continue
            row['ok'] = False
            if install_type(record) == 'sing-box':
                row['error'] = '当前 sing-box 尚无实际 Reality 验证器，未列入可选结果'
                continue
            address = row.get('address')
            try:
                if not address or not ipaddress.ip_address(address).is_global:
                    raise ValueError('缺少已验证的公网目标地址')
                key = (record['id'], record.get('fingerprint'), row['domain'], address)
                with self.lock:
                    cached = self.sni_cache.get(key)
                if not force and cached and time.monotonic() - cached[0] < (600 if cached[1] else 15):
                    row.update(ok=cached[1], realityVerified=cached[1], cached=True)
                else:
                    pending.append((row, key))
            except Exception as exc:
                row['error'] = 'Reality 验证未完成：' + str(exc)[:160]
        if pending:
            try:
                with slots:
                    for attempt in range(2):
                        script = probe_batch_script([(row['domain'], key[3]) for row, key in pending])
                        code, output = self.execute(ssh, record, script, timeout=80)
                        if code != 17:
                            break
                if code:
                    raise ValueError({12:'服务器缺少 curl 或 timeout', 13:'服务器未安装可用的 Xray 验证内核',
                                      16:'隔离测试内核启动失败，请重试扫描',
                                      17:'随机测试端口已被占用，未触碰现有服务，请重试扫描'}.get(code, '隔离 Reality 批量实测未完成，请重试'))
                readings = {int(index): value == 'OK' for index, value in re.findall(r'^MXIOC_REALITY_RESULT (\d+) (OK|FAIL)$', output, re.M)}
                for index, (row, key) in enumerate(pending):
                    if index not in readings:
                        row['error'] = '隔离测试未返回此目标结果，请重试'
                        continue
                    verified = readings[index]
                    row.update(ok=verified, realityVerified=verified)
                    with self.lock:
                        if len(self.sni_cache) >= 2048:
                            self.sni_cache.pop(next(iter(self.sni_cache)))
                        self.sni_cache[key] = (time.monotonic(), verified)
            except Exception as exc:
                for row, _ in pending:
                    row['error'] = 'Reality 验证未完成：' + str(exc)[:160]
        for row in rows:
            if row.get('ok') and row.get('realityVerified'):
                row['verifiedAddress'] = row['address']
            elif not row.get('error'):
                row['error'] = 'TLS 可连接，但两次实际 Reality 握手未通过；不提供选择'
            row.pop('address', None)
        result['results'] = rows
        return result

    def create_inbound(self, server_id, payload):
        def action(api, record):
            body = prepare_inbound(payload["inbound"]) if "inbound" in payload else build_inbound(api, self.verified_template_payload(record, payload))
            created = api.request("panel/api/inbounds/add", body)
            if not isinstance(created, dict) or not created.get("id"):
                raise ValueError("3x-ui 返回的新增入站结果缺少 ID，请刷新列表核对，勿重复提交")
            created["id"] = positive_id(created["id"])
            result = {"inbound": created, "shareLinks": []}
            try:
                result["shareLinks"] = [self.node_uri(n) for n in inbound_nodes(created, record)]
            except (ValueError, KeyError, TypeError):
                pass
            return result
        return self.with_panel(server_id, action)

    def verified_template_payload(self, record, payload):
        """Use the actual public endpoint that passed the scan, not a fresh DNS pick."""
        result = dict(payload)
        result.pop('_verifiedRealityAddress', None)
        if result.get('template', 'vless-reality') != 'vless-reality':
            return result
        domain = valid_domain(result.get('serverName', 'raw.githubusercontent.com'))
        with self.lock:
            matches = [(value[0], key[3]) for key, value in self.sni_cache.items()
                       if key[:3] == (record['id'], record.get('fingerprint'), domain)
                       and value[1] and time.monotonic() - value[0] < 600
                       and (not result.get('sniAddress') or result['sniAddress'] == key[3])]
        if matches:
            result['_verifiedRealityAddress'] = max(matches)[1]
        elif result.get('sniVerified') is True:
            raise ValueError('SNI 实测结果已过期或服务器状态已变化，请重新扫描后创建')
        return result

    def update_inbound(self, server_id, inbound_id, payload):
        inbound_id = positive_id(inbound_id)
        body = prepare_inbound(payload)

        def action(api, record):
            if str(inbound_id) in record.get("bandwidths", {}):
                old = api.request(f"panel/api/inbounds/get/{inbound_id}")
                if any(body.get(key) != old.get(key) for key in ("port", "listen", "protocol")):
                    raise ValueError("该节点已限速，修改端口、监听地址或协议前请先取消限速")
                from bandwidth import policy
                limited = record["bandwidths"][str(inbound_id)]
                if policy(body, limited["uploadKbps"], limited["downloadKbps"])["protocols"] != limited["protocols"]:
                    raise ValueError("该节点已限速，切换 TCP / UDP 传输前请先取消限速")
            if any(x["inboundId"] == inbound_id for x in record.get("relays", [])):
                old = api.request(f"panel/api/inbounds/get/{inbound_id}")
                if any(body.get(key) != old.get(key) for key in ("port", "listen", "protocol")):
                    raise ValueError("中转入站的端口、监听地址和协议关联路由，请保持不变；如需修改请重新创建中转")
            return api.request(f"panel/api/inbounds/update/{inbound_id}", body)
        return self.with_panel(server_id, action)

    def delete_inbound(self, server_id, inbound_id):
        inbound_id = positive_id(inbound_id)

        def remove(api, record, missing=False):
            managed = next((x for x in record.get("relays", []) if x["inboundId"] == inbound_id), None)
            if not managed:
                if not missing:
                    api.request(f"panel/api/inbounds/del/{inbound_id}", {})
                return {"deleted": True}
            original, wrapper = read_xray(api)
            changed = copy.deepcopy(original)
            changed["outbounds"] = [x for x in changed.get("outbounds", []) if x.get("tag") != managed["outboundTag"]]
            changed.setdefault("routing", {})["rules"] = [x for x in changed.get("routing", {}).get("rules", [])
                                                           if x.get("outboundTag") != managed["outboundTag"]]
            self.backup_xray(server_id, original)
            try:
                write_xray(api, changed, wrapper)
                if not missing:
                    api.request(f"panel/api/inbounds/del/{inbound_id}", {})
            except Exception:
                write_xray(api, original, wrapper)
                raise
            with self.lock:
                self.record(server_id)["relays"] = [x for x in record.get("relays", []) if x["inboundId"] != inbound_id]
                self.flush()
            return {"deleted": True}
        def action(api, record):
            previous = copy.deepcopy(record.get("bandwidths", {}))
            rows = api.request("panel/api/inbounds/list") or []
            missing = not any(r["id"] == inbound_id for r in rows)
            if str(inbound_id) not in previous:
                return remove(api, record, missing)
            changed = copy.deepcopy(previous)
            changed.pop(str(inbound_id))
            # If clearing fails, leave the inbound and its old policy in place.
            self._write_bandwidth(api, record, changed)
            try:
                return remove(api, record, missing)
            except Exception as exc:
                if not missing:
                    try:
                        self._write_bandwidth(api, record, previous)
                    except Exception as restore:
                        raise ValueError(f"删除失败且限速恢复失败，请重新应用限速：{restore}") from exc
                raise
        return self.with_panel(server_id, action)

    def backup_xray(self, server_id, configuration):
        with self.lock:
            self.record(server_id)["lastXrayBackup"] = self.seal(json.dumps(configuration))
            self.flush()

    def create_relay(self, server_id, payload):
        landing = self.parse_link(text(payload.get("landingLink"), "落地分享链接", maximum=12000))
        tag = "mxioc-relay-" + secrets.token_hex(8)
        if landing.get("type") in ("hysteria2", "tuic"):
            if install_type(self.record(server_id)) != "sing-box":
                raise ValueError("Hysteria2 / TUIC 落地仅支持 sing-box 入口服务器")
            from core_adapter import sing_quic_outbound
            outbound = {"tag": tag, "protocol": "mxioc-native", "settings": {"native": sing_quic_outbound(landing, tag)}}
        else:
            outbound = node_outbound(landing, tag)

        def action(api, record):
            original, wrapper = read_xray(api)
            self.backup_xray(server_id, original)
            body = build_inbound(api, self.verified_template_payload(record, {**payload, "template": "vless-reality"}))
            created = api.request("panel/api/inbounds/add", body)
            if not isinstance(created, dict) or not created.get("id") or not created.get("tag"):
                raise ValueError("中转入口返回的 ID/tag 不完整，请到入站列表核对")
            created["id"] = positive_id(created["id"])
            changed = copy.deepcopy(original)
            changed.setdefault("outbounds", []).append(outbound)
            changed.setdefault("routing", {}).setdefault("rules", []).insert(0, {
                "type": "field", "inboundTag": [created["tag"]], "outboundTag": outbound["tag"]})
            try:
                write_xray(api, changed, wrapper)
            except Exception as exc:
                failures = []
                for label, revert in (("恢复 Xray 配置", lambda: write_xray(api, original, wrapper)),
                                      ("删除本次入口", lambda: api.request(f"panel/api/inbounds/del/{created['id']}", {}))):
                    try:
                        revert()
                    except Exception:
                        failures.append(label)
                suffix = "；已撤回本次创建" if not failures else "；部分撤回失败：" + "、".join(failures)
                raise ValueError(str(exc) + suffix) from exc
            with self.lock:
                self.record(server_id).setdefault("relays", []).append({"inboundId": created["id"], "outboundTag": outbound["tag"]})
                self.flush()
            return {"inbound": created, "shareLinks": [self.node_uri(n) for n in inbound_nodes(created, record)]}
        return self.with_panel(server_id, action)


def positive_id(value):
    if isinstance(value, bool) or not str(value).isdigit() or int(value) <= 0:
        raise ValueError("入站 ID 无效")
    return int(value)


def json_object(value):
    result = json.loads(value) if isinstance(value, str) else copy.deepcopy(value)
    if not isinstance(result, dict):
        raise ValueError("配置必须是 JSON 对象")
    return result


def prepare_inbound(payload):
    if not isinstance(payload, dict):
        raise ValueError("入站配置必须是 JSON 对象")
    result = {key: value for key, value in payload.items() if key in INBOUND_FIELDS}
    result["port"] = valid_port(result.get("port"))
    if result.get("protocol") not in {"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "dokodemo-door", "mixed", "tunnel", "hysteria2", "tuic"}:
        raise ValueError("不支持该 Xray 入站协议")
    for key in ("settings", "streamSettings", "sniffing"):
        if key in result:
            result[key] = json.dumps(json_object(result[key]), ensure_ascii=False)
    if len(json.dumps(result)) > 256 * 1024:
        raise ValueError("单条入站配置不能超过 256 KB")
    return result


def build_inbound(api, payload):
    supplied_port = payload.get("port")
    port = valid_port(20001 + secrets.randbelow(45535) if supplied_port in (None, "") else supplied_port)
    remark = text(payload.get("remark", "新建节点"), "节点名称", maximum=100)
    template = payload.get("template", "vless-reality")
    client = {"id": str(uuid.uuid4()), "email": "mxioc-" + secrets.token_hex(6), "enable": True,
              "totalGB": 0, "expiryTime": 0, "limitIp": 0, "subId": secrets.token_hex(8), "reset": 0, "tgId": ""}
    stream = {"network": "tcp", "security": "none", "tcpSettings": {"header": {"type": "none"}}}
    if template == "vless-reality":
        sni = valid_domain(payload.get("serverName", "raw.githubusercontent.com"))
        if not sni:
            raise ValueError("Reality 需要填写伪装域名")
        keys = api.request("panel/api/server/getNewX25519Cert")
        if not isinstance(keys, dict) or not keys.get("privateKey") or not keys.get("publicKey"):
            raise ValueError("3x-ui 未返回可用的 Reality 密钥")
        client["flow"] = "xtls-rprx-vision"
        protocol, settings = "vless", {"clients": [client], "decryption": "none", "fallbacks": []}
        target = sni + ':443'
        if payload.get('_verifiedRealityAddress'):
            address = ipaddress.ip_address(payload['_verifiedRealityAddress'])
            if not address.is_global:
                raise ValueError('已验证的 Reality 目标必须为公网地址')
            target = (f'[{address}]' if address.version == 6 else str(address)) + ':443'
        stream.update(security="reality", realitySettings={"show": False, "xver": 0, "target": target,
                      "serverNames": [sni], "privateKey": keys["privateKey"], "shortIds": [secrets.token_hex(8)],
                      "settings": {"publicKey": keys["publicKey"], "fingerprint": "chrome", "serverName": sni, "spiderX": "/"}})
    elif template in ("trojan-tls", "vless-ws-tls", "hysteria2", "tuic"):
        sni = valid_domain(payload.get("serverName"))
        if not sni:
            raise ValueError("TLS 模板必须填写证书对应域名")
        cert = text(payload.get("certFile"), "远端证书文件路径", maximum=512)
        key = text(payload.get("keyFile"), "远端私钥文件路径", maximum=512)
        if any(not p.startswith("/") or ".." in Path(p).parts for p in (cert, key)):
            raise ValueError("证书和私钥必须填写远端绝对路径")
        if template in ("hysteria2", "tuic") and getattr(api, "kind", "") != "sing-box":
            raise ValueError("Hysteria2 / TUIC 模板仅支持独立 sing-box 内核")
        if template in ("trojan-tls", "hysteria2", "tuic"):
            client["password"] = secrets.token_urlsafe(24)
            protocol, settings = ("trojan" if template == "trojan-tls" else template), {"clients": [client]}
        else:
            protocol, settings = "vless", {"clients": [client], "decryption": "none"}
            stream.update(network="ws", wsSettings={"path": text(payload.get("path", "/"), "WebSocket 路径", maximum=256)})
        stream.update(security="tls", tlsSettings={"serverName": sni, "alpn": ["h3"] if template in ("hysteria2", "tuic") else ["h2", "http/1.1"], "certificates": [{"certificateFile": cert, "keyFile": key}]})
    elif template == "vmess-tcp":
        protocol, settings = "vmess", {"clients": [client], "disableInsecureEncryption": False}
    elif template == "shadowsocks":
        protocol, settings = "shadowsocks", {"method": "aes-128-gcm", "password": secrets.token_urlsafe(24), "network": "tcp,udp"}
    else:
        raise ValueError("未知节点模板")
    return prepare_inbound({"remark": remark, "port": port, "protocol": protocol, "enable": True,
                            "listen": "", "up": 0, "down": 0, "total": 0, "expiryTime": 0,
                            "settings": settings, "streamSettings": stream,
                            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}})


def inbound_nodes(inbound, record):
    settings = json_object(inbound.get("settings", {}))
    stream = json_object(inbound.get("streamSettings", {}))
    protocol = inbound.get("protocol")
    base = {"name": inbound.get("remark") or "3x-ui 节点", "server": record["host"], "port": inbound["port"]}
    if protocol in ("socks", "http"):
        accounts = settings.get("accounts", []) or [{}]
        return [{**base, "type": "socks5" if protocol == "socks" else "http",
                 **({"username": account.get("user", ""), "password": account.get("pass", "")} if account else {})}
                for account in accounts]
    if protocol == "shadowsocks" and settings.get("password"):
        return [{**base, "type": "ss", "cipher": settings["method"], "password": settings["password"]}]
    if protocol not in ("vless", "vmess", "trojan", "hysteria2", "tuic"):
        return []
    result = []
    for client in settings.get("clients", []):
        if client.get("enable") is False:
            continue
        node = {**base, "type": protocol, "name": base["name"] + (" / " + str(client.get("email", "")) if len(settings["clients"]) > 1 else "")}
        node["password" if protocol in ("trojan", "hysteria2") else "uuid"] = client.get("password" if protocol in ("trojan", "hysteria2") else "id", "")
        if protocol == "tuic":
            node["password"] = client.get("password", "")
        if protocol == "vmess":
            node.update(cipher="auto", alterId=0)
        if client.get("flow"):
            node["flow"] = client["flow"]
        network = stream.get("network", "tcp")
        if network != "tcp":
            node["network"] = network
        if network == "ws":
            node["ws-opts"] = {"path": stream.get("wsSettings", {}).get("path", "/"), "headers": stream.get("wsSettings", {}).get("headers", {})}
        if network == "grpc":
            node["grpc-opts"] = {"grpc-service-name": stream.get("grpcSettings", {}).get("serviceName", "")}
        security = stream.get("security")
        if security in ("tls", "reality"):
            node["tls"] = True
            tls = stream.get("tlsSettings", {})
            node["servername"] = tls.get("serverName") or record.get("domain", "")
            if protocol in ("hysteria2", "tuic"):
                node["sni"] = node["servername"]
                node["alpn"] = tls.get("alpn", ["h3"])
        if security == "reality":
            reality = stream.get("realitySettings", {})
            public_key = reality.get("settings", {}).get("publicKey")
            if not public_key and reality.get("privateKey"):
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                raw = base64.urlsafe_b64decode(reality["privateKey"] + "=" * (-len(reality["privateKey"]) % 4))
                public_key = base64.urlsafe_b64encode(X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip("=")
            if not public_key:
                continue
            node.update(servername=(reality.get("serverNames") or [""])[0], **{"client-fingerprint": "chrome", "reality-opts": {
                "public-key": public_key, "short-id": (reality.get("shortIds") or [""])[0],
                "support-x25519mlkem768": True}})
        result.append(node)
    return result


def node_outbound(node, tag):
    kind = node.get("type")
    if kind not in ("vless", "vmess", "trojan", "ss", "socks5", "http"):
        raise ValueError("中转落地支持 VLESS、VMess、Trojan、Shadowsocks、SOCKS5 和 HTTP；Xray 不支持此落地协议")
    host, port = node["server"], valid_port(node["port"])
    if kind == "vless":
        settings = {"address": host, "port": port, "id": node["uuid"], "encryption": node.get("encryption", "none"), "flow": node.get("flow", "")}
    elif kind == "vmess":
        settings = {"vnext": [{"address": host, "port": port, "users": [{"id": node["uuid"], "security": node.get("cipher", "auto"), "alterId": node.get("alterId", 0)}]}]}
    else:
        endpoint = {"address": host, "port": port}
        if kind in ("trojan", "ss"):
            endpoint["password"] = node["password"]
        if kind == "ss":
            endpoint["method"] = node["cipher"]
        if kind in ("socks5", "http") and node.get("username") is not None:
            endpoint["users"] = [{"user": node.get("username", ""), "pass": node.get("password", "")}]
        settings = {"servers": [endpoint]}
    outbound = {"tag": tag, "protocol": {"ss": "shadowsocks", "socks5": "socks"}.get(kind, kind), "settings": settings}
    network = node.get("network", "tcp")
    if network not in ("tcp", "ws", "grpc"):
        raise ValueError("该落地传输暂不支持，请使用 TCP、WebSocket 或 gRPC")
    stream = {"network": network, "security": "none"}
    if node.get("reality-opts"):
        r = node["reality-opts"]
        stream.update(security="reality", realitySettings={"serverName": node.get("servername", ""), "fingerprint": node.get("client-fingerprint", "chrome"),
                      "publicKey": r.get("public-key", ""), "shortId": r.get("short-id", ""), "spiderX": "/"})
    elif node.get("tls"):
        stream.update(security="tls", tlsSettings={"serverName": node.get("servername") or node.get("sni", ""), "allowInsecure": bool(node.get("skip-cert-verify"))})
    if network == "ws":
        opts = node.get("ws-opts") or {}
        stream["wsSettings"] = {"path": opts.get("path", "/"), "headers": opts.get("headers", {})}
    if network == "grpc":
        stream["grpcSettings"] = {"serviceName": (node.get("grpc-opts") or {}).get("grpc-service-name", "")}
    outbound["streamSettings"] = stream
    return outbound


def read_xray(api):
    wrapper = json_object(api.request("panel/xray/", {}))
    configuration = json_object(wrapper["xraySetting"])
    return configuration, wrapper


def write_xray(api, configuration, wrapper):
    api.request("panel/xray/update", {"xraySetting": json.dumps(configuration, ensure_ascii=False),
                "outboundTestUrl": wrapper.get("outboundTestUrl", "https://www.google.com/generate_204")})
    api.request("panel/api/server/restartXrayService", {})
