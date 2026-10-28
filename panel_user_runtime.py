"""Verify/repair one X-Panel user via the remote loopback HandlerService.

No client handshake, production proxy traffic, counter reset, peer removal or
service restart is performed. Older kernels can explicitly report unsupported.
"""
import base64
import ipaddress
import json
import shlex
import uuid
import time
from urllib.parse import urlsplit

BINARIES = ('/usr/local/x-ui/bin/xray-linux-amd64', '/usr/local/x-ui/bin/xray-linux-arm64',
            '/usr/local/x-ui/bin/xray-linux-386', '/usr/local/x-ui/bin/xray', '/usr/local/bin/xray')


def api_address(config):
    api = config.get('api') or {}
    if api.get('listen'):
        address = urlsplit('//'+str(api['listen']))
        try:
            if not ipaddress.ip_address(address.hostname).is_loopback or not address.port:
                return None
            return str(api['listen'])
        except (ValueError, TypeError):
            return None
    for row in config.get('inbounds', []):
        if row.get('tag') == api.get('tag', 'api') and type(row.get('port')) is int and 1 <= row['port'] <= 65535:
            listen = row.get('listen') or '127.0.0.1'
            if listen not in ('127.0.0.1', '::1', '0.0.0.0', '::'):
                return None
            return ('[::1]' if ':' in listen else '127.0.0.1')+':'+str(row['port'])
    return None


def runtime_status(output, protocol, client):
    try:
        value = json.loads(output)
        matches = [u for u in value['users'] if u.get('email') == client['email']]
        if not matches:
            return 'missing'
        if len(matches) != 1:
            return 'mismatch'
        account = matches[0].get('account', {})
        key = 'password' if protocol == 'trojan' else 'id'
        if key not in account:
            return 'unsupported'  # Older CLIs can return an opaque account blob.
        actual, expected = account.get(key), client.get(key)
        if key == 'id':
            actual, expected = str(uuid.UUID(actual)), str(uuid.UUID(expected))
        if actual != expected:
            return 'mismatch'
        if protocol == 'vless':
            actual = account.get('flow', '').replace('-udp443', '')
            expected = client.get('flow', '').replace('-udp443', '')
            if actual != expected:
                return 'mismatch'
        return 'present'
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError('X-Panel 运行用户查询返回无效内容，绑定已保留，请核对后重试') from exc


def check_authorized(row, client):
    if row.get('enable') is False or client.get('enable') is False:
        raise ValueError('X-Panel 入站或用户已被停用，不自动恢复授权')
    stats = [s for s in (row.get('clientStats') or []) if s.get('email') == client['email']]
    if len(stats) > 1:
        raise ValueError('X-Panel 用户流量记录重复，停止自动同步')
    if stats and stats[0].get('enable') is False:
        raise ValueError('X-Panel 已禁用此用户的授权，不能绕过面板限制补同步')
    owned_stats = stats[0] if stats else {}
    limits = ((row, row.get('total', 0)),
              (owned_stats, owned_stats.get('total', client.get('totalGB', 0))))
    for item, total in limits:
        expiry = item.get('expiryTime', 0)
        if expiry and expiry > 0 and expiry <= int(time.time()*1000):
            raise ValueError('X-Panel 远端授权已到期，不能补同步用户')
        if total and total > 0 and item.get('up', 0)+item.get('down', 0) >= total:
            raise ValueError('X-Panel 远端流量额度已用尽，不能补同步用户')
    expiry = client.get('expiryTime', 0)
    if expiry and expiry > 0 and expiry <= int(time.time()*1000):
        raise ValueError('X-Panel 此用户已到期，不能补同步用户')


def sync_user(manager, api, record, row, client):
    """Only repair a confirmed missing user; never replace a conflicting one."""
    check_authorized(row, client)
    try:
        config = api.request('panel/api/server/getConfigJson')
    except ValueError as exc:
        if 'HTTP 404' in str(exc):
            return {'runtimeVerified': None}
        raise
    if config is None:
        return {'runtimeVerified': None}
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except ValueError:
            raise ValueError('X-Panel 未返回有效内核配置，无法确认用户同步，请重试') from None
    if not isinstance(config, dict):
        raise ValueError('X-Panel 内核配置格式无效，无法确认用户同步')
    address = api_address(config)
    if not address or row.get('protocol') not in ('vless', 'vmess', 'trojan') or not row.get('tag'):
        return {'runtimeVerified': None}
    discovery = 'for candidate in '+ ' '.join(shlex.quote(p) for p in BINARIES) + '; do if [ -x "$candidate" ]; then printf "%s" "$candidate"; break; fi; done'
    code, output = manager.execute(api.ssh, record, discovery, timeout=15)
    binary = output.strip()
    if code or binary not in BINARIES:
        return {'runtimeVerified': None}
    query = (shlex.quote(binary)+' api inbounduser --server='+shlex.quote(address)+
             ' -timeout=3 -tag='+shlex.quote(row['tag'])+' -email='+shlex.quote(client['email']))
    def read():
        code, output = manager.execute(api.ssh, record, query, timeout=10, max_output=256*1024)
        if code:
            if any(s in output.lower() for s in ('unknown command', 'unknown method', 'unimplemented', 'flag provided but not defined')):
                return 'unsupported'
            raise ValueError('无法连接 X-Panel 运行内核的用户接口；面板绑定已保留，请恢复内核后重试')
        return runtime_status(output, row['protocol'], client)
    status = read()
    if status == 'unsupported':
        return {'runtimeVerified': None}
    if status == 'mismatch':
        raise ValueError('X-Panel 运行用户凭据与面板记录不一致，停止自动修复，避免覆盖现有用户')
    if status == 'present':
        return {'runtimeVerified': True, 'runtimeRepaired': False}
    # Build a one-user addition. adu never replaces the inbound or its peers.
    from shared_users import settings
    runtime_client = dict(client)
    if row['protocol'] == 'vless' and runtime_client.get('flow'):
        runtime_client['flow'] = runtime_client['flow'].replace('-udp443', '')
    model = {'inbounds': [{'tag': row['tag'], 'listen': '127.0.0.1', 'port': row['port'],
                           'protocol': row['protocol'], 'settings': {**settings(row), 'clients': [runtime_client]}}]}
    encoded = base64.b64encode(json.dumps(model).encode()).decode()
    script = '''set -eu
candidate=$(mktemp /tmp/mxioc-user-sync.XXXXXXXX)
trap 'rm -f "$candidate"' EXIT
chmod 600 "$candidate"
printf '%s' '''+shlex.quote(encoded)+''' | base64 -d > "$candidate"
'''+shlex.quote(binary)+' api adu --server='+shlex.quote(address)+' -timeout=3 "$candidate"\n'
    code, _ = manager.execute(api.ssh, record, script, timeout=15, max_output=256*1024)
    if code or read() != 'present':
        raise ValueError('X-Panel 已保存 UUID，但运行内核未接受此用户；未删除其他用户或重启服务，请核对内核兼容性后重试')
    return {'runtimeVerified': True, 'runtimeRepaired': True}
