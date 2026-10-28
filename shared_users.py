"""User-scoped ownership for shared inbounds; never identify users by port."""
import copy
import hashlib
import json
import secrets
import uuid

PROTOCOLS = {'vless', 'vmess', 'trojan', 'hysteria2', 'tuic'}


def settings(row):
    value = row.get('settings') or {}
    value = json.loads(value) if isinstance(value, str) else copy.deepcopy(value)
    if not isinstance(value, dict) or not isinstance(value.get('clients', []), list):
        raise ValueError('入站用户列表格式无效')
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def endpoint_identity(row):
    # Other users, counters, expiry and enabled flags must not invalidate ownership.
    value = {k: row.get(k) for k in ('id', 'port', 'protocol', 'tag')}
    value['listen'] = row.get('listen') or ''
    stream = row.get('streamSettings') or {}
    value['streamSettings'] = json.loads(stream) if isinstance(stream, str) else stream
    return digest(value)


def user_identity(client):
    return digest({k: client.get(k) for k in ('id', 'password', 'email', 'flow')})


def find_user(row, binding, missing_ok=False):
    if endpoint_identity(row) != binding['identityHash']:
        raise ValueError('远端入站身份已变化，停止用户操作')
    matches = [c for c in settings(row).get('clients', []) if c.get('email') == binding['userEmail']]
    if not matches and missing_ok:
        return None
    if len(matches) != 1 or user_identity(matches[0]) != binding['userHash']:
        raise ValueError('远端用户身份已变化或缺失，停止用户操作')
    field = 'password' if row.get('protocol') in ('trojan', 'hysteria2') else 'id'
    credential = matches[0].get(field)
    if not credential or sum(c.get(field) == credential for c in settings(row).get('clients', [])) != 1:
        raise ValueError('用户认证凭据被共用，停止操作以免影响其他用户')
    return matches[0]


def check_email_namespace(rows, email):
    # Xray StatsService keys are global to the core, not scoped by inbound ID.
    if sum(c.get('email') == email for row in rows for c in settings(row).get('clients', [])) > 1:
        raise ValueError('认证用户 email 在多个入站重复，无法独立计量，已停止用户操作')


def new_user(row):
    protocol = row.get('protocol')
    if protocol not in PROTOCOLS:
        raise ValueError('该协议暂不支持共用入站独立用户，请选择 VLESS、VMess、Trojan、Hysteria2 或 TUIC')
    user = {'email': 'mxioc-' + secrets.token_hex(12), 'enable': True,
            'totalGB': 0, 'expiryTime': 0, 'limitIp': 0, 'subId': secrets.token_hex(8)}
    if protocol in ('vless', 'vmess', 'tuic'):
        user['id'] = str(uuid.uuid4())
    if protocol in ('trojan', 'hysteria2', 'tuic'):
        user['password'] = secrets.token_urlsafe(24)
    if protocol == 'vless':
        stream = row.get('streamSettings') or {}
        stream = json.loads(stream) if isinstance(stream, str) else stream
        clients = [c for c in settings(row).get('clients', []) if c.get('enable') is not False]
        if clients:
            # Preserve the existing inbound's working user transport mode; a
            # fresh UUID must not silently turn ordinary VLESS into Vision.
            flow = clients[0].get('flow') or ''
            if flow not in ('', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'):
                raise ValueError('现有用户使用未支持的 VLESS flow，不能自动生成兼容用户')
            if flow:
                user['flow'] = flow
        elif stream.get('security') == 'reality' and stream.get('network', 'tcp') in ('tcp', 'raw'):
            user['flow'] = 'xtls-rprx-vision'
    return user


def counters(row, binding):
    find_user(row, binding)
    if not isinstance(row.get('clientStats'), list):
        raise ValueError('缺少独立用户流量计数，不能使用共用入站总流量计费')
    matches = [s for s in row['clientStats'] if s.get('email') == binding['userEmail']]
    if len(matches) != 1 or any(type(matches[0].get(k)) is not int or matches[0][k] < 0 for k in ('up', 'down')):
        raise ValueError('认证用户流量计数缺失，等待下次采集')
    return {'up': matches[0]['up'], 'down': matches[0]['down'], 'source': 'authenticated-client'}
