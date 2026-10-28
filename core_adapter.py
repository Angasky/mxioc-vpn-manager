"""Transactional adapters for controller-owned Xray/sing-box inbounds.

The common model is the X-ui inbound JSON. Existing unmanaged native configuration
is preserved. Only explicitly managed tags are replaced or removed.
"""
import base64
import copy
import json
import secrets
import shlex


def key_pair():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    key = X25519PrivateKey.generate()
    encode = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip('=')
    return {"privateKey": encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            "publicKey": encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}


def sing_inbound(row):
    from remote_manager import json_object
    settings = json_object(row['settings'])
    stream = json_object(row.get('streamSettings', {}))
    protocol = row['protocol']
    native = {"type": protocol, "tag": row['tag'], "listen": row.get('listen') or '::',
              "listen_port": row['port']}
    if protocol == 'shadowsocks':
        native.update(method=settings['method'], password=settings['password'])
    elif protocol in ('vless', 'vmess', 'trojan', 'hysteria2', 'tuic'):
        native['users'] = []
        for client in settings.get('clients', []):
            if client.get('enable') is False:
                continue
            user = {"name": client.get('email', client.get('id', ''))}
            if protocol in ('trojan', 'hysteria2'):
                user['password'] = client['password']
            else:
                user['uuid'] = client['id']
            if protocol == 'tuic':
                user['password'] = client['password']
            if client.get('flow'):
                user['flow'] = client['flow']
            native['users'].append(user)
    else:
        raise ValueError('sing-box 暂不支持该入站模板')
    security = stream.get('security', 'none')
    if security == 'reality':
        r = stream['realitySettings']
        target = r.get('target') or r.get('dest')
        host, port = target.rsplit(':', 1)
        native['tls'] = {"enabled": True, "server_name": r['serverNames'][0],
                         "reality": {"enabled": True, "handshake": {"server": host, "server_port": int(port)},
                                     "private_key": r['privateKey'], "short_id": r['shortIds']}}
    elif security == 'tls':
        tls = stream['tlsSettings']
        cert = tls['certificates'][0]
        native['tls'] = {'enabled': True, 'server_name': tls.get('serverName', ''),
                         'certificate_path': cert['certificateFile'], 'key_path': cert['keyFile']}
        if tls.get('alpn'):
            native['tls']['alpn'] = tls['alpn']
    elif security != 'none':
        raise ValueError('不支持该 TLS 配置')
    network = stream.get('network', 'tcp')
    if network == 'ws':
        native['transport'] = {"type": 'ws', "path": stream.get('wsSettings', {}).get('path', '/')}
    elif network == 'grpc':
        native['transport'] = {"type": 'grpc', "service_name": stream.get('grpcSettings', {}).get('serviceName', '')}
    elif network != 'tcp':
        raise ValueError('不支持该入站传输')
    return native


def sing_outbound(row):
    protocol, settings = row['protocol'], row.get('settings', {})
    if protocol == 'mxioc-native':
        return copy.deepcopy(settings['native'])
    if protocol in ('freedom', 'blackhole'):
        if protocol == 'blackhole':
            raise ValueError('sing-box 新版请使用 route action reject，不能转换 blackhole')
        return {"type": 'direct', "tag": row['tag']}
    native = {"type": {'socks': 'socks', 'shadowsocks': 'shadowsocks'}.get(protocol, protocol), 'tag': row['tag']}
    if protocol in ('vless', 'vmess'):
        server = settings['vnext'][0] if 'vnext' in settings else settings
        user = server['users'][0] if 'users' in server else server
        native.update(server=server['address'], server_port=server['port'], uuid=user['id'])
        if protocol == 'vmess':
            native.update(security=user.get('security', 'auto'), alter_id=user.get('alterId', 0))
        if user.get('flow'):
            native['flow'] = user['flow']
    else:
        server = settings['servers'][0]
        native.update(server=server['address'], server_port=server['port'])
        if protocol in ('shadowsocks', 'trojan'):
            native['password'] = server['password']
        if protocol == 'shadowsocks':
            native['method'] = server['method']
        if protocol in ('socks', 'http') and server.get('users'):
            native.update(username=server['users'][0]['user'], password=server['users'][0]['pass'])
        if protocol == 'socks':
            native['version'] = '5'
    stream = row.get('streamSettings', {})
    security = stream.get('security', 'none')
    if security in ('tls', 'reality'):
        tls = stream.get('realitySettings' if security == 'reality' else 'tlsSettings', {})
        native['tls'] = {"enabled": True, "server_name": tls.get('serverName', ''),
                         "insecure": tls.get('allowInsecure', False)}
        if security == 'reality':
            native['tls'].update(utls={"enabled": True, "fingerprint": tls.get('fingerprint', 'chrome')},
                                 reality={"enabled": True, "public_key": tls['publicKey'], "short_id": tls.get('shortId', '')})
    network = stream.get('network', 'tcp')
    if network == 'ws':
        opts = stream.get('wsSettings', {})
        native['transport'] = {"type": 'ws', "path": opts.get('path', '/'), "headers": opts.get('headers', {})}
    elif network == 'grpc':
        native['transport'] = {"type": 'grpc', "service_name": stream.get('grpcSettings', {}).get('serviceName', '')}
    elif network != 'tcp':
        raise ValueError('sing-box 不支持该出站传输')
    return native


def sing_quic_outbound(node, tag):
    native = {"type": node['type'], "tag": tag, "server": node['server'], "server_port": node['port'],
              "password": node['password'], "tls": {"enabled": True,
              "server_name": node.get('sni') or node.get('servername', ''),
              "insecure": bool(node.get('skip-cert-verify'))}}
    if node.get('alpn'):
        native['tls']['alpn'] = node['alpn'] if isinstance(node['alpn'], list) else [node['alpn']]
    if node['type'] == 'tuic':
        native.update(uuid=node['uuid'], congestion_control=node.get('congestion-controller', 'bbr'),
                      udp_relay_mode=node.get('udp-relay-mode', 'native'))
    elif node.get('obfs'):
        if node['obfs'] != 'salamander':
            raise ValueError('sing-box Hysteria2 仅支持 salamander 混淆')
        native['obfs'] = {"type": 'salamander', "password": node.get('obfs-password', '')}
    return native


class CoreAPI:
    def __init__(self, manager, ssh, record):
        self.manager, self.ssh, self.record = manager, ssh, record
        self.kind = record['installType']
        self.path = '/usr/local/etc/xray/config.json' if self.kind == 'xray' else '/etc/sing-box/config.json'
        self.binary = '/usr/local/bin/xray' if self.kind == 'xray' else '/usr/bin/sing-box'
        code, output = manager.execute(ssh, record, 'base64 < ' + self.path, timeout=30, max_output=2 * 1024 * 1024)
        if code:
            raise ValueError(f'无法读取内核配置 {self.path}，请检查安装位置及 SSH 提权权限')
        try:
            self.native = json.loads(base64.b64decode(output))
        except (ValueError, TypeError) as exc:
            raise ValueError('远端内核配置不是有效 JSON') from exc
        if not isinstance(self.native, dict):
            raise ValueError('远端内核配置必须为 JSON 对象')
        self.state = json.loads(manager.secret(record, 'coreState')) if record.get('coreState') else {
            'inbounds': [], 'outbounds': [], 'routing': {'rules': []}}
        self.pending = None

    def check_user_stats_support(self):
        existing = self.native.get('api') if self.kind == 'xray' else self.native.get('experimental', {}).get('v2ray_api')
        if existing and not self.state.get('userStats'):
            raise ValueError('原生配置已有统计 API，请先人工核对，不能自动覆盖')
        binary = self.binary if self.kind == 'xray' else '/usr/local/bin/xray'
        code, _ = self.manager.execute(self.ssh, self.record, 'test -x ' + shlex.quote(binary), timeout=15)
        if code:
            raise ValueError('独立内核用户计量需要 /usr/local/bin/xray 查询工具；未绑定订阅，不能退回端口计量')
        if self.kind == 'sing-box':
            code, output = self.manager.execute(self.ssh, self.record, self.binary + ' version', timeout=15)
            if code or 'with_v2ray_api' not in output:
                raise ValueError('此 sing-box 构建缺少 with_v2ray_api，不能按用户计量；请使用支持此功能的构建或选择 Xray / 面板入站')
        return binary

    def enable_user_stats(self, email):
        binary = self.check_user_stats_support()
        state = copy.deepcopy(self.state)
        stats = state.get('userStats')
        if not stats:
            stats = {'listen': '127.0.0.1:10085', 'binary': binary, 'users': []}
        if email in stats['users']:
            return
        stats['users'].append(email)
        state['userStats'] = stats
        self.apply(state)
        # Verify StatsService actually exists (sing-box builds may omit it).
        self.user_stats()

    def user_stats(self):
        stats = self.state.get('userStats')
        if not stats:
            return None
        command = (shlex.quote(stats['binary']) + ' api statsquery --server=' +
                   shlex.quote(stats['listen']) + " --pattern='user>>>'")
        code, output = self.manager.execute(self.ssh, self.record, command, timeout=20, max_output=2 * 1024 * 1024)
        if code:
            raise ValueError('独立用户 StatsService 读取失败，请检查内核构建与本地统计接口')
        try:
            entries = json.loads(output).get('stat', [])
            users = {}
            for entry in entries:
                parts = entry['name'].split('>>>')
                if len(parts) == 4 and parts[0] == 'user' and parts[2] == 'traffic' and parts[3] in ('uplink', 'downlink'):
                    value = int(entry.get('value', 0))
                    if value < 0:
                        raise ValueError()
                    users.setdefault(parts[1], {})['up' if parts[3] == 'uplink' else 'down'] = value
            # Native StatsService registers counters lazily, a missing direction
            # before first traffic is zero; transport/API failure is never zero.
            return [{'email': email, 'up': users.get(email, {}).get('up', 0),
                     'down': users.get(email, {}).get('down', 0)} for email in stats['users']]
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError('独立用户 StatsService 返回无效计数') from exc

    def apply(self, state):
        native = copy.deepcopy(self.native)
        old_tags = {r['tag'] for r in self.state['inbounds']}
        new_rows = state['inbounds']
        native['inbounds'] = [r for r in native.get('inbounds', []) if r.get('tag') not in old_tags]
        for row in new_rows:
            if not row.get('enable', True):
                continue
            if self.kind == 'sing-box':
                native['inbounds'].append(sing_inbound(row))
            else:
                from remote_manager import json_object
                item = {k: copy.deepcopy(row[k]) for k in ('tag', 'listen', 'port', 'protocol') if k in row}
                item['listen'] = item.get('listen') or '0.0.0.0'
                item['settings'] = json_object(row['settings'])
                if 'clients' in item['settings']:
                    item['settings']['clients'] = [c for c in item['settings']['clients'] if c.get('enable') is not False]
                item['streamSettings'] = json_object(row.get('streamSettings', {}))
                item['sniffing'] = json_object(row.get('sniffing', {}))
                native['inbounds'].append(item)
        previous = {r['tag'] for r in self.state.get('outbounds', [])}
        native['outbounds'] = [r for r in native.get('outbounds', []) if r.get('tag') not in previous]
        if not native['outbounds']:
            native['outbounds'].append({'type': 'direct', 'tag': 'mxioc-direct'} if self.kind == 'sing-box' else
                                       {'protocol': 'freedom', 'tag': 'mxioc-direct'})
        native['outbounds'].extend(sing_outbound(r) if self.kind == 'sing-box' else copy.deepcopy(r)
                                   for r in state.get('outbounds', []))
        if self.kind == 'sing-box':
            rules = native.setdefault('route', {}).setdefault('rules', [])
            rules[:] = [r for r in rules if r.get('outbound') not in previous]
            rules[:0] = [{"inbound": r['inboundTag'], "action": 'route', "outbound": r['outboundTag']}
                         for r in state.get('routing', {}).get('rules', [])]
        else:
            rules = native.setdefault('routing', {}).setdefault('rules', [])
            rules[:] = [r for r in rules if r.get('outboundTag') not in previous]
            rules[:0] = copy.deepcopy(state.get('routing', {}).get('rules', []))
        if state.get('userStats'):
            stats = state['userStats']
            if self.kind == 'xray':
                native['api'] = {'tag': 'mxioc-user-stats', 'listen': stats['listen'], 'services': ['StatsService']}
                native.setdefault('stats', {})
                levels = native.setdefault('policy', {}).setdefault('levels', {})
                from remote_manager import json_object
                for row in new_rows:
                    for client in json_object(row['settings']).get('clients', []):
                        levels.setdefault(str(client.get('level', 0)), {}).update(statsUserUplink=True, statsUserDownlink=True)
            else:
                native.setdefault('experimental', {})['v2ray_api'] = {
                    'listen': stats['listen'], 'stats': {'enabled': True, 'users': stats['users']}}
        raw = json.dumps(native, ensure_ascii=False)
        encoded = base64.b64encode(raw.encode()).decode()
        check = self.binary + (' run -test -config' if self.kind == 'xray' else ' check -c')
        script = f'''set -Eeuo pipefail
exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || exit 75
candidate=$(mktemp {self.path}.mxioc.XXXXXXXX)
backup=$(mktemp {self.path}.backup.XXXXXXXX)
cp -p {self.path} "$backup"
applied=0
cleanup() {{
  rc=$?
  if [ "$rc" != 0 ] && [ "$applied" = 1 ]; then
    cp -p "$backup" {self.path}
    systemctl restart {self.kind} >/dev/null 2>&1 || echo 'Configuration restored but service restart failed'
  fi
  rm -f "$candidate" "$backup"
}}
trap cleanup EXIT
printf '%s' '{encoded}' | base64 -d > "$candidate"
{check} "$candidate" >/dev/null 2>&1 || {{ echo 'Native configuration validation failed'; exit 22; }}
chown --reference={self.path} "$candidate"
chmod --reference={self.path} "$candidate"
applied=1
mv "$candidate" {self.path}
systemctl restart {self.kind}
sleep 1
systemctl is-active --quiet {self.kind}
'''
        code, _ = self.manager.execute(self.ssh, self.record, script, timeout=90)
        if code:
            raise ValueError(f'内核配置应用失败（退出码 {code}）；已尝试恢复配置，请读取服务诊断')
        with self.manager.lock:
            stored = self.manager.record(self.record['id'])
            stored['coreState'] = self.manager.seal(json.dumps(state))
            stored['coreConfig'] = self.manager.seal(raw)
            self.manager.flush()
        self.state, self.native = copy.deepcopy(state), native

    def request(self, path, payload=None, **kwargs):
        if path.endswith('getNewX25519Cert'):
            return key_pair()
        if path == 'panel/api/inbounds/list':
            return copy.deepcopy(self.state['inbounds'])
        if '/inbounds/get/' in path:
            identity = int(path.rsplit('/', 1)[1])
            return copy.deepcopy(next(r for r in self.state['inbounds'] if r['id'] == identity))
        if path == 'panel/xray/':
            return {'xraySetting': {'outbounds': copy.deepcopy(self.state['outbounds']),
                                    'routing': copy.deepcopy(self.state['routing'])}}
        if path == 'panel/xray/update':
            model = json.loads(payload['xraySetting'])
            self.pending = {**copy.deepcopy(self.state), 'outbounds': model.get('outbounds', []),
                            'routing': model.get('routing', {'rules': []})}
            return None
        if path.endswith('restartXrayService'):
            if self.pending is not None:
                self.apply(self.pending)
                self.pending = None
            return None
        state = copy.deepcopy(self.state)
        if path.endswith('/inbounds/add'):
            from remote_manager import valid_port
            port = valid_port(payload['port'])
            if any(r.get('port', r.get('listen_port')) == port for r in self.native.get('inbounds', [])):
                raise ValueError('该内核已存在相同监听端口')
            identity = secrets.randbelow(2 ** 31 - 1) + 1
            row = {**copy.deepcopy(payload), 'id': identity, 'tag': 'mxioc-inbound-' + str(identity)}
            state['inbounds'].append(row)
            self.apply(state)
            return copy.deepcopy(row)
        if '/inbounds/update/' in path:
            identity = int(path.rsplit('/', 1)[1])
            row = next((r for r in state['inbounds'] if r['id'] == identity), None)
            if not row:
                raise ValueError('仅可编辑总控创建的内核入站')
            if payload['port'] != row['port']:
                raise ValueError('独立内核入站端口不能修改，请重新创建以保持计量关联')
            row.update(copy.deepcopy(payload))
            self.apply(state)
            return copy.deepcopy(row)
        if '/inbounds/del/' in path:
            identity = int(path.rsplit('/', 1)[1])
            state['inbounds'] = [r for r in state['inbounds'] if r['id'] != identity]
            self.apply(state)
            return None
        raise ValueError('独立内核不支持该操作：' + path)
