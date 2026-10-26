"""Official Mieru simple URLs mapped to Mihomo's native Mieru outbound model."""
import base64
import binascii
import copy
import re
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

MULTIPLEXING = ('MULTIPLEXING_DEFAULT', 'MULTIPLEXING_OFF', 'MULTIPLEXING_LOW',
                'MULTIPLEXING_MIDDLE', 'MULTIPLEXING_HIGH')
HANDSHAKE = ('HANDSHAKE_DEFAULT', 'HANDSHAKE_STANDARD', 'HANDSHAKE_NO_WAIT')


def validate(node):
    node = copy.deepcopy(node)
    port, port_range = node.get('port'), node.get('port-range')
    if port_range:
        if port not in (None, ''):
            raise ValueError('Mieru 的 port 与 port-range 不能同时填写')
        match = re.fullmatch(r'([0-9]{1,5})-([0-9]{1,5})', str(port_range))
        if not match or not 1 <= int(match[1]) <= int(match[2]) <= 65535:
            raise ValueError('Mieru 端口范围须为 1–65535 内的起始端口-结束端口')
        node['port-range'] = f'{int(match[1])}-{int(match[2])}'
        node.pop('port', None)
    else:
        if type(port) not in (int, str) or not re.fullmatch(r'[0-9]{1,5}', str(port)) or not 1 <= int(port) <= 65535:
            raise ValueError('Mieru 端口须为 1–65535 的整数')
        node['port'] = int(port)
        node.pop('port-range', None)
    for field in ('username', 'password'):
        value = node.get(field)
        if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 64 or any(c in value for c in '\r\n\0'):
            raise ValueError('Mieru 用户名和密码均必填，最多 64 个 UTF-8 字节且不能含换行或空字符')
    transport = node.get('transport', 'TCP')
    if not isinstance(transport, str) or transport.upper() not in ('TCP', 'UDP'):
        raise ValueError('Mieru 传输协议仅支持 TCP 或 UDP')
    node['transport'] = transport.upper()
    for field, choices in (('multiplexing', MULTIPLEXING), ('handshake-mode', HANDSHAKE)):
        if field in node and node[field] not in choices:
            raise ValueError(f'Mieru {field} 选项无效')
    if 'mtu' in node:
        if type(node['mtu']) is not int or node['mtu'] != 1400:
            raise ValueError('当前 Mihomo Mieru 不支持自定义 MTU，请使用默认 1400')
        node.pop('mtu')  # Equivalent to the native library's default, not an ignored override.
    if 'udp' in node and type(node['udp']) is not bool:
        raise ValueError('Mieru UDP 转发开关必须为布尔值')
    pattern = node.get('traffic-pattern', '')
    if not isinstance(pattern, str):
        raise ValueError('Mieru traffic-pattern 必须为 Base64 字符串')
    if pattern:
        if not isinstance(pattern, str) or len(pattern) > 65536:
            raise ValueError('Mieru traffic-pattern 必须为 64 KiB 以内的 Base64 字符串')
        try:
            base64.b64decode(pattern, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError('Mieru traffic-pattern 不是有效 Base64') from None
    return node


def parse_nodes(link):
    parsed = urlsplit(link)
    if parsed.scheme.lower() != 'mierus':
        raise ValueError('mieru:// 是完整客户端配置，请改用官方导出的 mierus:// 简单链接或 Mihomo YAML')
    if not parsed.hostname or parsed.path not in ('', '/') or parsed.port is not None:
        raise ValueError('Mieru 链接须包含服务器地址，并用 port 查询参数指定端口')
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key in ('profile', 'mtu', 'multiplexing', 'handshake-mode', 'traffic-pattern'):
        if len(query.get(key, [])) > 1:
            raise ValueError(f'Mieru {key} 参数不能重复')
    profile = query.get('profile', [''])[0]
    if not profile or len(profile) > 200 or any(c in profile for c in '\r\n\0'):
        raise ValueError('Mieru 链接缺少有效的 profile 名称')
    ports, protocols = query.get('port', []), query.get('protocol', [])
    if not ports or len(ports) != len(protocols) or len(ports) > 256:
        raise ValueError('Mieru port 与 protocol 须一一对应，每条链接最多 256 组')
    base = {'name':unquote(parsed.fragment) or profile, 'type':'mieru', 'server':parsed.hostname,
            'username':unquote(parsed.username or ''), 'password':unquote(parsed.password or ''), 'udp':True}
    for key in ('multiplexing', 'handshake-mode', 'traffic-pattern'):
        if key in query:
            base[key] = query[key][0]
    if 'mtu' in query:
        if query['mtu'][0] != '1400':
            raise ValueError('当前 Mihomo Mieru 不支持自定义 MTU，请使用默认 1400')
    nodes = []
    for port, protocol in zip(ports, protocols):
        item = {**base, 'transport':protocol}
        item['port-range' if '-' in port else 'port'] = port
        if len(ports) > 1:
            item['name'] = f'{base["name"][:160]} · {protocol.upper()} {port}'
        nodes.append(validate(item))
    return nodes


def to_uri(node):
    node = validate(node)
    if node.get('udp') is False:
        raise ValueError('mierus:// 无法表达关闭 UDP 转发，请使用 Mihomo 完整订阅')
    host = node['server']
    if ':' in host:
        host = '[' + host.strip('[]') + ']'
    query = {'profile':node['name'], 'port':node.get('port-range') or node['port'], 'protocol':node['transport']}
    for key in ('multiplexing', 'handshake-mode', 'traffic-pattern'):
        if key in node:
            query[key] = node[key]
    auth = quote(node['username'], safe='') + ':' + quote(node['password'], safe='')
    return f'mierus://{auth}@{host}?{urlencode(query)}'
