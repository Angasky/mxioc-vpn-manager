"""Snell nodes and Shadowrocket-compatible Base64 share URLs; legacy imports kept."""
import base64
import copy
import csv
import re
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit


def validate(node):
    node = copy.deepcopy(node)
    psk = node.get('psk')
    if not isinstance(psk, str) or not psk or len(psk.encode()) > 1024 or any(c in psk for c in '\r\n\0'):
        raise ValueError('Snell 必须填写有效 PSK，最多 1024 字节且不能含换行或空字符')
    version = node.get('version', 1)
    if type(version) is not int or version not in range(1, 6):
        raise ValueError('当前 Mihomo Snell 支持版本 1–5，请与服务端版本一致')
    node['version'] = version
    for key in ('udp', 'reuse', 'tfo'):
        if key in node and type(node[key]) is not bool:
            raise ValueError('Snell ' + key + ' 必须为布尔值')
    if node.get('udp') and version < 3:
        raise ValueError('Snell UDP 转发要求版本 3 或以上')
    if node.get('reuse') and version < 4:
        raise ValueError('Snell reuse 选项要求版本 4 或以上')
    obfs = node.get('obfs-opts')
    if obfs == {}:
        node.pop('obfs-opts')
        obfs = None
    if obfs is not None:
        if not isinstance(obfs, dict) or obfs.get('mode') not in ('http', 'tls', 'shadow-tls', 'restls', 'jls'):
            raise ValueError('Snell 混淆模式无效')
        if 'host' in obfs:
            from remote_manager import valid_domain
            obfs['host'] = valid_domain(obfs['host'])
            if not obfs['host']:
                raise ValueError('Snell 混淆 Host 须为有效域名')
        if obfs['mode'] in ('shadow-tls', 'restls', 'jls'):
            if not obfs.get('host'):
                raise ValueError('此 Snell 混淆模式必须填写 Host 域名')
            if not isinstance(obfs.get('password'), str) or not obfs['password'] or any(c in obfs['password'] for c in '\r\n\0'):
                raise ValueError('此 Snell 混淆模式必须填写混淆密码')
        if obfs['mode'] == 'shadow-tls':
            if type(obfs.get('version')) is not int or obfs['version'] not in (1, 2, 3):
                raise ValueError('ShadowTLS 版本须为 1、2 或 3')
            if not isinstance(obfs.get('alpn'), list) or not obfs['alpn'] or any(x not in ('h2', 'http/1.1') for x in obfs['alpn']):
                raise ValueError('ShadowTLS ALPN 须为 h2 或 http/1.1 的非空数组')
        if obfs['mode'] == 'restls' and obfs.get('version-hint') not in ('tls12', 'tls13'):
            raise ValueError('Restls version-hint 须为 tls12 或 tls13')
        if obfs['mode'] == 'jls' and (not isinstance(obfs.get('username'), str) or not obfs['username'] or any(c in obfs['username'] for c in '\r\n\0')):
            raise ValueError('JLS 混淆必须填写用户名')
    return node


def parse(link):
    # Shadowrocket: snell://BASE64(method:PSK@host:port)?version=N#name.
    # Split the envelope before URL parsing: standard Base64 may contain '/'.
    envelope = link.split('://', 1)
    if len(envelope) != 2 or envelope[0].lower() != 'snell':
        raise ValueError('Snell 链接协议无效')
    body, _, fragment = envelope[1].partition('#')
    authority, _, query_text = body.partition('?')
    raw_query = parse_qs(query_text, keep_blank_values=True)
    encoded_psk = None
    if '@' not in authority and 'psk' not in raw_query:
        try:
            decoded = base64.b64decode(authority + '=' * (-len(authority) % 4), altchars=b'-_', validate=True).decode('utf-8')
            auth, separator, endpoint = decoded.rpartition('@')
            method, colon, encoded_psk = auth.partition(':')
            if not separator or not colon or method != 'chacha20-ietf-poly1305' or not encoded_psk:
                raise ValueError()
        except (ValueError, UnicodeError):
            raise ValueError('Snell Base64 认证段无效，必须包含加密标识、PSK 和服务器端口') from None
        link = 'snell://' + endpoint + ('?' + query_text if query_text else '') + ('#' + fragment if fragment else '')
    parsed = urlsplit(link)
    if parsed.scheme.lower() != 'snell' or not parsed.hostname or parsed.path not in ('', '/'):
        raise ValueError('Snell 链接须包含有效的服务器地址和端口')
    try:
        port = parsed.port
    except ValueError:
        raise ValueError('Snell 端口无效') from None
    if port is None or not 1 <= port <= 65535 or parsed.password is not None:
        raise ValueError('Snell 端口或认证格式无效，PSK 特殊字符请进行 URL 编码')
    query = parse_qs(parsed.query, keep_blank_values=True)
    allowed = {'psk', 'version', 'udp', 'reuse', 'tfo', 'obfs', 'obfs-host'}
    if any(k not in allowed or len(v) != 1 for k, v in query.items()):
        raise ValueError('Snell 链接含重复或未适配参数，请使用完整 Mihomo YAML')
    if parsed.username is not None and 'psk' in query:
        raise ValueError('Snell 链接不能同时使用认证段和 psk 查询参数')
    version = query.get('version', ['1'])[0]
    if not re.fullmatch('[1-5]', version):
        raise ValueError('Snell 链接版本须为 1–5')
    node = {'name': unquote(parsed.fragment) or '导入的 Snell 节点', 'type': 'snell',
            'server': parsed.hostname, 'port': port, 'psk': encoded_psk if encoded_psk is not None else (unquote(parsed.username or '') if parsed.username is not None else query.get('psk', [''])[0]),
            'version': int(version)}
    for key in ('udp', 'reuse', 'tfo'):
        if key in query:
            value = query[key][0].lower()
            if value not in ('true', 'false', '1', '0'):
                raise ValueError('Snell 链接开关值须为 true 或 false')
            node[key] = value in ('true', '1')
    if 'obfs' in query:
        node['obfs-opts'] = {'mode': query['obfs'][0]}
        if 'obfs-host' in query:
            node['obfs-opts']['host'] = query['obfs-host'][0]
    elif 'obfs-host' in query:
        raise ValueError('Snell 混淆 Host 必须同时指定混淆模式')
    return validate(node)


def parse_policy(line):
    """Surge-style single Snell policy line, not an entire Surge configuration."""
    name, body = line.split('=', 1)
    values = next(csv.reader([body], skipinitialspace=True, strict=True))
    values = [v.strip() for v in values]
    if len(values) < 3 or values[0].lower() != 'snell':
        raise ValueError('Snell 策略行格式无效')
    args = {}
    for item in values[3:]:
        key, separator, value = item.partition('=')
        if not separator or key in args or key not in ('psk','version','obfs','obfs-host','reuse','udp'):
            raise ValueError('Snell 策略含未适配或重复参数，请使用 Mihomo YAML')
        args[key] = value
        if value.startswith(('"', "'")) or value.endswith(('"', "'")):
            raise ValueError('带引号的 Snell 策略参数请改用 Mihomo YAML 或项目兼容链接')
    host = values[1].strip('[]')
    host = '[' + host + ']' if ':' in host else host
    return parse('snell://' + host + ':' + values[2] + '?' + urlencode(args) + '#' + quote(name.strip(), safe=''))


def to_uri(node):
    node = validate(node)
    allowed = {'name','type','server','port','psk','version','udp','reuse','tfo','obfs-opts'}
    obfs = node.get('obfs-opts') or {}
    if (set(node) - allowed or set(obfs) - {'mode','host'} or obfs.get('mode') not in (None,'http','tls')):
        raise ValueError('此 Snell 扩展参数不能用小火箭链接无损表达，请使用完整 Mihomo 订阅')
    host = node['server']
    host = '[' + host.strip('[]') + ']' if ':' in host else host
    query = {'version': node['version']}
    for key in ('udp','reuse'):
        if key in node:
            query[key] = str(node[key]).lower()
    if 'tfo' in node:
        if type(node['tfo']) is not bool:
            raise ValueError('Snell tfo 必须为布尔值')
        query['tfo'] = '1' if node['tfo'] else '0'
    if obfs:
        query['obfs'] = obfs['mode']
        if 'host' in obfs:
            query['obfs-host'] = obfs['host']
    payload = 'chacha20-ietf-poly1305:' + node['psk'] + '@' + host + ':' + str(node['port'])
    encoded = base64.b64encode(payload.encode('utf-8')).decode('ascii').rstrip('=')
    return 'snell://' + encoded + '?' + urlencode(query) + '#' + quote(node['name'],safe='')
