"""Disposable loopback-only REALITY test; no production nodes/counters involved."""
import json
import secrets
import uuid


def _probe_pair(domain, address, server_port, socks_port):
    import ipaddress
    target = ipaddress.ip_address(address)
    if not target.is_global:
        raise ValueError('Reality 探测仅支持已验证的公网地址')
    destination = f'[{target}]:443' if target.version == 6 else f'{target}:443'
    from core_adapter import key_pair
    keys = key_pair()
    identity, short_id = str(uuid.uuid4()), secrets.token_hex(8)
    server = {'log': {'loglevel': 'none'}, 'inbounds': [{
        'listen': '127.0.0.1', 'port': server_port, 'protocol': 'vless',
        'settings': {'clients': [{'id': identity, 'flow': 'xtls-rprx-vision'}], 'decryption': 'none'},
        'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
            'target': destination, 'serverNames': [domain], 'privateKey': keys['privateKey'],
            'shortIds': [short_id], 'minClientVer': '1.8.2'}}}],
        'outbounds': [{'protocol': 'blackhole', 'settings': {'response': {'type': 'http'}}}]}
    client = {'log': {'loglevel': 'none'}, 'inbounds': [{
        'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
        'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
            'address': '127.0.0.1', 'port': server_port,
            'users': [{'id': identity, 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                'serverName': domain, 'fingerprint': 'chrome', 'publicKey': keys['publicKey'], 'shortId': short_id}}}]}
    return server, client


def probe_script(domain, address):
    server_port, socks_port = secrets.SystemRandom().sample(range(20001, 65536), 2)
    server, client = _probe_pair(domain, address, server_port, socks_port)
    return f'''set -eu
command -v curl >/dev/null && command -v timeout >/dev/null || exit 12
binary=''
for candidate in /usr/local/x-ui/bin/xray* /usr/local/bin/xray; do
 if test -f "$candidate" && test -x "$candidate"; then binary="$candidate"; break; fi
done
test -n "$binary" || exit 13
server_pid=''; client_pid=''
cleanup() {{
 test -z "$client_pid" || kill "$client_pid" 2>/dev/null || true
 test -z "$server_pid" || kill "$server_pid" 2>/dev/null || true
 wait 2>/dev/null || true
}}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
timeout 18 "$binary" run -config stdin: <<'MXIOC_TEST_SERVER' >/dev/null 2>&1 &
{json.dumps(server, separators=(',', ':'))}
MXIOC_TEST_SERVER
server_pid=$!
timeout 18 "$binary" run -config stdin: <<'MXIOC_TEST_CLIENT' >/dev/null 2>&1 &
{json.dumps(client, separators=(',', ':'))}
MXIOC_TEST_CLIENT
client_pid=$!
sleep 0.6
for attempt in 1 2; do
 result=$(curl --disable --noproxy '' --socks5-hostname 127.0.0.1:{socks_port} --silent --head --output /dev/null --connect-timeout 4 --max-time 6 --write-out '%{{http_code}}' http://reality-probe.invalid/) || exit 14
 test "$result" = 403 || exit 15
done
printf 'MXIOC_REALITY_OK\\n'
'''


def probe_batch_script(targets):
    """Two temporary Xray processes per batch, four probes at once, no Python."""
    if not 1 <= len(targets) <= 20:
        raise ValueError('每批 Reality 实测支持 1–20 个目标')
    ports = secrets.SystemRandom().sample(range(20001, 65536), len(targets) * 2)
    ports_hex = ' ' + ' '.join(f'{port:04X}' for port in ports) + ' '
    server = {'log': {'loglevel': 'none'}, 'inbounds': [],
              'outbounds': [{'protocol': 'blackhole', 'settings': {'response': {'type': 'http'}}}]}
    client = {'log': {'loglevel': 'none'}, 'inbounds': [], 'outbounds': [], 'routing': {'rules': []}}
    jobs = []
    for index, (domain, address) in enumerate(targets):
        source, destination = _probe_pair(domain, address, ports[index * 2], ports[index * 2 + 1])
        server['inbounds'].extend(source['inbounds'])
        inbound, outbound = destination['inbounds'][0], destination['outbounds'][0]
        inbound['tag'] = 'probe-in-' + str(index)
        outbound['tag'] = 'probe-out-' + str(index)
        client['inbounds'].append(inbound)
        client['outbounds'].append(outbound)
        client['routing']['rules'].append({'type': 'field', 'inboundTag': [inbound['tag']], 'outboundTag': outbound['tag']})
        jobs.append(f'probe {index} {ports[index * 2 + 1]} &\npids="$pids $!"')
    chunks = []
    for offset in range(0, len(jobs), 4):
        chunks.append('pids=""\n' + '\n'.join(jobs[offset:offset + 4]) + '\nfor pid in $pids; do wait "$pid" || true; done\npids=""')
    return f'''set -eu
command -v curl >/dev/null && command -v timeout >/dev/null || exit 12
binary=''
for candidate in /usr/local/x-ui/bin/xray* /usr/local/bin/xray; do
 if test -f "$candidate" && test -x "$candidate"; then binary="$candidate"; break; fi
done
test -n "$binary" || exit 13
ports_hex='{ports_hex}'
for table in /proc/net/tcp /proc/net/tcp6; do
 test -r "$table" || continue
 while read -r entry_id bind_address peer_address bind_state rest; do
  if test "$bind_state" = 0A; then
   case "$ports_hex" in *" ${{bind_address##*:}} "*) exit 17;; esac
  fi
 done < "$table"
done
server_pid=''; client_pid=''; pids=''
cleanup() {{
 for pid in $pids; do kill "$pid" 2>/dev/null || true; done
 test -z "$client_pid" || kill "$client_pid" 2>/dev/null || true
 test -z "$server_pid" || kill "$server_pid" 2>/dev/null || true
 wait 2>/dev/null || true
}}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
timeout 75 "$binary" run -config stdin: <<'MXIOC_TEST_SERVER' >/dev/null 2>&1 &
{json.dumps(server, separators=(',', ':'))}
MXIOC_TEST_SERVER
server_pid=$!
timeout 75 "$binary" run -config stdin: <<'MXIOC_TEST_CLIENT' >/dev/null 2>&1 &
{json.dumps(client, separators=(',', ':'))}
MXIOC_TEST_CLIENT
client_pid=$!
# Readiness retry replaces a fixed startup delay and never contacts production ports.
for attempt in 1 2 3 4 5 6 7 8 9 10; do
 kill -0 "$server_pid" 2>/dev/null && kill -0 "$client_pid" 2>/dev/null || exit 16
 if (echo > /dev/tcp/127.0.0.1/{ports[1]}) 2>/dev/null; then break; fi
 sleep 0.1
done
probe() {{
 index="$1"; port="$2"
 for attempt in 1 2; do
  result=$(curl --disable --noproxy '' --socks5-hostname "127.0.0.1:$port" --silent --head --output /dev/null --connect-timeout 4 --max-time 6 --write-out '%{{http_code}}' http://reality-probe.invalid/) || {{ printf 'MXIOC_REALITY_RESULT %s FAIL\\n' "$index"; return; }}
  if test "$result" != 403; then printf 'MXIOC_REALITY_RESULT %s FAIL\\n' "$index"; return; fi
 done
 printf 'MXIOC_REALITY_RESULT %s OK\\n' "$index"
}}
{chr(10).join(chunks)}
'''
