"""Bounded ACME preparation over the existing pinned SSH connection."""
import shlex

ACME_COMMIT = '37d064f7b580055d3f2ddf9a9c960f754f3694d6'
ACME_SHA256 = 'fa4842619ddf50f774d79092ae06887a2107c660757283b763bef834dfc150ff'
TLS_TEMPLATES = ('hysteria2', 'tuic', 'trojan-tls', 'vless-ws-tls')

def certificate_script(domain, host, service):
    from remote_manager import valid_domain, valid_ip
    domain, host = valid_domain(domain), valid_ip(host)
    if not domain or service not in ('x-ui', 'xray', 'sing-box'):
        raise ValueError('证书域名或服务类型无效')
    directory = '/etc/mxioc-certificates/' + domain
    prefix = '\n'.join(f'{key}={shlex.quote(value)}' for key, value in (
        ('cert_domain', domain), ('expected_ip', host), ('cert_dir', directory), ('cert_service', service)))
    return prefix + r'''
set -eu
umask 077
export LC_ALL=C
acme_home=/var/lib/mxioc-acme
mkdir -p "$acme_home"
command -v flock >/dev/null || { echo '缺少 flock，请安装 util-linux'; exit 1; }
exec 9>"$acme_home/operation.lock"
flock -n 9 || { echo '证书签发或续期正在运行，请稍后重试'; exit 1; }
for dependency in openssl curl getent sha256sum timeout systemctl; do
 command -v "$dependency" >/dev/null || { echo "缺少依赖: $dependency"; exit 1; }
done
dns_ips=$(getent ahosts "$cert_domain" | awk '{print $1}' | sort -u)
[ -n "$dns_ips" ] || { echo '域名未解析，尚未创建节点'; exit 1; }
local_ips=$(ip -o addr show scope global | awk '{split($4,a,"/");print a[1]}'; printf '%s\n' "$expected_ip")
for address in $dns_ips; do
 printf '%s\n' "$local_ips" | grep -Fxq "$address" || { echo "域名解析到 $address，未指向当前服务器；请核对 A/AAAA 并关闭 CDN 代理"; exit 1; }
done
cert_valid() {
 test -s "$cert_dir/fullchain.pem" && test -s "$cert_dir/privkey.pem" &&
 openssl x509 -in "$cert_dir/fullchain.pem" -checkend 604800 -noout >/dev/null 2>&1 &&
 openssl verify -untrusted "$cert_dir/fullchain.pem" -verify_hostname "$cert_domain" "$cert_dir/fullchain.pem" >/dev/null 2>&1
}
if ! cert_valid; then
 ss -H -lnt 'sport = :80' | grep -q . && { echo 'TCP 80 已被占用，请使用已有证书或释放验证端口；不会停止现有网站'; exit 1; }
 if ! command -v socat >/dev/null; then
  if command -v apt-get >/dev/null; then
   DEBIAN_FRONTEND=noninteractive timeout 90 apt-get install -y --no-install-recommends socat
  elif command -v dnf >/dev/null; then timeout 90 dnf install -y socat
  elif command -v yum >/dev/null; then timeout 90 yum install -y socat
  else echo '缺少 socat，请先通过系统包管理器安装'; exit 1; fi
 fi
 if [ ! -x "$acme_home/acme.sh" ]; then
  bootstrap_dir=$(mktemp -d "$acme_home/bootstrap.XXXXXX")
  bootstrap="$bootstrap_dir/acme.sh"
  trap 'rm -f -- "$bootstrap"; rmdir -- "$bootstrap_dir"' EXIT
  curl -fLsS --connect-timeout 10 --max-time 35 --proto '=https' '__ACME_URL__' -o "$bootstrap"
  printf '%s  %s\n' '__ACME_SHA__' "$bootstrap" | sha256sum -c - >/dev/null
  (cd "$bootstrap_dir" && sh ./acme.sh --install --home "$acme_home" --nocron --noprofile)
  rm -f -- "$bootstrap"
  rmdir -- "$bootstrap_dir"
  trap - EXIT
 fi
 # No --force: retries retain ACME state and do not blindly create new orders.
 timeout 140 "$acme_home/acme.sh" --issue --home "$acme_home" --server letsencrypt --standalone -d "$cert_domain" --keylength ec-256
 mkdir -p "$cert_dir"
 chmod 755 /etc/mxioc-certificates "$cert_dir"
 owner=$(systemctl show -p User --value "$cert_service.service")
 owner=${owner:-root}
 printf '%s\n' "$owner" | grep -Eq '^[a-zA-Z_][a-zA-Z0-9_-]*[$]?$' || { echo '服务用户格式异常，证书未安装'; exit 1; }
 id -- "$owner" >/dev/null
 hook="$cert_dir/reload.sh"
 printf '#!/bin/sh\nset -eu\nchown %s %s\nchmod 600 %s\nif [ ! -e %s ]; then touch %s; exit 0; fi\nsystemctl try-reload-or-restart %s.service\n' "$owner" "$cert_dir/privkey.pem" "$cert_dir/privkey.pem" "$cert_dir/.ready" "$cert_dir/.ready" "$cert_service" > "$hook"
 chmod 700 "$hook"
 "$acme_home/acme.sh" --install-cert --home "$acme_home" -d "$cert_domain" --ecc --key-file "$cert_dir/privkey.pem" --fullchain-file "$cert_dir/fullchain.pem" --reloadcmd "$hook"
fi
cert_valid || { echo '证书验证失败，尚未创建节点'; exit 1; }
cert_pub=$(openssl x509 -in "$cert_dir/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
key_pub=$(openssl pkey -in "$cert_dir/privkey.pem" -pubout -outform DER | sha256sum)
[ "$cert_pub" = "$key_pub" ] || { echo '证书与私钥不匹配，尚未创建节点'; exit 1; }
cat > /etc/systemd/system/mxioc-acme-renew.service <<'UNIT'
[Unit]
Description=Renew MXIOC managed TLS certificates
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/flock -w 300 /var/lib/mxioc-acme/operation.lock /bin/sh /var/lib/mxioc-acme/acme.sh --cron --home /var/lib/mxioc-acme
UNIT
cat > /etc/systemd/system/mxioc-acme-renew.timer <<'UNIT'
[Unit]
Description=Check MXIOC certificates daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now mxioc-acme-renew.timer >/dev/null
printf 'MXIOC_CERT_READY\n'
'''.replace('__ACME_URL__', f'https://raw.githubusercontent.com/acmesh-official/acme.sh/{ACME_COMMIT}/acme.sh').replace('__ACME_SHA__', ACME_SHA256)

def prepare_certificate(manager, api, record, payload):
    from remote_manager import valid_domain, install_type
    domain = valid_domain(payload.get('serverName'))
    if not domain:
        raise ValueError('自动证书需要填写自己的域名，并解析到当前节点服务器')
    kind = install_type(record)
    service = 'x-ui' if kind in ('3x-ui', 'x-ui', 'x-panel') else kind
    script = certificate_script(domain, record['host'], service)
    code, output = manager.execute(api.ssh, record, script, timeout=290, max_output=65536)
    if code or 'MXIOC_CERT_READY' not in output.splitlines():
        raise ValueError('自动证书准备失败（未创建节点）：' + output[-1800:])
    directory = '/etc/mxioc-certificates/' + domain
    return {**payload, 'serverName': domain, 'certFile': directory+'/fullchain.pem', 'keyFile': directory+'/privkey.pem'}
