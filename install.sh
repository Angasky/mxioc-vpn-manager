#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="mxioc-rule-manager"
APP_DIR="/opt/${APP_NAME}"
CONFIG_DIR="/etc/sing-box/subscribe"
CONFIG_FILE="${CONFIG_DIR}/clash-cn-route"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
NGINX_CONF="/etc/nginx/conf.d/${APP_NAME}.conf"
SHORTCUT_FILE="/usr/local/bin/vpn"
RAW_BASE="${MXIOC_RAW_BASE:-https://raw.githubusercontent.com/Angasky/mxioc-vpn-manager/main}"
MODE=""
DOMAIN=""
CERT_EMAIL=""
ACCESS_URL=""
SUBSCRIPTION_URL=""
HTTP_PORT=""
HTTPS_PORT=""
CUSTOM_PORT=""
ACME_ROOT="/var/lib/mxioc-rule-manager/acme"
STAGE_DIR=""
ACTION=""
PURGE_DATA=0

if [[ -t 1 ]]; then
    C_CYAN='\033[1;36m'
    C_BLUE='\033[1;34m'
    C_GREEN='\033[1;32m'
    C_YELLOW='\033[1;33m'
    C_RED='\033[1;31m'
    C_DIM='\033[2m'
    C_RESET='\033[0m'
else
    C_CYAN=''
    C_BLUE=''
    C_GREEN=''
    C_YELLOW=''
    C_RED=''
    C_DIM=''
    C_RESET=''
fi

say() { printf '%b\n' "$*"; }
info() { say "${C_BLUE}[INFO]${C_RESET} $*"; }
success() { say "${C_GREEN}[ OK ]${C_RESET} $*"; }
warn() { say "${C_YELLOW}[WARN]${C_RESET} $*"; }
fatal() { say "${C_RED}[FAIL]${C_RESET} $*" >&2; exit 1; }

cleanup() {
    if [[ -n "${STAGE_DIR}" && -d "${STAGE_DIR}" && "${STAGE_DIR}" == /tmp/mxioc-install.* ]]; then
        rm -rf -- "${STAGE_DIR}"
    fi
}
trap cleanup EXIT
trap 'fatal "安装在第 ${LINENO} 行中断，请查看上方错误信息。"' ERR

banner() {
    clear 2>/dev/null || true
    say "${C_CYAN}"
    cat <<'MXIOC'
███╗   ███╗██╗  ██╗██╗ ██████╗  ██████╗
████╗ ████║╚██╗██╔╝██║██╔═══██╗██╔════╝
██╔████╔██║ ╚███╔╝ ██║██║   ██║██║
██║╚██╔╝██║ ██╔██╗ ██║██║   ██║██║
██║ ╚═╝ ██║██╔╝ ██╗██║╚██████╔╝╚██████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝  ╚═════╝
MXIOC
    say "${C_RESET}${C_DIM}      VPN Subscription Manager · One-click Installer${C_RESET}"
    say "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
}

usage() {
    cat <<EOF
用法：
  sudo bash install.sh                  交互菜单
  sudo bash install.sh --ip             IP 模式（HTTP）
  sudo bash install.sh --domain 域名    域名模式（HTTPS）
  sudo bash install.sh --fast           极速模式（HTTP，默认端口 5656）
  sudo bash install.sh --update-only    只更新后台程序，不修改现有配置和部署方式
  sudo bash install.sh --reset-auth     重置管理员用户名与密码
  sudo bash install.sh --uninstall      卸载后台并归档保留用户数据
  sudo bash install.sh --purge          彻底卸载后台并删除主订阅

可选参数：
  --email 邮箱      Let's Encrypt 到期通知邮箱
  --port 端口       IP 或域名模式的自定义访问端口
  --help            显示帮助
EOF
}

prompt_value() {
    local variable="$1"
    local message="$2"
    local default_value="${3:-}"
    local answer=""
    if [[ -r /dev/tty ]]; then
        read -r -p "${message}" answer </dev/tty || true
    else
        read -r -p "${message}" answer || true
    fi
    answer="${answer:-${default_value}}"
    printf -v "${variable}" '%s' "${answer}"
}

prompt_secret() {
    local variable="$1"
    local message="$2"
    local answer=""
    if [[ -r /dev/tty ]]; then
        read -r -s -p "${message}" answer </dev/tty || true
        printf '\n' >/dev/tty
    else
        read -r -s -p "${message}" answer || true
        printf '\n'
    fi
    printf -v "${variable}" '%s' "${answer}"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ip)
                ACTION="install"
                MODE="ip"
                shift
                ;;
            --fast)
                ACTION="install"
                MODE="fast"
                shift
                ;;
            --domain)
                [[ $# -ge 2 ]] || fatal "--domain 后必须填写域名"
                ACTION="install"
                MODE="domain"
                DOMAIN="$2"
                shift 2
                ;;
            --email)
                [[ $# -ge 2 ]] || fatal "--email 后必须填写邮箱"
                CERT_EMAIL="$2"
                shift 2
                ;;
            --port)
                [[ $# -ge 2 ]] || fatal "--port 后必须填写端口"
                CUSTOM_PORT="$2"
                shift 2
                ;;
            --update-only)
                ACTION="update"
                shift
                ;;
            --reset-auth)
                ACTION="reset-auth"
                shift
                ;;
            --uninstall)
                ACTION="uninstall"
                PURGE_DATA=0
                shift
                ;;
            --purge)
                ACTION="uninstall"
                PURGE_DATA=1
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                fatal "未知参数：$1"
                ;;
        esac
    done
}

choose_action() {
    [[ -n "${ACTION}" ]] && return
    say "${C_CYAN}请选择要执行的操作${C_RESET}"
    say "  ${C_GREEN}1)${C_RESET} IP 部署模式      ${C_DIM}通过 http://服务器IP 访问${C_RESET}"
    say "  ${C_GREEN}2)${C_RESET} 域名 HTTPS 模式  ${C_DIM}校验解析后自动申请并续期证书（推荐）${C_RESET}"
    say "  ${C_GREEN}3)${C_RESET} 极速安装模式      ${C_DIM}零配置启动，默认使用 5656 端口${C_RESET}"
    say "  ${C_GREEN}4)${C_RESET} 升级 / 修复       ${C_DIM}更新后台程序，保留全部用户数据${C_RESET}"
    say "  ${C_GREEN}5)${C_RESET} 重置管理员凭证   ${C_DIM}修改登录用户名和密码${C_RESET}"
    say "  ${C_YELLOW}6)${C_RESET} 卸载并保留数据   ${C_DIM}先归档用户数据，再移除后台${C_RESET}"
    say "  ${C_RED}7)${C_RESET} 彻底卸载           ${C_DIM}同时删除后台数据和主订阅${C_RESET}"
    say "  ${C_RED}0)${C_RESET} 退出"
    say ""
    local choice=""
    prompt_value choice "请输入选项 [0-7]："
    case "${choice}" in
        1) ACTION="install"; MODE="ip" ;;
        2) ACTION="install"; MODE="domain" ;;
        3) ACTION="install"; MODE="fast" ;;
        4) ACTION="update" ;;
        5) ACTION="reset-auth" ;;
        6) ACTION="uninstall"; PURGE_DATA=0 ;;
        7) ACTION="uninstall"; PURGE_DATA=1 ;;
        0) exit 0 ;;
        *) fatal "无效选项：${choice}" ;;
    esac
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || fatal "请使用 root 运行，或在命令前添加 sudo。"
    command -v systemctl >/dev/null 2>&1 || fatal "当前系统不支持 systemd。"
}

detect_system() {
    [[ -r /etc/os-release ]] || fatal "无法识别 Linux 发行版。"
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_LABEL="${PRETTY_NAME:-${ID:-Linux}}"
    case "${ID:-}:${ID_LIKE:-}" in
        *debian*|*ubuntu*) PACKAGE_FAMILY="apt" ;;
        *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)
            if command -v dnf >/dev/null 2>&1; then PACKAGE_FAMILY="dnf"; else PACKAGE_FAMILY="yum"; fi
            ;;
        *) fatal "暂不支持 ${OS_LABEL}，当前支持 Debian/Ubuntu/RHEL/CentOS/Rocky/AlmaLinux。" ;;
    esac
    success "系统识别：${OS_LABEL}"
}

install_packages() {
    info "安装 Python、Nginx、DNS 与下载工具……"
    case "${PACKAGE_FAMILY}" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y
            apt-get install -y python3 python3-venv python3-pip nginx curl ca-certificates dnsutils iproute2
            if [[ "${MODE}" == "domain" ]]; then
                apt-get install -y certbot python3-certbot-nginx
            fi
            ;;
        dnf)
            dnf install -y python3 python3-pip nginx curl ca-certificates bind-utils iproute
            if [[ "${MODE}" == "domain" ]]; then
                dnf install -y certbot python3-certbot-nginx || {
                    dnf install -y epel-release
                    dnf install -y certbot python3-certbot-nginx
                }
            fi
            ;;
        yum)
            yum install -y python3 python3-pip nginx curl ca-certificates bind-utils iproute
            if [[ "${MODE}" == "domain" ]]; then
                yum install -y epel-release || true
                yum install -y certbot python3-certbot-nginx
            fi
            ;;
    esac
    command -v python3 >/dev/null 2>&1 || fatal "Python 3 安装失败。"
    python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' \
        || fatal "需要 Python 3.9 或更高版本。"
    command -v nginx >/dev/null 2>&1 || fatal "Nginx 安装失败。"
    success "基础依赖安装完成"
}

normalize_public_ips() {
    python3 -c '
import ipaddress, sys
seen = set()
for raw in sys.stdin:
    for value in raw.split():
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            continue
        if address.is_global and address.compressed not in seen:
            seen.add(address.compressed)
            print(address.compressed)
'
}

collect_server_ips() {
    mapfile -t SERVER_IPS < <(
        {
            curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true
            echo
            curl -6 -fsS --max-time 8 https://api64.ipify.org 2>/dev/null || true
            echo
            ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true
            ip -o -6 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true
        } | normalize_public_ips | sort -u
    )
    [[ ${#SERVER_IPS[@]} -gt 0 ]] || fatal "无法检测本机公网 IP，请确认服务器可以访问互联网。"
    PRIMARY_IP=""
    local ip
    for ip in "${SERVER_IPS[@]}"; do
        if [[ "${ip}" == *.* ]]; then PRIMARY_IP="${ip}"; break; fi
    done
    PRIMARY_IP="${PRIMARY_IP:-${SERVER_IPS[0]}}"
    info "检测到本机公网地址：${SERVER_IPS[*]}"
}

validate_port() {
    local value="$1"
    [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 )) \
        || fatal "端口必须是 1–65535 之间的数字：${value}"
}

port_in_use() {
    local port="$1"
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ":${port}$"
}

port_used_by_nginx() {
    local port="$1"
    ss -H -ltnp 2>/dev/null | grep -E ":${port}[[:space:]]" | grep -q nginx
}

random_free_port() {
    local candidate=""
    local attempt
    for attempt in {1..20}; do
        candidate="$(python3 -c 'import socket
for family, address in ((socket.AF_INET6, ("::", 0)), (socket.AF_INET, ("", 0))):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.bind(address)
        print(sock.getsockname()[1])
        sock.close()
        break
    except OSError:
        pass' || true)"
        if [[ -n "${candidate}" ]] && ! port_in_use "${candidate}"; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    fatal "暂时无法自动找到空闲端口，请使用 --port 手动指定。"
}

configure_access_port() {
    local selected="${CUSTOM_PORT}"
    case "${MODE}" in
        fast)
            selected="${selected:-5656}"
            validate_port "${selected}"
            if port_in_use "${selected}"; then
                local previous="${selected}"
                selected="$(random_free_port)"
                warn "极速模式默认端口 ${previous} 已被占用，已自动改用空闲端口 ${selected}。"
            fi
            HTTP_PORT="${selected}"
            ;;
        ip)
            if [[ -z "${selected}" ]]; then
                prompt_value selected "请输入 HTTP 访问端口 [80]：" "80"
            fi
            validate_port "${selected}"
            if port_in_use "${selected}" && ! port_used_by_nginx "${selected}"; then
                fatal "端口 ${selected} 已被其他程序占用，请更换端口。"
            fi
            HTTP_PORT="${selected}"
            ;;
        domain)
            if [[ -z "${selected}" ]]; then
                prompt_value selected "请输入 HTTPS 访问端口 [443]：" "443"
            fi
            validate_port "${selected}"
            [[ "${selected}" != "80" ]] || fatal "HTTPS 访问端口不能使用 80；80 端口需要保留给证书验证。"
            if port_in_use "${selected}" && ! port_used_by_nginx "${selected}"; then
                fatal "端口 ${selected} 已被其他程序占用，请更换端口。"
            fi
            if port_in_use 80 && ! port_used_by_nginx 80; then
                fatal "80 端口被其他程序占用，Let's Encrypt 无法完成证书验证。"
            fi
            HTTPS_PORT="${selected}"
            ;;
    esac
}

normalize_domain() {
    DOMAIN="${DOMAIN,,}"
    DOMAIN="${DOMAIN#http://}"
    DOMAIN="${DOMAIN#https://}"
    DOMAIN="${DOMAIN%%/*}"
    DOMAIN="${DOMAIN%%:*}"
    DOMAIN="${DOMAIN%.}"
    [[ "${DOMAIN}" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] \
        || fatal "域名格式不正确：${DOMAIN}"
}

contains_ip() {
    local wanted="$1"
    local item
    for item in "${SERVER_IPS[@]}"; do
        [[ "${item}" == "${wanted}" ]] && return 0
    done
    return 1
}

verify_domain_dns() {
    if [[ -z "${DOMAIN}" ]]; then
        prompt_value DOMAIN "请输入已经解析到本服务器的域名（例如 vpn.example.com）："
    fi
    normalize_domain
    info "检查 ${DOMAIN} 的 A/AAAA 解析……"
    local cloudflare_hosted=0
    local nameservers=""
    local ns_domain="${DOMAIN}"
    while [[ "${ns_domain}" == *.* ]]; do
        nameservers="$(dig +short NS "${ns_domain}" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
        [[ -z "${nameservers}" ]] || break
        ns_domain="${ns_domain#*.}"
    done
    if grep -q 'cloudflare\.com' <<<"${nameservers}"; then
        cloudflare_hosted=1
        info "检测到该域名使用 Cloudflare DNS 托管。"
    fi
    mapfile -t DNS_IPS < <(
        {
            dig +short A "${DOMAIN}" 2>/dev/null || true
            dig +short AAAA "${DOMAIN}" 2>/dev/null || true
        } | normalize_public_ips | sort -u
    )
    [[ ${#DNS_IPS[@]} -gt 0 ]] || fatal "${DOMAIN} 没有可用的 A/AAAA 记录，请先完成 DNS 解析后重新运行。"

    local address
    local mismatched=()
    for address in "${DNS_IPS[@]}"; do
        contains_ip "${address}" || mismatched+=("${address}")
    done
    if [[ ${#mismatched[@]} -gt 0 ]]; then
        if [[ "${cloudflare_hosted}" == "1" ]]; then
            say "${C_YELLOW}检测到 Cloudflare 小黄云代理可能已开启。${C_RESET}"
            say "  请进入 Cloudflare → DNS，将 ${DOMAIN} 的代理状态改为“仅 DNS（灰色云朵）”。"
            say "  等待解析生效后再重新运行 vpn 申请证书。"
            fatal "必须先关闭 Cloudflare 小黄云，Let's Encrypt 才能直接验证本服务器。"
        fi
        say "${C_RED}域名解析校验未通过。${C_RESET}"
        say "  域名当前解析：${DNS_IPS[*]}"
        say "  本服务器地址：${SERVER_IPS[*]}"
        say "  不属于本机的记录：${mismatched[*]}"
        fatal "请修正 DNS；如果使用 Cloudflare，请暂时关闭代理云朵并设为“仅 DNS”。"
    fi
    if [[ "${cloudflare_hosted}" == "1" ]]; then
        success "Cloudflare 当前为仅 DNS 状态，可以继续申请证书"
    fi
    success "域名解析正确：${DOMAIN} → ${DNS_IPS[*]}"
}

local_source_root() {
    local candidate=""
    candidate="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
    if [[ -f "${candidate}/server.py" && -f "${candidate}/index.html" ]]; then
        printf '%s' "${candidate}"
    fi
}

stage_file() {
    local relative="$1"
    local destination="${STAGE_DIR}/$(basename "${relative}")"
    local source_root="${SOURCE_ROOT:-}"
    if [[ -n "${source_root}" && -f "${source_root}/${relative}" ]]; then
        cp -- "${source_root}/${relative}" "${destination}"
    else
        curl -fsSL --retry 3 --connect-timeout 10 "${RAW_BASE}/${relative}" -o "${destination}"
    fi
    [[ -s "${destination}" ]] || fatal "下载失败：${relative}"
}

install_shortcut() {
    cat >"${SHORTCUT_FILE}" <<'VPN'
#!/usr/bin/env bash
set -Eeuo pipefail

installer="$(mktemp /tmp/mxioc-vpn-menu.XXXXXX)"
cleanup() {
    [[ ! -f "${installer}" ]] || rm -f -- "${installer}"
}
trap cleanup EXIT

curl -fsSL --retry 3 --connect-timeout 10 \
    https://raw.githubusercontent.com/Angasky/mxioc-vpn-manager/main/install.sh \
    -o "${installer}"
chmod 0700 "${installer}"

if [[ "${EUID}" -eq 0 ]]; then
    /bin/bash "${installer}" "$@"
else
    sudo /bin/bash "${installer}" "$@"
fi
VPN
    chmod 0755 "${SHORTCUT_FILE}"
}

install_application() {
    STAGE_DIR="$(mktemp -d /tmp/mxioc-install.XXXXXX)"
    SOURCE_ROOT="$(local_source_root)"
    info "获取 MXIOC 管理后台程序……"
    stage_file server.py
    stage_file index.html
    stage_file requirements.txt
    stage_file deploy/mxioc-rule-manager.service
    stage_file templates/clash.yaml

    install -d -m 0755 "${APP_DIR}" "${APP_DIR}/code-backups" "${APP_DIR}/templates" "${CONFIG_DIR}"
    local stamp
    stamp="$(date +%Y%m%d-%H%M%S)"
    [[ ! -f "${APP_DIR}/server.py" ]] || cp -- "${APP_DIR}/server.py" "${APP_DIR}/code-backups/server.py.${stamp}"
    [[ ! -f "${APP_DIR}/index.html" ]] || cp -- "${APP_DIR}/index.html" "${APP_DIR}/code-backups/index.html.${stamp}"
    install -m 0644 "${STAGE_DIR}/server.py" "${APP_DIR}/server.py"
    install -m 0644 "${STAGE_DIR}/index.html" "${APP_DIR}/index.html"
    install -m 0644 "${STAGE_DIR}/requirements.txt" "${APP_DIR}/requirements.txt"
    install -m 0644 "${STAGE_DIR}/clash.yaml" "${APP_DIR}/templates/clash.yaml"

    if [[ ! -x "${APP_DIR}/venv/bin/python" ]]; then
        python3 -m venv "${APP_DIR}/venv"
    fi
    "${APP_DIR}/venv/bin/python" -m pip install --disable-pip-version-check --upgrade pip
    "${APP_DIR}/venv/bin/python" -m pip install --disable-pip-version-check -r "${APP_DIR}/requirements.txt"
    install -m 0644 "${STAGE_DIR}/mxioc-rule-manager.service" "${SERVICE_FILE}"
    install_shortcut
    success "程序文件与 Python 环境安装完成"
    success "快捷命令已安装：输入 vpn 即可打开管理菜单"
}

write_release_version() {
    local release_sha="${MXIOC_RELEASE_SHA:-}"
    if [[ -z "${release_sha}" && -n "${SOURCE_ROOT:-}" ]] && command -v git >/dev/null 2>&1; then
        release_sha="$(git -C "${SOURCE_ROOT}" rev-parse HEAD 2>/dev/null || true)"
    fi
    if [[ -z "${release_sha}" ]]; then
        release_sha="$(curl -fsSL --connect-timeout 10 -H 'Accept: application/vnd.github+json' \
            https://api.github.com/repos/Angasky/mxioc-vpn-manager/commits/main 2>/dev/null \
            | python3 -c 'import json,sys; print(json.load(sys.stdin).get("sha", ""))' 2>/dev/null || true)"
    fi
    if [[ "${release_sha}" =~ ^[0-9a-fA-F]{7,64}$ ]]; then
        printf '%s\n' "${release_sha}" > "${APP_DIR}/version"
        chmod 0644 "${APP_DIR}/version"
    fi
}

perform_update_only() {
    require_root
    detect_system
    install_packages
    install_application
    systemctl daemon-reload
    systemctl enable "${APP_NAME}" >/dev/null 2>&1 || true
    systemctl restart "${APP_NAME}"
    local ready=0
    local attempt
    for attempt in {1..30}; do
        if curl -fsS --max-time 2 http://127.0.0.1:62577/admin/ >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done
    [[ "${ready}" == "1" ]] || fatal "新版本启动失败，版本号未更新，请查看服务日志。"
    write_release_version
    success "后台程序已更新；现有订阅、节点、规则、域名和证书均未修改"
}

reset_admin_auth() {
    require_root
    command -v python3 >/dev/null 2>&1 || fatal "未找到 Python 3。"
    [[ -d "${APP_DIR}" ]] || fatal "未检测到已安装的 MXIOC 管理后台。"

    local current_username="admin"
    if [[ -s /etc/mxioc-rule-manager.auth.json ]]; then
        current_username="$(python3 -c 'import json; print(json.load(open("/etc/mxioc-rule-manager.auth.json", encoding="utf-8")).get("username", "admin"))' 2>/dev/null || echo admin)"
    fi
    local new_username=""
    local new_password=""
    local confirm_password=""
    prompt_value new_username "请输入新的管理员用户名 [${current_username}]：" "${current_username}"
    [[ ${#new_username} -ge 3 && ${#new_username} -le 64 ]] || fatal "用户名长度必须为 3–64 位。"
    [[ "${new_username}" != *:* && "${new_username}" != *[[:space:]]* ]] || fatal "用户名不能包含空格或冒号。"
    prompt_secret new_password "请输入新的管理员密码（至少 10 位）："
    prompt_secret confirm_password "请再次输入新密码："
    [[ ${#new_password} -ge 10 ]] || fatal "密码至少需要 10 位。"
    [[ "${new_password}" == "${confirm_password}" ]] || fatal "两次输入的密码不一致。"

    MXIOC_NEW_USERNAME="${new_username}" MXIOC_NEW_PASSWORD="${new_password}" python3 <<'PY'
import hashlib
import json
import os
import secrets
from pathlib import Path

path = Path("/etc/mxioc-rule-manager.auth.json")
salt = secrets.token_hex(16)
digest = hashlib.pbkdf2_hmac(
    "sha256", os.environ["MXIOC_NEW_PASSWORD"].encode(), bytes.fromhex(salt), 240000
).hex()
temporary = path.with_name(path.name + ".tmp")
temporary.write_text(json.dumps({
    "username": os.environ["MXIOC_NEW_USERNAME"],
    "salt": salt,
    "hash": digest,
}), encoding="utf-8")
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY
    rm -f "${APP_DIR}/sessions.json" "${APP_DIR}/initial-password.txt" /etc/mxioc-rule-manager.auth
    systemctl restart "${APP_NAME}" 2>/dev/null || true
    success "管理员凭证已重置，全部旧登录会话已退出"
    say "新管理员用户名：${C_YELLOW}${new_username}${C_RESET}"
}

uninstall_application() {
    require_root
    local confirmation=""
    if [[ "${PURGE_DATA}" == "1" ]]; then
        warn "彻底卸载会删除后台、后台数据以及主 Clash 订阅文件。"
        prompt_value confirmation "请输入 PURGE 确认彻底卸载："
        [[ "${confirmation}" == "PURGE" ]] || fatal "确认文字不正确，已取消卸载。"
    else
        warn "即将卸载管理后台；订阅和后台数据会先归档到 /var/backups。"
        prompt_value confirmation "请输入 UNINSTALL 确认卸载："
        [[ "${confirmation}" == "UNINSTALL" ]] || fatal "确认文字不正确，已取消卸载。"
    fi

    local backup_dir=""
    if [[ "${PURGE_DATA}" != "1" ]]; then
        backup_dir="/var/backups/mxioc-rule-manager-$(date +%Y%m%d-%H%M%S)"
        install -d -m 0700 "${backup_dir}"
        tar -czf "${backup_dir}/user-data.tar.gz" \
            /etc/sing-box/subscribe "${APP_DIR}/profiles.json" "${APP_DIR}/profiles" \
            "${APP_DIR}/backups" /etc/mxioc-rule-manager.auth.json \
            /etc/mxioc-rule-manager.auth 2>/dev/null || true
        [[ -s "${backup_dir}/user-data.tar.gz" ]] || fatal "用户数据归档失败，已取消卸载。"
        success "用户数据已归档到 ${backup_dir}/user-data.tar.gz"
    fi

    systemctl disable --now "${APP_NAME}" >/dev/null 2>&1 || true
    rm -f -- "${SERVICE_FILE}"
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -f -- "${NGINX_CONF}"
    if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
        systemctl reload nginx >/dev/null 2>&1 || true
    fi
    rm -f -- /etc/mxioc-rule-manager.auth.json /etc/mxioc-rule-manager.auth
    if [[ "${PURGE_DATA}" == "1" ]]; then
        rm -f -- /etc/sing-box/subscribe/clash-cn-route /etc/sing-box/subscribe/clash-cn-route.yml
    fi
    rm -f -- "${SHORTCUT_FILE}"
    rm -rf -- "${APP_DIR}"
    if [[ "${PURGE_DATA}" == "1" ]]; then
        success "MXIOC 管理后台及主订阅数据已彻底卸载"
    else
        success "MXIOC 管理后台已卸载；用户数据归档已保留"
    fi
}

create_initial_config() {
    [[ -s "${CONFIG_FILE}" ]] && {
        success "检测到现有订阅配置，已完整保留"
        return
    }
    info "创建初始 Clash/Mihomo 订阅配置……"
    cp -- "${APP_DIR}/templates/clash.yaml" "${CONFIG_FILE}"
    chmod 0644 "${CONFIG_FILE}"
    success "已使用内置完整模板创建初始订阅配置"
}

install_service() {
    systemctl daemon-reload
    systemctl enable --now "${APP_NAME}"
    local attempt
    for attempt in {1..20}; do
        if curl -fsS --max-time 2 http://127.0.0.1:62577/admin/ >/dev/null 2>&1; then
            success "MXIOC 后端服务已启动"
            return
        fi
        sleep 1
    done
    systemctl status "${APP_NAME}" --no-pager || true
    fatal "后端服务启动失败。"
}

prepare_nginx() {
    if [[ -L /etc/nginx/sites-enabled/default ]] \
        && [[ "$(readlink -f /etc/nginx/sites-enabled/default)" == "/etc/nginx/sites-available/default" ]]; then
        unlink /etc/nginx/sites-enabled/default
    fi
    if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
        setsebool -P httpd_can_network_connect 1 2>/dev/null || warn "SELinux 代理权限设置失败，请手动允许 Nginx 连接本机端口。"
    fi
}

proxy_location() {
    cat <<'NGINX'
    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:62577;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
NGINX
}

write_ip_nginx() {
    local server_name="${PRIMARY_IP} _"
    {
        cat <<EOF
server {
    listen ${HTTP_PORT};
    listen [::]:${HTTP_PORT};
    server_name ${server_name};
EOF
        proxy_location
        echo "}"
    } >"${NGINX_CONF}"
}

write_domain_challenge_nginx() {
    install -d -m 0755 "${ACME_ROOT}/.well-known/acme-challenge"
    {
        cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root ${ACME_ROOT};
        default_type text/plain;
    }
EOF
        proxy_location
        echo "}"
    } >"${NGINX_CONF}"
}

write_domain_tls_nginx() {
    local redirect_port=""
    [[ "${HTTPS_PORT}" == "443" ]] || redirect_port=":${HTTPS_PORT}"
    cat >"${NGINX_CONF}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root ${ACME_ROOT};
        default_type text/plain;
    }

    location / {
        return 301 https://\$host${redirect_port}\$request_uri;
    }
}

server {
    listen ${HTTPS_PORT} ssl http2;
    listen [::]:${HTTPS_PORT} ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
EOF
    proxy_location >>"${NGINX_CONF}"
    echo "}" >>"${NGINX_CONF}"
}

reload_nginx() {
    nginx -t
    systemctl enable nginx
    systemctl restart nginx
    success "Nginx 反向代理配置生效"
}

configure_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        if [[ "${MODE}" == "domain" ]]; then
            ufw allow 80/tcp >/dev/null
            ufw allow "${HTTPS_PORT}/tcp" >/dev/null
        else
            ufw allow "${HTTP_PORT}/tcp" >/dev/null
        fi
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if [[ "${MODE}" == "domain" ]]; then
            firewall-cmd --permanent --add-port=80/tcp >/dev/null
            firewall-cmd --permanent --add-port="${HTTPS_PORT}/tcp" >/dev/null
        else
            firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp" >/dev/null
        fi
        firewall-cmd --reload >/dev/null
    fi
}

main_subscription_path() {
    python3 -c 'import json, sys, urllib.parse
try:
    profiles = json.load(open("/opt/mxioc-rule-manager/profiles.json", encoding="utf-8"))["profiles"]
    record = next(item for item in profiles if item.get("id") == "clash")
    slug = record.get("slug")
    print("/sub/" + urllib.parse.quote(str(slug), safe="") if slug else "/clash")
except Exception:
    print("/clash")'
}

configure_ip_mode() {
    prepare_nginx
    write_ip_nginx
    reload_nginx
    configure_firewall
    local display_ip="${PRIMARY_IP}"
    [[ "${display_ip}" == *:* ]] && display_ip="[${display_ip}]"
    local authority="${display_ip}"
    [[ "${HTTP_PORT}" == "80" ]] || authority="${display_ip}:${HTTP_PORT}"
    ACCESS_URL="http://${authority}/admin/"
    SUBSCRIPTION_URL="http://${authority}$(main_subscription_path)"
}

configure_domain_mode() {
    prepare_nginx
    write_domain_challenge_nginx
    reload_nginx
    configure_firewall

    if [[ -z "${CERT_EMAIL}" ]]; then
        prompt_value CERT_EMAIL "请输入证书通知邮箱（可留空）："
    fi
    local email_args=()
    if [[ -n "${CERT_EMAIL}" ]]; then
        [[ "${CERT_EMAIL}" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || fatal "邮箱格式不正确。"
        email_args=(--email "${CERT_EMAIL}")
    else
        email_args=(--register-unsafely-without-email)
    fi

    info "向 Let's Encrypt 申请 ${DOMAIN} 的 HTTPS 证书……"
    certbot certonly --webroot -w "${ACME_ROOT}" --non-interactive --agree-tos \
        --keep-until-expiring --deploy-hook "systemctl reload nginx" \
        "${email_args[@]}" -d "${DOMAIN}"
    [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]] || fatal "证书文件未生成。"
    write_domain_tls_nginx
    reload_nginx
    systemctl enable --now certbot.timer 2>/dev/null || true
    success "HTTPS 证书申请及域名绑定完成"
    local authority="${DOMAIN}"
    [[ "${HTTPS_PORT}" == "443" ]] || authority="${DOMAIN}:${HTTPS_PORT}"
    ACCESS_URL="https://${authority}/admin/"
    SUBSCRIPTION_URL="https://${authority}$(main_subscription_path)"
}

show_result() {
    local initial_password=""
    [[ ! -f "${APP_DIR}/initial-password.txt" ]] || initial_password="$(cat "${APP_DIR}/initial-password.txt")"
    say ""
    say "${C_GREEN}╭──────────────────────────────────────────────────────────╮${C_RESET}"
    say "${C_GREEN}│                 MXIOC 部署完成                            │${C_RESET}"
    say "${C_GREEN}╰──────────────────────────────────────────────────────────╯${C_RESET}"
    say "后台地址：${C_CYAN}${ACCESS_URL}${C_RESET}"
    say "订阅地址：${C_CYAN}${SUBSCRIPTION_URL}${C_RESET}"
    say "管理员账号：${C_YELLOW}admin${C_RESET}"
    if [[ -n "${initial_password}" ]]; then
        say "初始密码：${C_YELLOW}${initial_password}${C_RESET}"
        say "${C_DIM}首次登录后请在后台修改密码。${C_RESET}"
    else
        say "管理员密码：${C_DIM}保留现有密码${C_RESET}"
    fi
    if [[ "${MODE}" == "domain" ]]; then
        say "证书续期：${C_GREEN}Certbot 自动续期已启用${C_RESET}"
    else
        warn "当前模式使用 HTTP，登录信息不会经过 TLS 加密；长期使用建议改为域名 HTTPS 模式。"
    fi
    say ""
}

main() {
    parse_args "$@"
    banner
    choose_action
    case "${ACTION}" in
        update)
            perform_update_only
            return
            ;;
        reset-auth)
            reset_admin_auth
            return
            ;;
        uninstall)
            uninstall_application
            return
            ;;
    esac
    require_root
    detect_system
    install_packages
    collect_server_ips
    configure_access_port
    [[ "${MODE}" != "domain" ]] || verify_domain_dns
    install_application
    create_initial_config
    install_service
    write_release_version
    if [[ "${MODE}" == "domain" ]]; then
        configure_domain_mode
    else
        configure_ip_mode
    fi
    show_result
}

if [[ "${MXIOC_SOURCE_ONLY:-0}" != "1" ]]; then
    main "$@"
fi
