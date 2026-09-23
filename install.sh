#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="mxioc-rule-manager"
APP_DIR="/opt/${APP_NAME}"
CONFIG_DIR="/etc/sing-box/subscribe"
CONFIG_FILE="${CONFIG_DIR}/clash-cn-route"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
NGINX_CONF="/etc/nginx/conf.d/${APP_NAME}.conf"
RAW_BASE="${MXIOC_RAW_BASE:-https://raw.githubusercontent.com/Angasky/mxioc-vpn-manager/main}"
MODE=""
DOMAIN=""
CERT_EMAIL=""
ACCESS_URL=""
SUBSCRIPTION_URL=""
STAGE_DIR=""
UPDATE_ONLY=0

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
  sudo bash install.sh --update-only    只更新后台程序，不修改现有配置和部署方式

可选参数：
  --email 邮箱      Let's Encrypt 到期通知邮箱
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

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ip)
                MODE="ip"
                shift
                ;;
            --domain)
                [[ $# -ge 2 ]] || fatal "--domain 后必须填写域名"
                MODE="domain"
                DOMAIN="$2"
                shift 2
                ;;
            --email)
                [[ $# -ge 2 ]] || fatal "--email 后必须填写邮箱"
                CERT_EMAIL="$2"
                shift 2
                ;;
            --update-only)
                UPDATE_ONLY=1
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

choose_mode() {
    [[ -n "${MODE}" ]] && return
    say "${C_CYAN}请选择部署方式${C_RESET}"
    say "  ${C_GREEN}1)${C_RESET} IP 部署模式      ${C_DIM}通过 http://服务器IP 访问${C_RESET}"
    say "  ${C_GREEN}2)${C_RESET} 域名 HTTPS 模式  ${C_DIM}校验解析后自动申请并续期证书（推荐）${C_RESET}"
    say "  ${C_RED}0)${C_RESET} 退出"
    say ""
    local choice=""
    prompt_value choice "请输入选项 [1-2]："
    case "${choice}" in
        1) MODE="ip" ;;
        2) MODE="domain" ;;
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
        say "${C_RED}域名解析校验未通过。${C_RESET}"
        say "  域名当前解析：${DNS_IPS[*]}"
        say "  本服务器地址：${SERVER_IPS[*]}"
        say "  不属于本机的记录：${mismatched[*]}"
        fatal "请修正 DNS；如果使用 Cloudflare，请暂时关闭代理云朵并设为“仅 DNS”。"
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
    success "程序文件与 Python 环境安装完成"
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
    listen 80;
    listen [::]:80;
    server_name ${server_name};
EOF
        proxy_location
        echo "}"
    } >"${NGINX_CONF}"
}

write_domain_nginx() {
    {
        cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
EOF
        proxy_location
        echo "}"
    } >"${NGINX_CONF}"
}

reload_nginx() {
    nginx -t
    systemctl enable nginx
    systemctl restart nginx
    success "Nginx 反向代理配置生效"
}

configure_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow 80/tcp >/dev/null
        [[ "${MODE}" != "domain" ]] || ufw allow 443/tcp >/dev/null
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-service=http >/dev/null
        [[ "${MODE}" != "domain" ]] || firewall-cmd --permanent --add-service=https >/dev/null
        firewall-cmd --reload >/dev/null
    fi
}

configure_ip_mode() {
    prepare_nginx
    write_ip_nginx
    reload_nginx
    configure_firewall
    local display_ip="${PRIMARY_IP}"
    [[ "${display_ip}" == *:* ]] && display_ip="[${display_ip}]"
    ACCESS_URL="http://${display_ip}/admin/"
    SUBSCRIPTION_URL="http://${display_ip}/clash"
}

configure_domain_mode() {
    prepare_nginx
    write_domain_nginx
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
    certbot --nginx --non-interactive --agree-tos --redirect --keep-until-expiring \
        "${email_args[@]}" -d "${DOMAIN}"
    nginx -t
    systemctl reload nginx
    systemctl enable --now certbot.timer 2>/dev/null || true
    [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]] || fatal "证书文件未生成。"
    success "HTTPS 证书申请及域名绑定完成"
    ACCESS_URL="https://${DOMAIN}/admin/"
    SUBSCRIPTION_URL="https://${DOMAIN}/clash"
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
    if [[ "${MODE}" == "ip" ]]; then
        warn "IP 模式使用 HTTP，登录信息不会经过 TLS 加密；长期使用建议改为域名 HTTPS 模式。"
    else
        say "证书续期：${C_GREEN}Certbot 自动续期已启用${C_RESET}"
    fi
    say ""
}

main() {
    parse_args "$@"
    if [[ "${UPDATE_ONLY}" == "1" ]]; then
        perform_update_only
        return
    fi
    banner
    choose_mode
    require_root
    detect_system
    install_packages
    collect_server_ips
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
