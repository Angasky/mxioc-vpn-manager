# 🚀 MXIOC VPN Manager

一个面向 Mihomo / Clash 的可视化订阅管理后台。无需数据库，通过网页即可管理节点、链式代理、策略组、路由规则、DNS 分流和多份订阅配置。

## ⚡ 一键安装

在 Linux 服务器中执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Angasky/mxioc-vpn-manager/main/install.sh | sudo bash
```

安装完成后，服务器会自动创建快捷命令：

```bash
vpn
```

以后输入 `vpn` 就能重新打开管理菜单，不需要再次复制安装命令。普通用户执行时会自动调用 `sudo`。

```text
1) 🌐 IP 部署模式
2) 🔒 域名 HTTPS 模式
3) ⬆️ 升级 / 修复
4) 🔑 重置管理员凭证
5) 📦 卸载并保留数据
6) 🗑️ 彻底卸载
0) 👋 退出
```

> 推荐选择域名 HTTPS 模式。脚本会检查域名的 A/AAAA 记录，确认已经指向当前服务器后，自动申请并续期 Let's Encrypt 证书。

## ✨ 主要功能

### 🧩 节点与订阅

- VLESS、TUIC、Hysteria2、Trojan、Shadowsocks、VMess、SOCKS5、HTTP 和 HTTPS 节点管理
- 节点分享链接一键导入，兼容 IPv4 与 IPv6
- Clash YAML / Base64 订阅批量导入
- 总览集中展示 Clash、V2Ray/v2rayN 与 Shadowrocket 订阅，并为每个链接生成本地二维码
- 公开订阅地址无需后台登录 Cookie，可直接粘贴或扫码导入客户端
- 节点拖动排序、上移、下移、全选和批量删除
- 根据节点公网 IP 自动添加国家旗帜，重复执行不会叠加
- 多订阅的新建、复制、重命名、切换和删除
- 转换为 v2rayN 与 Shadowrocket 可用的 Base64 订阅
- 转换前显示协议兼容性，无法转换的节点会明确提示

### 🔗 链式代理

- 可视化选择入口节点和出口节点
- 自定义链式代理名称
- 选择加入一个、多个或全部策略组
- 删除普通节点时自动清理策略组中的失效引用

### 🧭 规则与 DNS

- 策略组、路由规则和 DNS 分流的可视化增删改查
- 中国业务直连，境外业务使用加密海外 DNS
- Google、YouTube、TikTok、Facebook、Telegram、Netflix、WhatsApp、X 等独立业务分组
- Google 网页、Android、Play、FCM、Firebase、Drive、Gemini 等业务完整分流
- YouTube 保持独立策略，不与其他 Google 服务混用
- 基础广告拦截与强力广告拦截
- 内置完整无私人节点的 Clash 起始模板

### 🛡️ 系统管理

- 兼容 IP/HTTP 与域名/HTTPS 登录
- 登录状态持久保存 30 天
- 网页和 Linux 菜单均可修改管理员用户名与密码
- 每天自动检查 GitHub 更新
- 网页和 `vpn` 菜单均可升级或修复程序
- 修改配置前自动创建快照备份
- 支持保留数据卸载与彻底卸载

## 🖥️ 快捷命令

安装后直接运行：

```bash
vpn
```

也可以跳过菜单，直接指定操作：

```bash
# 🌐 IP 模式
vpn --ip

# 🔒 域名 HTTPS 模式
vpn --domain vpn.example.com --email admin@example.com

# ⬆️ 升级或修复
vpn --update-only

# 🔑 重置管理员用户名和密码
vpn --reset-auth

# 📦 卸载后台并归档用户数据
vpn --uninstall

# 🗑️ 彻底卸载后台和主订阅
vpn --purge
```

快捷命令每次运行都会获取仓库中的最新管理脚本，因此菜单功能会保持最新。

## 🔐 首次登录

首次安装会生成管理员账号 `admin` 和随机密码：

```text
/opt/mxioc-rule-manager/initial-password.txt
```

登录后可以在“账号与安全”中修改用户名和密码，也可以运行：

```bash
vpn --reset-auth
```

修改凭证后，所有旧登录会话都会自动失效。

## 📦 升级与卸载

### 升级

```bash
vpn --update-only
```

升级只替换后台程序、服务文件和内置模板，不会覆盖正在使用的节点、规则、订阅、管理员凭证、历史备份和 TLS 证书。

### 保留数据卸载

```bash
vpn --uninstall
```

用户数据会先归档至：

```text
/var/backups/mxioc-rule-manager-日期时间/user-data.tar.gz
```

归档失败时会自动取消卸载。

### 彻底卸载

```bash
vpn --purge
```

彻底卸载会删除管理后台、后台运行数据和主 Clash 订阅，但不会删除其他 sing-box 文件或服务器上的 TLS 证书。

## 📁 重要路径

```text
程序目录        /opt/mxioc-rule-manager
快捷命令        /usr/local/bin/vpn
认证文件        /etc/mxioc-rule-manager.auth.json
主订阅          /etc/sing-box/subscribe/clash-cn-route
主订阅备用路径  /etc/sing-box/subscribe/clash-cn-route.yml
Nginx 配置       /etc/nginx/conf.d/mxioc-rule-manager.conf
systemd 服务    /etc/systemd/system/mxioc-rule-manager.service
数据归档        /var/backups/mxioc-rule-manager-日期时间
```

后台程序只监听 `127.0.0.1:62577`，公网访问由 Nginx 反向代理提供。

## 🧰 环境要求

- Debian / Ubuntu
- RHEL / CentOS / Rocky Linux / AlmaLinux
- Python 3.9+
- systemd
- Nginx
- 可访问 GitHub 与系统软件源

安装脚本会自动准备 Python、PyYAML、Nginx、Curl、DNS 工具和证书组件。

## 🚫 广告规则自动更新

需要定时更新本地广告规则时可以启用：

```bash
sudo install -m 0755 work/update-ad-rules.py /usr/local/libexec/update-mxioc-ad-rules.py
sudo install -m 0644 work/mxioc-ad-rules.service work/mxioc-ad-rules.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mxioc-ad-rules.timer
```

## 🔒 数据安全

仓库只保存程序源码和无私人节点的模板，不包含生产环境中的节点链接、服务器密码、管理员密码、订阅文件、历史备份或 TLS 私钥。

节点国旗识别会把节点服务器 IP 发送给 `api.country.is`，仅用于获取 ISO 国家代码，查询结果会在内存中缓存七天。

## 🧪 开发检查

```bash
python -m pytest -q
bash -n install.sh
```

项目当前由 Python 后端、单页网页前端、Nginx 和 systemd 组成，不依赖数据库。
