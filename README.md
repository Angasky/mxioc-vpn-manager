# Mxioc VPN 配置管理后台

用于管理 Mihomo/Clash YAML 订阅配置的轻量级网页后台。项目由 Python 后端和单页前端组成，不依赖数据库。

## 功能

- 多订阅配置的新建、复制、重命名和删除
- VLESS、TUIC、Hysteria2 等节点的表单管理和链接导入
- 入口中转节点与出口落地节点的可视化链式代理配置
- Clash YAML/Base64 订阅链接的批量导入、重名处理与策略组多选
- 面向新版 v2rayN 和 Shadowrocket 的 Base64 转换订阅链接
- 转换前兼容性报告；无法表达两跳关系的链式节点会明确跳过
- 策略组、路由规则与 DNS 分流的可视化管理
- 修改前自动备份配置文件
- 登录认证、会话过期和密码修改
- 广告规则库的定时更新工具
- 订阅下载文件名与流量统计响应头

## 安全说明

仓库只包含程序源码和部署模板，不包含生产环境的订阅文件、节点链接、认证文件、备份、TLS 私钥或服务器密码。请勿把这些运行数据提交到 Git。

## 环境要求

- Linux 服务器
- Python 3.9+
- PyYAML
- Nginx（用于 HTTPS 和反向代理）
- systemd（推荐）

## 安装

```bash
sudo install -d -m 0755 /opt/mxioc-rule-manager
sudo install -m 0644 server.py index.html /opt/mxioc-rule-manager/
sudo python3 -m pip install -r requirements.txt
sudo install -m 0644 deploy/mxioc-rule-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mxioc-rule-manager
```

首次启动时，程序会生成管理员账号 `admin` 和随机密码。初始密码保存在：

```text
/opt/mxioc-rule-manager/initial-password.txt
```

登录并修改密码后，应删除这个初始密码文件。

## 配置文件位置

主配置默认从以下路径读取，优先使用第一个存在的文件：

```text
/etc/sing-box/subscribe/clash-cn-route
/etc/sing-box/subscribe/clash-cn-route.yml
```

管理后台监听 `127.0.0.1:62577`。生产环境应通过 Nginx 提供 HTTPS，不要把该端口直接开放到公网。参考配置见 `deploy/nginx.conf.example`。

## 广告规则自动更新

可选安装：

```bash
sudo install -m 0755 work/update-ad-rules.py /usr/local/libexec/update-mxioc-ad-rules.py
sudo install -m 0644 work/mxioc-ad-rules.service work/mxioc-ad-rules.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mxioc-ad-rules.timer
```

## 更新部署

拉取新版本后，将 `server.py` 与 `index.html` 覆盖到 `/opt/mxioc-rule-manager/`，然后重启服务：

```bash
sudo systemctl restart mxioc-rule-manager
```

GitHub 用于托管源码和版本记录；正在运行的管理后台仍部署在自己的服务器上。
