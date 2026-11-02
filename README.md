<p align="center"><img src="docs/assets/readme-banner.svg" alt="MXIOC · 节点、订阅与服务器管理" width="100%"></p>

<h1 align="center">MXIOC VPN Manager</h1>
<p align="center">把节点、订阅和服务器，放进一个清爽的控制台。</p>

<p align="center">
  <a href="#快速开始">快速开始</a> ·
  <a href="docs/server-node-workflow.md">使用指南</a> ·
  <a href="CHANGELOG.md">更新日志</a> ·
  <a href="https://github.com/Angasky/mxioc-vpn-manager/issues">反馈问题</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Mihomo%20%2F%20Clash-订阅管理-2563eb?style=flat-square" alt="Mihomo / Clash 订阅管理">
  <img src="https://img.shields.io/badge/Python-轻量部署-0f766e?style=flat-square" alt="Python 轻量部署">
  <img src="https://img.shields.io/badge/UI-三种主题-7c3aed?style=flat-square" alt="三种主题">
</p>

## 一个面板，管理日常所需

- **节点** — 链接导入、卡片排序、策略组分配、二维码分享。
- **订阅** — 多订阅管理、套餐模板、额度与有效期、客户端格式转换。
- **服务器** — 接入已有面板、创建节点、HY2 模板、硬件监控。
- **分流** — 策略组、路由规则、DNS 与链式代理，可视化配置。

支持 VLESS、VMess、Trojan、Shadowsocks、HY2、TUIC、Snell、Mieru、SOCKS5 等协议。各客户端与服务器内核的支持范围见[兼容说明](docs/client-compatibility.md)。

## 快速开始

在 Linux 服务器执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Angasky/mxioc-vpn-manager/main/install.sh | sudo bash
```

完成安装后，使用 `vpn` 打开管理菜单、升级或重置账号。

**第一次使用：** 新建订阅 → 导入链接或接入服务器 → 分配策略组 → 复制订阅到客户端。

<details>
<summary>部署前准备</summary>

- 使用支持 systemd 的 Linux，以及 root 或 sudo 权限。
- 域名 HTTPS 模式：先解析域名，使用 Cloudflare 时切换为「仅 DNS」，放行证书验证所需端口。
- 创建 TLS / HY2 节点需要远端证书和私钥；HY2 还需放行对应 UDP 端口。

</details>

## 按需阅读

[服务器与节点](docs/server-node-workflow.md) · [客户端兼容](docs/client-compatibility.md) · [流量与倍率](docs/traffic-multiplier-bandwidth.md)

[Snell](docs/snell.md) · [HY2 连通测试](docs/hy2-testing.md) · [多入口主备](docs/multi-entry-failover.md) · [性能](docs/performance.md)

<details>
<summary>开发与历史参考</summary>

回归测试：`python -m unittest discover -s tests`。真实内核测试方法见 [HY2 测试文档](docs/hy2-testing.md)。

[历史完整说明](docs/legacy-reference.md)保留此前的部署与实现细节；部分描述对应旧版本，请结合更新日志阅读。

</details>

---

<p align="center"><sub>MXIOC · 简化管理，专注连接。</sub></p>
