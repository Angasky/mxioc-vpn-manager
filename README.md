# 🚀 MXIOC VPN Manager

[Snell 节点使用说明](docs/snell.md) · 支持 Mihomo v1–v5 节点添加、编辑与导入。

一个面向 Mihomo / Clash 的可视化订阅管理后台。无需数据库，通过网页即可管理节点、链式代理、策略组、路由规则、DNS 分流和多份订阅配置。

[中文更新日志](CHANGELOG.md) · [客户端适配说明](docs/client-compatibility.md)

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
3) ⚡ 极速安装模式
4) ⬆️ 升级 / 修复
5) 🔑 重置管理员凭证
6) 📦 卸载并保留数据
7) 🗑️ 彻底卸载
0) 👋 退出
```

> 推荐选择域名 HTTPS 模式。脚本会检查域名的 A/AAAA 记录，识别 Cloudflare 小黄云状态，并自动申请和续期 Let's Encrypt 证书。

### 三种部署方式

- 🌐 **IP 模式**：默认使用 80 端口；直接回车保留默认值，也可以填写其他端口。
- 🔒 **域名 HTTPS 模式**：默认使用 443 端口，也可以自定义 HTTPS 端口；80 端口始终保留给证书验证和续期。
- ⚡ **极速模式**：不询问域名和端口，默认使用 5656；如果端口已占用，会自动选择其他空闲端口。

使用 Cloudflare 托管域名时，如果检测到小黄云代理已开启，安装器会停止申请证书并提示先切换到“仅 DNS（灰色云朵）”。

## ✨ 主要功能

### 🧩 节点与订阅

- VLESS、TUIC、Hysteria2、Trojan、Shadowsocks、VMess、Mieru、SOCKS5、HTTP 和 HTTPS 节点管理
- 节点分享链接一键导入，兼容 IPv4 与 IPv6
- Clash YAML / Base64 订阅批量导入
- 总览集中展示 Clash、V2Ray/v2rayN 与 Shadowrocket 订阅，并为每个链接生成本地二维码
- 公开订阅地址无需后台登录 Cookie，可直接粘贴或扫码导入客户端
- 节点拖动排序、上移、下移、全选和批量删除
- 根据节点公网 IP 自动添加国家旗帜，重复执行不会叠加
- 多订阅的新建、复制、重命名、切换和删除
- 独立“订阅管理”页面：搜索名称/标识、筛选状态、按名称或创建顺序排序，并按页显示订阅卡片
- 顶部显示当前订阅，点击进入管理页面切换；不再通过长下拉列表选择配置
- 订阅卡片可直接进入节点配置、设置流量、复制链接、显示二维码、复制为新订阅或重命名
- 新安装与新建订阅默认使用约 256-bit 强度的随机访问密钥，不再暴露固定 `/clash` 地址
- 需要固定路径时可以手动开启自定义 Slug，但长度必须为 32–80 位
- 转换为 v2rayN 与 Shadowrocket 可用的 Base64 订阅
- 转换前显示协议兼容性，无法转换的节点会明确提示
- 每份订阅独立设置流量额度、已用上传/下载流量、到期时间；总览显示用量与剩余额度
- Clash / Mihomo、V2Ray 和 Shadowrocket 三种订阅统一返回标准 `Subscription-Userinfo`，支持 GET 与 HEAD
- 未配置流量时不再返回虚假的总额度和到期日期

### 📊 流量与到期

选择当前订阅后，打开侧栏“流量与到期”，填写总额度、已用上传与下载流量，以及本地时间的到期日期。
支持 GiB、MiB、TiB 单位；总额度留空表示不限，到期日期留空表示长期有效。保存后，在客户端手动更新订阅即可读取新的信息。

未绑定服务器用户时，这是管理员维护的展示数据。通过总控添加独立订阅用户并启用服务器强制限制后，可自动采集该用户流量、执行额度和到期撤销；多个订阅共用入站端口。用法、旧绑定迁移和内核条件见 [共用入站与独立订阅用户](docs/shared-inbound-users.md)。
三个导出格式使用相同的统计来源；客户端是否显示额度卡片取决于其版本和对订阅响应头的支持。
数据持久保存在现有 `profiles.json` 中；复制订阅模板时不会复制其他订阅的流量用量。

### 🎨 界面与性能

- 统一深色配色、表单、列表、弹窗与手机导航
- 首次访问先验证会话，避免登录页和后台界面相互闪现
- 订阅卡片、节点、链路、策略组、路由规则和 DNS 列表每页最多 50 项
- 搜索延迟 120 ms 合并输入，并保留输入框焦点和光标
- 无外部字体、动画库或新增生产前端依赖
- “设置”中可选择科技主题（终端工作台）、简洁主题（轻量界面）、猛男主题（暖粉界面），立即切换并保存在当前浏览器
- 新安装及未保存主题偏好的浏览器默认使用科技主题；保留旧版主题偏好。简洁主题关闭持续闪烁和弹窗背景模糊；猛男主题参考暖色留白、衬线标题和柔和圆角布局
- 主题偏好在样式绘制前读取，避免先显示默认主题再切换的闪屏；系统开启“减少动态效果”时停用动画

### 🔗 链式代理

- 可视化选择入口节点和出口节点
- 自定义链式代理名称
- 选择加入一个、多个或全部策略组
- 删除普通节点时自动清理策略组中的失效引用

### 🖥️ 服务器管理与 3x-ui

侧栏“服务器管理”可登记服务器 IP、SSH 账号、密码、SSH 端口，以及预设的 3x-ui 面板账号、密码和可选域名。

新增服务器时可选择 **3x-ui 面板（含 Xray）**、**独立 Xray** 或 **独立 sing-box**。旧记录默认使用 3x-ui，现有面板接入模式不变。

独立内核通过 [Xray 官方安装器](https://github.com/XTLS/Xray-install) 或 [sing-box 官方安装器](https://sing-box.app/install.sh) 安装，要求 Linux / systemd 和 root / sudo。无需面板账号密码，不会安装 Web 面板。可填写包含 `inbounds` 和 `outbounds` 数组的完整 JSON 配置；配置加密保存在本机且不会回显，留空继续使用此前保存的配置，勾选清除后下次安装保留远端配置。首次安装留空使用官方默认配置，不会自动创建可连接的节点。

内核安装保留已有配置，提交的新配置先经 `xray run -test` 或 `sing-box check` 校验，再重启并检查服务。失败会尝试恢复安装前配置并重启；这不是二进制版本回滚。配置路径分别为 `/usr/local/etc/xray/config.json`、`/etc/sing-box/config.json`。替换已有配置时保留 `.mxioc-backup` 备份。独立内核的域名、证书及监听端口需要在 JSON 中配置并自行放行防火墙；内核更新可能产生短暂服务中断。

独立内核现支持总控创建的模板入站、启停、删除、链接导出和中转。原生配置中未由总控创建的入站会保留，但不会冒充为可删除的总控节点。Xray / sing-box 的应用变更先调用原生校验命令，通过后替换配置并重启服务，失败尝试恢复原配置；因此变更会短暂影响该内核的其他连接。

模板包括 VLESS Reality/Vision、VMess TCP、Shadowsocks AES-128-GCM、Trojan TLS、VLESS WebSocket TLS；sing-box 另支持 Hysteria2 TLS、TUIC TLS。TLS 模板要求填写远端已有证书和私钥的绝对路径。中转落地支持 VLESS、VMess、Trojan、Shadowsocks、SOCKS5、HTTP，sing-box 还支持 Hysteria2 / TUIC。

[xeefei/X-Panel](https://github.com/xeefei/X-Panel) 通过“添加已安装面板的服务器 → 现有 X-Panel”接入；适配带中文标注的 CLI 输出、会话登录、入站 API 及 Xray 配置接口。现有 X-ui 会先探测 `/panel/api`，仅在入站列表明确返回 404 后尝试 `/xui/API`；未识别版本报错，不会通过试写探测接口。X-ui / X-Panel 的第三方交互式安装器不在总控中自动运行，必须先自行安装。切换安装类型不会卸载原软件；有关联专属节点时禁止更换服务器地址、内核类型或覆盖整份配置。

已有 X-ui / 3x-ui 时，点击“添加已安装面板的服务器”，填写 SSH 信息和现有面板账号密码（不是设置新密码）。系统仅通过 SSH 读取 `/usr/local/x-ui` 的面板设置，验证登录及入站列表，然后返回管理地址；不运行安装脚本、不重置凭证、不修改原有节点。该模式不提供安装/更新按钮，后端也禁止安装。没有 API 令牌的版本使用登录会话；旧版无 CSRF 接口时仅在明确返回 404 后兼容。需支持 `/panel/api/inbounds/list` 或 `/xui/API/inbounds/list` 等入站 API；不兼容的版本会显示验证错误，连接信息仍保留以便修正后重试。可在接入后继续管理节点；中转功能仍取决于对应版本是否支持所需的 Xray 配置接口。
SSH 账号需要 root 或 sudo 权限。首次连接先检测、核对并固定 SSH 主机指纹；指纹变化会中止连接。

1. 添加服务器，填写 SSH 信息和至少 12 位的面板密码，选择无域名或绑定域名模式并保存。
2. 使用“测试 SSH”检查认证和提权权限，再点击“安装 / 更新”确认执行。
3. 安装在后台运行，可关闭日志窗口后重新打开。日志显示阶段、真实错误和退出码，密码和令牌会脱敏。
4. 脚本完成后设置预设面板凭证，验证登录、服务和 API，读取远端实际端口及路径并返回面板地址。
5. 失败时自动读取服务状态、最近日志、监听端口和域名解析；排查后可重试。不会自动清空远端数据或把失败的域名安装改成 HTTP。

安装来源固定为用户指定的 [Teminuosi/3x-ui 安装脚本](https://github.com/Teminuosi/3x-ui/blob/main/install.sh)。
域名模式以 `XUI_DOMAIN=域名` 执行，无域名模式以 `XUI_AUTO=1` 执行。
脚本先下载并检查下载退出码再运行，避免下载失败被误认为安装完成。该脚本生成的随机初始凭证会在安装结束后替换为表单中预设的账号密码。
绑定域名时请先完成 DNS 解析并放行 80 端口；还需在云防火墙放行实际面板端口和需要使用的节点端口。

“节点 / 中转”直接调用该分支的 3x-ui 接口：

- 新建 VLESS + Reality/Vision、VMess TCP、Shadowsocks AES-128-GCM 入站。
- 通过 JSON 编辑入站配置，启用、停用、删除，复制分享链接并导入当前订阅。
- 新建中转时以 Reality 为入口，落地支持 VLESS、VMess、Trojan、Shadowsocks、SOCKS5、HTTP 分享链接。
- 中转会创建入口入站、落地出站、最高优先级路由；保留原有配置并加密保存变更前备份。失败时尝试恢复配置并删除本次入口，部分恢复失败会明确提示。
- 删除本面板创建的中转入站时会同步清理其路由和出站；本地已导入的订阅链接仍需单独清理。
- “移除管理”只删除总面板中的登记与凭证，不卸载远端 3x-ui。

管理 API 通过固定主机指纹的 SSH 隧道访问远端回环地址，支持面板 HTTP/HTTPS、Bearer 令牌及登录 CSRF 会话。
SSH 与面板密码加密保存在 `/opt/mxioc-rule-manager/remote/servers.json`，密钥在同目录 `credentials.key`；目录权限为 0700、文件为 0600。
备份或迁移时须同时保存数据和密钥，丢失密钥后需重新填写服务器凭证。保留数据卸载会把该目录一并归档。
总面板重启会把尚未确认完成的任务标记为中断，请先诊断远端运行状态再重试；安装器使用远端锁防止重复安装。
本功能需要总面板运行 Python 3.9+，升级脚本会安装固定版本的 Paramiko 与 Cryptography。

### X-Panel 登录兼容

总控针对 X-Panel 使用独立、仅驻内存的登录会话，按服务器、SSH 指纹、账号及准确访问地址隔离；会话不会发给浏览器或写入服务器记录。重复读取节点不重复登录，凭证或地址变化后重新认证。只有明确的 HTTP 401 认证拒绝会重试一次；超时、未知响应及 CSRF 错误不自动重放操作。登录失败后暂停 60 秒，避免后台扫描持续提交旧密码。

X-Panel 不再执行 `x-ui setting` 或不存在的 `-getApiToken` 查询。填写完整面板地址时直接使用地址；自动识别只以 SQLite `mode=ro`、`query_only` 读取已存在数据库的端口、路径、域名和证书配置，不启动数据库迁移、不改密码或重启服务。非默认数据库位置请填写完整地址。

该兼容修复不等于已经复现所有版本的手动登录闪退。若升级后仍出现登录循环，需核对实际 X-Panel 版本、反向代理与浏览器 Cookie；多个面板共用同一域名/IP、仅端口不同时，Cookie 名称和根路径可能冲突，应分别使用不同子域名。上游参考：[Cookie 会话设置](https://github.com/xeefei/X-Panel/blob/main/web/web.go)、[会话路径](https://github.com/xeefei/X-Panel/blob/main/web/session/session.go)、[设置命令初始化](https://github.com/xeefei/X-Panel/blob/main/main.go)。本次验证为本地 HTTP/SSH 转发替身，不是生产服务器实测。

### 服务器硬件监控

左侧“硬件监控”进入服务器卡片概览，支持按名称、IP、内核搜索，每页 18 台，展示 CPU、内存、磁盘及采样状态；点击卡片进入单台详情，不再通过下拉菜单切换服务器。概览仅对当前页采样、最多 3 个并发，每轮完成后 30 秒更新；详情保留 5 秒采样。切页、隐藏标签页会停止后续任务并取消前端请求，恢复可见后继续。错误与历史采样明确标记，未知值不显示为零。

采样通过已有固定指纹 SSH 连接，只读访问 Linux `/proc`、挂载信息和 `ip -j address`，无需增加监听端口或常驻代理；需要 Python 3，网卡地址列表需要 iproute2。

显示整体 / 每核 CPU、1/5/15 分钟负载、内存 / Swap、磁盘挂载点与可用空间、持续运行时间、默认路由网卡入站 / 出站速度及累计字节、SSH 目标 IP 和本机 IPv4 / IPv6。可切换网卡并查看最近 60 次有效采样趋势；默认汇总默认路由网卡，减少虚拟网卡重复计数。累计流量从开机或计数器重置起计算，与订阅计费统计分别展示。

首次采样、重启或采样间隔超过 60 秒时，CPU 百分比和速度显示等待状态；需要第二次采样才能计算。每台主机缓存 5 秒，多访问者合并 SSH 采样；失败时明确标记历史数据和错误，不把旧数据冒充实时值。后台标签页或离开页面时停止轮询，恢复页面后继续。NAT 场景只展示登记的 SSH 目标和本机地址，不通过内网地址猜测公网映射。

### 主题、图标与节点编辑

三个主题使用相同的功能组件和语义化设计变量，分别定义颜色、字体、表面、按钮、表单、表格、弹窗、状态、焦点和滚动区域。终端网格 / 光晕仅作用于科技主题；切换主题时整帧更新颜色，避免中间态混色。侧栏使用 22px 的 [Lucide](https://github.com/lucide-icons/lucide) SVG 图标（ISC，见 `LICENSES/lucide.txt`），已嵌入页面，不依赖 CDN。

节点编辑可生成 UUID，校验端口、UUID、Reality 公钥 / Short ID、Vision 传输组合和 Shadowsocks 2022 密钥长度，并在保存前“校验与预览”规范化配置。预览不连接服务器、不证明节点连通，也不保存配置；编辑后旧预览失效。高级参数会保留，提交中禁用重复保存。

后端快照缓存、压缩和本地测量见 [性能说明](docs/performance.md)。本轮保留 Python 接口，不进行未经兼容性验证的整站语言迁移。

### 服务器内部链式代理

“链式代理 → 新增 → 服务器内部转发”选择已有入口、出口节点，填写新入口端口和 Reality SNI。两端都须唯一匹配总控登记的 IP / 域名，并匹配远端真实入站的端口和凭证。未匹配会提示选择 **Mihomo 客户端专用链式代理模式**，不会悄悄降级为客户端链路或修改未知服务器。

服务器模式创建专属 Reality 入站、落地出站及最高优先级路由，导入一个可被普通客户端使用的节点分享链接；原入口节点不变。新入站归属当前订阅。链路列表可删除远端链路与本地生成节点。失败会尝试撤回本次创建，撤回不完整会显示错误。Mihomo 模式仍使用 `dialer-proxy`，只在客户端实现链路。

### 订阅流量与到期强制限制

新建服务器入站会记录当前订阅归属。已有入站可在服务器节点列表点击“绑定当前订阅”，但必须是该订阅**独占**的整个入站；不能把其他用户共用的入站绑定过来，也不能把同一入站绑定两个订阅。绑定时以当前计数为基线，不把历史用量算到新订阅。专属入站的认证、协议和端口不能原地替换，防止入站 ID 复用后误删其他节点。

在“流量与到期”勾选“启用服务器强制限制”，设置总字节数和有效期。旧订阅的展示模式保持原样，需显式启用限制；新表单默认勾选。后台每轮检查后等待 30 秒，逐订阅累计所有绑定入站的上传/下载增量，持久化基线，识别计数器重置。达到总额或到期时先持久化撤销状态，再删除专属入站及本总控创建的中转出站/路由，尝试用 `ss -K` 清理该专属端口的存量 TCP 连接。三个公开订阅地址的 GET / HEAD 均返回 403，客户端缓存中的凭证也不能重新建立已删除入站的连接。续期不会恢复旧凭证，需要创建新专属节点。

面板使用其入站用量统计；独立内核要求远端有 **nftables**，按专属端口计量，规则保存在 `/etc/mxioc-meter/rules.nft`，通过 `mxioc-meter-restore.service` 在开机时恢复；清理存量 TCP 连接要求 **iproute2**。未能初始化计量时不允许启用限制。独立内核计量包含该端口收到的未认证流量和协议开销，与应用层面板计数不完全等价。多个已绑定入站的字节数直接相加，若同一链路的入口和落地都计量，会包含两端的中转流量；请为需要隔离计费的用户规划专属入口。

限制存在巡检和 SSH 操作延迟，不能保证到字节或到秒立刻断开；总控停机、远端不可达、计量或删除失败时，服务器侧无法保证按时撤销。后台保留并展示错误，后续轮次重试，可点击“立即同步用量 / 重试撤销”。计量重置会累计重置后的当前值，但重启或故障期间尚未采样的流量无法完整恢复。未绑定的外部节点或被共享的其他凭证不在总控强制限制范围内。

### SNI 候选测试

节点及中转表单提供独立“扫描并选择 SNI”窗口，打开后自动扫描 69 个内置候选，并合并当前订阅已有 SNI（去重后最多 200 个）；可展开自定义列表编辑。前端每批最多 20 个、最多两批并发，显示进度、TLS / ALPN 和失败原因；成功项按延迟排序，一键回填后保留原表单内容。关闭窗口停止后续批次并取消前端请求，已发送的远端探测可能继续至超时。证书模板须填写与实际证书匹配的域名，不使用任意候选替代证书域名。

测试通过所选服务器的固定指纹 SSH 连接执行，使用 Python 3 校验公网 DNS 地址、证书和 TLS 1.3 握手，延迟为远端 DNS + TCP + TLS 总耗时，不把总控延迟冒充为远端延迟。候选集合不是互联网上全部可用 SNI，测试通过也不能保证 Reality 在所有网络中可用。

### 开发验证

```bash
python -m unittest discover -s tests -v
# 可选：使用自行下载的官方 release 二进制进行真实配置校验，不安装服务或建立监听
MXIOC_XRAY_BIN=/path/to/xray MXIOC_SING_BOX_BIN=/path/to/sing-box \
  python -m unittest discover -s tests -p test_native_core_binaries.py -v
```

界面 DOM 冒烟测试可选运行（jsdom 仅为开发依赖，不需安装到生产服务）：

```bash
npm install --prefix /tmp/mxioc-ui-test jsdom --no-audit --no-fund
NODE_PATH=/tmp/mxioc-ui-test/node_modules node tests/ui_smoke.cjs
# 可选：本机已有 Chromium 时，使用示例数据验证三个主题和所有页面
npm install --prefix /tmp/mxioc-ui-test puppeteer-core --no-audit --no-fund
NODE_PATH=/tmp/mxioc-ui-test/node_modules MXIOC_CHROMIUM_BIN=/usr/bin/chromium node tests/ui_visual.cjs
```

实际校验覆盖 12 个原生入站配置以及 14 个中转出站配置组合。单元测试使用隔离临时目录与模拟 SSH，不会安装或删除生产服务器节点；真实 SSH、面板和客户端连通性还需要在测试服务器上验收。

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
- 登录会话固定有效 12 小时，同时最多保留 8 个会话
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

# 🌐 IP 模式并指定端口
vpn --ip --port 8080

# 🔒 域名 HTTPS 模式
vpn --domain vpn.example.com --email admin@example.com

# 🔒 域名 HTTPS 模式并指定访问端口
vpn --domain vpn.example.com --port 8443 --email admin@example.com

# ⚡ 极速安装，默认端口 5656
vpn --fast

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

### 多入口主备与节点保存优化

「链式代理」现支持创建多个服务器入口、一个固定出口的 Mihomo 主备组，按优先顺序故障切换和恢复切回。入口专属转发绑定当前订阅的总流量和到期限制。使用要求、切换边界与失败清理见 [多入口主备说明](docs/multi-entry-failover.md)。

节点同名编辑使用局部复制和 YAML 分段缓存，相同配置跳过重复写入；实测及复现方法见 [性能说明](docs/performance.md#node-editing-2026-10-23)。远端 SSH 与重启耗时尚未做线上测量。

### 电脑与手机客户端

v2rayN（电脑）与 v2rayNG（安卓）新增独立的节点订阅和 Xray 主备 JSON 订阅；Shadowrocket（iPhone）新增配对的主备节点订阅与策略配置。所有格式沿用订阅用量/到期响应头，桌面端提供真实节点备注摘要作为兼容显示。主备导入方法、端口要求、版本差异与实测边界见 [客户端适配说明](docs/client-compatibility.md)。

### 接入已有独立内核

在「服务器管理 → 接入已有面板 / 内核」选择 Xray 或 sing-box，填写 SSH 信息并核对主机指纹后保存。接入只读取当前配置、校验内核并检查 systemd 服务，不执行安装、重启或覆盖配置；无需面板账号密码。Xray 默认读取 `/usr/local/etc/xray/config.json`，程序为 `/usr/local/bin/xray`；sing-box 默认读取 `/etc/sing-box/config.json`，程序为 `/usr/bin/sing-box`。原有未受管入站不会自动导入，总控新建的节点单独管理。

### 接入已安装的面板

在「接入已有面板 / 内核」选择 3x-ui、X-ui 或 X-Panel，可直接填写完整面板地址，例如 `https://panel.example.com:13145/riben/`，并填写所选面板的账号密码；也可切换为通过 SSH 自动读取。完整地址按所填协议、端口及路径访问面板 API，连接仍经核对指纹的 SSH 隧道到该服务器的本机端口；SSH 同时用于监控和服务器节点管理。若公开地址经过 CDN 或位于其他机器的反向代理，请使用本机可访问的原站地址或自动读取模式。接入不会安装软件、申请证书或更改面板凭据。

### 选择服务器创建与导入节点

「节点管理」新增服务器创建和导入入口：可选择服务器创建模板节点，也可选择现有面板入站的连接导入订阅。专属入站支持同时绑定订阅，再统一设置总流量和有效期；多用户共用入站只能导入连接信息，需另建专属入站才能强制撤销。操作与边界见 [服务器节点工作流](docs/server-node-workflow.md)。

### 流量倍率与订阅节点限速

「流量与有效期」支持订阅流量倍率，例如实际采集 1 GiB 按 2 GiB 扣费；历史用量不重新计算。绑定到订阅的独占入站可分别设置客户端上传、下载 Mbps 上限，通过服务器 nftables 执行。共用入站内按单个用户限速暂不支持；超速丢包允许短时突发，需按实际协议验证。依赖、操作方法及实测边界见 [流量倍率与节点限速说明](docs/traffic-multiplier-bandwidth.md)。

### 全流程测试与 BUG 修复

本地完整验证共 181 项全部通过，覆盖真实 HTTP / Cookie / 浏览器流程、计费与限速撤销，以及实际内核配置和主备切换。已修复的问题、性能数据与生产验收边界见 [中文 BUG 报告](docs/bug-report-2026-10-23.md)。

### Mieru / mierus 批量导入

「节点管理」支持手动新增 / 编辑 Mieru（Mihomo）节点，并在「批量链接导入」粘贴一行一条的官方 `mierus://` 链接。支持 TCP / UDP、单端口 / 端口范围、多组端口展开、握手与复用参数；Mihomo 完整订阅保留配置。此功能不在服务器安装 Mieru，不将其转换成 Xray 或小火箭节点。格式、限制和实测范围见 [Mieru 使用说明](docs/mieru.md)。
