# Mieru / mierus 使用说明

`mierus://` 是 Mieru 官方的简单分享链接格式，Mihomo 中的节点类型为 `mieru`。本次以老仓库 main 提交 `5ffed82` 为基线开发；安装和更新源继续使用 Angasky/mxioc-vpn-manager。

## 添加节点

在「节点管理 → 新增」选择 Mieru，填写服务器 IP / 域名、用户名、密码、服务端口，并选择 TCP 或 UDP 传输。可填写端口范围，例如 `2090-2099`；此时单端口停用，两者互斥。可选参数为多路复用、握手模式与 Base64 流量特征；留空使用内核默认。

用户名、密码均必填，按官方客户端限制最多 64 个 UTF-8 字节。TCP / UDP 指到 Mieru 服务端的底层传输，页面的“启用 UDP 转发”指是否允许应用 UDP 流量，两者含义不同。无需填写其他协议的 UUID、SNI 或 TLS 公钥。

## 批量添加

进入「节点管理 → 批量链接导入」，一行粘贴一条官方简单分享链接：

```text
mierus://user:example-password@node.example.com?profile=Mieru-TCP&port=2999&protocol=TCP
mierus://user:example-password@node.example.com?profile=Mieru-UDP&port=2090-2099&protocol=UDP
```

以上是示例凭据与域名，不是真实节点。用户名和密码中的特殊字符应按 URL 规则编码，IPv6 地址使用方括号。

同一条链接可包含多组端口与协议，数量必须一致、按顺序配对。例如：

```text
mierus://user:example-password@node.example.com?profile=Multiple&port=2999&port=3000-3002&protocol=TCP&protocol=UDP
```

此例导入两个 Mihomo 节点，一个使用 TCP 单端口，一个使用 UDP 端口范围。不会把范围展开成每个端口一个节点。导入结果的“识别条数”按输入链接计数，“导入节点数”按展开后的节点计数，因此节点数可多于链接数。

支持与 VLESS、Shadowsocks 等已有格式混合粘贴；同名节点追加序号，不覆盖已有节点。无效链接单独报告，合法链接仍可导入。一个链接中的端口 / 协议会先全部校验，任一组不合法则该链接不导入。每条链接最多 256 组端口。

已有的“订阅导入”也支持含 Mieru 节点的 Clash YAML，以及包含 mierus 链接的 Base64 订阅。导入范围节点后，列表显示完整端口范围；可编辑、导出单节点链接和二维码。

## 支持边界

- 使用支持 Mieru 的 Mihomo 内核及“Clash / Mihomo 完整订阅”。本地验证版本为 Mihomo v1.19.33。
- `mieru://` 是 Base64 编码的完整 protobuf 客户端配置，不是简单链接。本次不解析它；请通过官方工具导出为 `mierus://`，或导入 Mihomo YAML。
- Mihomo 当前的 Mieru 适配器不暴露自定义 MTU。链接中的默认 `mtu=1400` 可接受，其他值报错，不会静默改成默认值。
- `traffic-pattern` 做 Base64 基础格式校验；其 protobuf 内容和语义由实际 Mihomo 内核校验。必须使用官方生成、与服务端匹配的值。
- 关闭 UDP 转发无法由官方简单链接无损表达，此时单节点分享会提示使用完整 Mihomo 订阅。
- Xray JSON、v2rayNG / v2rayN 的既有通用链接订阅及 Shadowrocket 导出不宣称支持 Mieru，转换报告会显示不兼容。选择 v2rayN 的 Mihomo 内核时，可使用完整 Mihomo 配置，不应导入 Xray 专用配置。
- 本次只管理客户端节点，不在远端安装 Mieru / mita，也不把其包装成 Xray 或 sing-box 服务端模板。未新增 Mieru 服务端所有权、套餐计量或到期撤销；手动导入链接不会自动获得这些服务器管理能力。

## 验证与上线

已覆盖链接往返、特殊字符凭据、IPv6、端口范围、多组展开、混合批量及部分失败、同名处理、YAML / Base64 导入、不兼容客户端过滤、真实管理 HTTP 流程和三个主题的桌面 / 手机表单操作；实际点击回归同时修复了提示条遮挡保存按钮的问题。

额外使用官方 mita v3.39.0 与 Mihomo v1.19.33，仅监听回环地址、使用临时随机密码，分别通过 TCP / UDP 底层传输访问本地 HTTP 测试页；另用 Mihomo 原生检查验证 TCP / UDP × 单端口 / 范围四种配置，包括握手与流量特征参数。没有连接生产服务器，没有将配置校验当作真实连通性测试。未验证公网线路吞吐、真实手机 App 或应用 UDP 数据报转发。

原生测试需要设置 `MXIOC_MIHOMO_BIN`；实际认证流量测试另需设置 `MXIOC_MITA_BIN`，在非 root Linux 环境执行。不设置时会明确跳过可选测试。安装新版本并在客户端刷新完整订阅后生效；GitHub 推送不等于生产部署。

参考：[Mieru 官方分享链接格式](https://github.com/enfein/mieru/blob/main/docs/client-install.zh_CN.md#分享链接)、[Mihomo Mieru 配置](https://wiki.metacubex.one/config/proxies/mieru/)。
