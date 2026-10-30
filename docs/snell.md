# Snell 节点支持

在「节点管理 → 新增节点」选择 Snell，填写服务器、端口、PSK，并明确选择服务端版本。当前范围为 Mihomo 的 Snell v1–v5；旧内核可能不支持后续版本，请升级客户端，不要把 v4/v5 配置改成 v3 来规避校验。

支持 UDP 转发（v3 以上）、连接复用开关（v4/v5）以及 HTTP / TLS / ShadowTLS / Restls / JLS 混淆。混淆必须与服务端实际设置相符；高级混淆需要相应密码、版本或用户名。完整 YAML 中已有的扩展选项会保留，编辑时不会重建成其他协议。

## 导入与订阅

- 支持 Mihomo YAML 节点、完整订阅中的 Snell 节点，以及 Base64 聚合链接。
- 支持 Surge 风格的单行 Snell 策略；不解析其他 Surge 配置段或承诺完整 Surge 配置转换。
- 支持本项目 `snell://` 兼容链接。这个格式不是通用客户端导入标准；第三方客户端优先使用完整 Mihomo YAML。
- 高级混淆、dialer-proxy、tfo 等扩展不能无损表达成此兼容链接时，明确拒绝单节点链接导出，仍可使用完整订阅；不静默丢失参数。
- v2rayN/v2rayNG/V2Ray/Shadowrocket 的现有链接转换不输出 Snell，并报告跳过原因；这不是对所有第三方客户端/内核能力的统一判断。

示例兼容链接（仅示例密钥）：

```text
snell://example-psk@example.com:24443?version=4&udp=true&reuse=true#Snell
```

可粘贴的策略示例：

```text
Snell 示例 = snell, example.com, 24443, psk=example-psk, version=3, obfs=http, obfs-host=bing.com
```

## 范围与验证

此功能管理客户端节点与订阅，不安装远端 Snell 服务端，不在 X-UI/Xray/sing-box 中伪造 Snell 入站，也不将外部 Snell 节点自动纳入远端流量计费。

本机 Mihomo v1.19.33 验证了 v1–v5、无混淆/HTTP/TLS 共 15 组配置；使用独立回环入站，完成了 v1–v5 的真实加密代理 HTTP 传输测试。高级混淆包含参数校验与无损保留测试，尚不代表与外部 ShadowTLS/Restls/JLS 服务端的互通实测。

参考：[Mihomo Snell 出站文档](https://wiki.metacubex.one/config/proxies/snell/)、[Mihomo 实现](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/outbound/snell.go)、[Surge Snell 策略语法](https://manual.nssurge.com/policies/snell.html)。版本能力以具体客户端内核为准；Snell v6 不在当前 Mihomo 适配范围内。
