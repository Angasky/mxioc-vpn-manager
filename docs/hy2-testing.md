# HY2 实际连通性验证（2026-11-02）

`tests/test_hy2_connectivity.py` 在本机回环地址启动由服务器模板与 CoreAPI 转换生成的服务端，再将导出的分享链接解析为 Mihomo 客户端配置，经真实 QUIC / HY2 隧道读取临时 HTTP 服务的固定内容。分别覆盖正确密码与错误密码，退出清理所有进程和临时配置。

已通过：Xray 26.10.31、sing-box 1.14.4，客户端 Mihomo 1.19.33。两种服务端均成功返回 HTTP 证明内容，错误密码均未获取数据。

仅测试文件使用自签名证书并允许客户端跳过验证。Xray 测试出站仅允许临时 HTTP 服务的回环 IP 和端口，不更改项目默认出站或生产环境配置。

运行时设置 `MXIOC_XRAY_BIN`、`MXIOC_SING_BOX_BIN`、`MXIOC_MIHOMO_BIN` 为官方发行版二进制的绝对路径，然后执行：

```sh
python -m unittest discover -s tests -p test_hy2_connectivity.py -v
```

此结果不等于某台远端服务器已验证：远端 UDP 端口、云安全组、防火墙、证书可读性、域名匹配及面板版本仍取决于部署环境。本次未创建或修改生产服务器入站。

## v2rayN 内核与多用户验证

`tests/test_hy2_v2rayn_core.py` 使用真实 Xray 服务端和 v2rayN 可使用的 sing-box 内核，验证：原用户可连接；未注册的新 HY2 密码不能连接；单用户补注册后可以传输 HTTP 内容；撤销后该用户不能重新连接；另一名用户仍可连接。测试客户端加载临时证书作为信任锚并校验域名，不关闭 TLS 验证。

```sh
PYTHONPATH=.:tests MXIOC_XRAY_BIN=/path/to/xray MXIOC_SING_BOX_BIN=/path/to/sing-box python -m unittest test_hy2_v2rayn_core -v
```

本轮还修正 HY2 的 `servername` 到 URI `sni` 映射、标准 URI 路径，以及单节点添加操作中 `hysteria` 被误当作不受管外部链接的问题。HY2 面板用户创建后会核对内核中的 `auth`，只补注册已确认缺失的独立用户；老内核不支持查询时仍会明确提示未核验。

服务器入站的“添加到订阅”支持搜索、多选订阅和失败项重试。逐份调用独立用户接口，VLESS / VMess 分配独立 UUID，HY2 分配独立密码；自动启用独立计量与到期处理，不复制原始链接。创建中断的凭据加密保存，重试复用同一身份，采集任务不会提前丢弃待核对记录。

验证范围为本地真实内核、HTTP 回归和桌面 / 手机宽度的浏览器操作；不表示已在用户截图中的远端服务器部署或实测。
