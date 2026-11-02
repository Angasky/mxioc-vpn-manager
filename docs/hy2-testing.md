# HY2 实际连通性验证（2026-11-02）

`tests/test_hy2_connectivity.py` 在本机回环地址启动由服务器模板与 CoreAPI 转换生成的服务端，再将导出的分享链接解析为 Mihomo 客户端配置，经真实 QUIC / HY2 隧道读取临时 HTTP 服务的固定内容。分别覆盖正确密码与错误密码，退出清理所有进程和临时配置。

已通过：Xray 26.10.31、sing-box 1.14.4，客户端 Mihomo 1.19.33。两种服务端均成功返回 HTTP 证明内容，错误密码均未获取数据。

仅测试文件使用自签名证书并允许客户端跳过验证。Xray 测试出站仅允许临时 HTTP 服务的回环 IP 和端口，不更改项目默认出站或生产环境配置。

运行时设置 `MXIOC_XRAY_BIN`、`MXIOC_SING_BOX_BIN`、`MXIOC_MIHOMO_BIN` 为官方发行版二进制的绝对路径，然后执行：

```sh
python -m unittest discover -s tests -p test_hy2_connectivity.py -v
```

此结果不等于某台远端服务器已验证：远端 UDP 端口、云安全组、防火墙、证书可读性、域名匹配及面板版本仍取决于部署环境。本次未创建或修改生产服务器入站。
