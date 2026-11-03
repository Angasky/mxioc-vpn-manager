# HY2 自动证书

服务器节点的 TLS 模板默认提供“自动申请并续期”，高级选项仍可填写已有证书路径。输入自己控制的域名，A/AAAA 全部解析到节点服务器，关闭 CDN 代理；签发使用 HTTP-01，节点服务器 TCP 80 必须可从公网访问且未被占用。不会停止已有网站或修改防火墙。

证书准备是独立的后台任务，浏览器显示进度后再创建节点。失败返回具体原因；重复点击同一服务器与域名复用运行中的任务。关闭窗口、切换订阅或改变配置后，不继续按原选择创建节点。签发任务重启后不恢复，重试会检查服务器已有有效证书，不盲目重复签发。

- 接口：POST `/admin/api/servers/certificates`，参数 `serverId`、`serverName`；GET 同路径，查询参数 `id`、`job`。沿用管理员 HTTPS、登录和 Origin 校验。
- 自动创建传递 `certificateMode=auto` 与准备完成的 `certificateJobId`；任务必须属于同一服务器连接信息与域名。手动证书请求保持兼容。
- acme.sh 首次安装固定源码提交并校验 SHA-256；远端使用 Shell / OpenSSL / socat，不需要 Python。缺少 socat 时尝试系统包管理器安装。
- 证书在 `/etc/mxioc-certificates/<domain>/`，ACME 状态在 `/var/lib/mxioc-acme/`。私钥不返回总控，由对应服务用户读取。
- `mxioc-acme-renew.timer` 每日检查并带随机延迟；续期安装后自动刷新对应 x-ui / xray / sing-box 服务。首次签发不重启现有节点服务。
- Reality 保留原内置候选列表与双次实测扫描。TLS/HY2 使用自己的证书域名候选，候选来自已签发记录、服务器绑定域名和已有 TLS 入站。第三方 Reality 目标不是可向自己签发的域名。

本功能接入 Python 正式后台及其安装器；Go 原生证书接口仍待迁移，不代表 Go 已支持模板创建入站。
