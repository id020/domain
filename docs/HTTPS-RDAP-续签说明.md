# WHOIS / RDAP 与 Spring Boot 内置 HTTPS 续签说明

## WHOIS / RDAP

点击现有域名详情页的「刷新 Whois」：优先请求 IANA RDAP Bootstrap，查到注册局 HTTPS 地址后查询域名；失败则回退到 TCP 43 WHOIS。刷新失败时页面展示具体错误并保留原缓存。某些后缀或隐私保护域名不会公开注册商、到期时间，属于注册局返回限制。

## 自动续签

证书必须是 ACME 签发、开启 autoRenew，且到期前 30 天（可配置）。现有定时任务每天检查并续签。证书详情页也提供「立即续签」。签发时要求域名公网 DNS 正确、HTTP 80 端口的 `/.well-known/acme-challenge/` 可以到达本应用。仅开放 HTTPS 443 端口无法通过 HTTP-01；可在网关映射 80 或扩展 DNS-01。

## Spring Boot 内置 HTTPS 部署

配置以下环境变量：

```bash
ACME_DEPLOY_HTTPS=true
ACME_DEPLOY_DOMAIN=your.example.com
ACME_KEYSTORE_PATH=/data/https.p12
ACME_KEYSTORE_PASSWORD='设置强密码'
```

在 `application.yml` 的 `server` 下配置：

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: ${ACME_KEYSTORE_PATH:/data/https.p12}
    key-store-type: PKCS12
    key-store-password: ${ACME_KEYSTORE_PASSWORD}
    key-alias: https
```

**首次启用 HTTPS 前，必须先签发证书并生成密钥库，或者先使用 HTTP 端口完成首次签发。** HTTP-01 需要另外提供公网 80 端口入口，不能仅将内置 HTTPS 端口配置为 8443。可以部署第二个 HTTP Connector 或独立 80 端口网关将挑战路径转发给应用；当前项目没有自动创建第二个 Connector。

续签成功后，新证书和私钥写入数据库；若域名匹配 `ACME_DEPLOY_DOMAIN`，同时原子替换 PKCS12 文件。**正在运行的内置 Tomcat 不保证自动重新加载磁盘上的 PKCS12**，需要由 systemd、Docker 或部署平台安排安全重启，并在重启后通过外部 HTTPS 探测确认证书生效。本版不会强行结束自己的 JVM，避免业务中断。自动续签不等于自动热加载，未配置重启流程时请在收到续签通知后重启。

建议将密钥库和 ACME 账户密钥放在持久化、权限受限的数据卷中；不要将私钥或真实密码提交到代码仓库。项目原压缩包包含真实 `acme-account.key`，本修订包已排除该文件，请自行安全保存，并在泄露时轮换账户密钥。

## 本版验证边界

当前执行环境未提供 Maven 与可访问的 ACME/DNS/MySQL 运行环境，未完成实际编译、证书签发、生产续签或 TLS 重载端到端测试。建议先使用 Let's Encrypt staging 环境验证，再切换生产目录。
