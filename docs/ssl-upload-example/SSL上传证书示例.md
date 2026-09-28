# SSL 证书上传示例

本示例演示如何在「证书管理 → 上传证书」中手动上传一张 SSL 证书（含私钥），
用于无法走 ACME 自动签发的内部/自签名/第三方证书场景。

> 随附示例文件（位于 `docs/ssl-upload-example/`）：
> - `example.com.crt` —— 示例证书（PEM，自签名，有效期 365 天）
> - `example.com.key` —— 示例私钥（PEM）
>
> 你也可以直接用自己真实的证书/私钥替换下面内容。

## 操作步骤

1. 登录系统后，进入顶部导航 **证书管理**。
2. 点击右上角 **+ 上传证书**，打开上传表单。
3. 按如下示例填写并粘贴，然后点击 **上传并入库**。

### 表单填写示例

| 字段 | 填写值 | 说明 |
|------|--------|------|
| 证书别名 * | `示例-生产环境证书` | 便于在列表里识别这张证书 |
| 关联域名 | `example.com` | 可选，填证书适用的主域名 |
| 证书内容（PEM）* | 下方「证书内容」整段 | 必须包含 `-----BEGIN CERTIFICATE-----` |
| 私钥（PEM） | 下方「私钥内容」整段 | 可选；自签名/第三方证书建议一并上传 |

### 证书内容（粘贴到“证书内容”框）

```pem
-----BEGIN CERTIFICATE-----
MIID3jCCAsagAwIBAgIUItw9f0UcdN0SzV5Y6/a0XSdHgzIwDQYJKoZIhvcNAQEL
BQAwajELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl
aWppbmcxFDASBgNVBAoMC0V4YW1wbGUgSW5jMQswCQYDVQQLDAJJVDEUMBIGA1UE
AwwLZXhhbXBsZS5jb20wHhcNMjYwOTIzMTM0ODA2WhcNMjcwOTIzMTM0ODA2WjBq
MQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamlu
ZzEUMBIGA1UECgwLRXhhbXBsZSBJbmMxCzAJBgNVBAsMAklUMRQwEgYDVQQDDAtl
eGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBftv6G
6WwLm+h2Kzs8/iRxAGBeIZqWHs9qWipzI+25cEV92nYGWlKRGhYa7lhDv1kmLpcj
lKPswPdG2jZoyq01R9cPWpSEDAXHNfhI5svuJRSNkFuWIu+w3gTuXKktw7GPNX3U
Jel+C9fak9Vn2jva4tvvBw784S7Z5jVbbYt12glcN+Lraa4SB8X8YbXt3Z66mlqu
FJ1+kfke+o1WV97mhfKqh4Tzq1Px4/nzPwssMHEAO0Mhc/NZ1KpLuyvFjE0E1yfh
wrL3VI2sOnUkwaTas7LqmPdEYVErmFWMge3jforwtjaBqEY8/CUgegT/AwM52aIH
+fWKjuuwIzpP7rkCAwEAAaN8MHowHQYDVR0OBBYEFMw97uiJKdnXECidJmYrt+cx
C+xlMB8GA1UdIwQYMBaAFMw97uiJKdnXECidJmYrt+cxC+xlMA8GA1UdEwEB/wQF
MAMBAf8wJwYDVR0RBCAwHoILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLmNvbTAN
BgkqhkiG9w0BAQsFAAOCAQEABevk5eq3Xm2RquhA3lMgSijPaElqU+a4RJHBZia1
7kjC6sruwOOD3yMev8IJzDCiVXLimZ1Wpb4HZWDIdf9p7qNgLm7C96RramJN/2G9
xmU3b8N3Pvirs1qYg6iTCeWNB04ID9XoTUN+MjE+n6J7+cWRCJuTGVkVKFFnLRSn
ALQ6znbXcjB5pFUZtxFquTKTpzC8WC/pzPWJw+dAYoSIh2uStgFNT8LdUiSz0/me
4YoTK/i2h+Mv3HHAZJK6n4sJb1DaWdptzEVG3LDWMkfuE7N8RpAa+5MDc98xm0wg
bpDbYzGlfBorFTvETve/3Ga2i5QXg9drdrfvNQp4DnVcGA==
-----END CERTIFICATE-----
```

### 私钥内容（粘贴到“私钥”框，可选）

```pem
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAX7b+hulsC5vo
dis7PP4kcQBgXiGalh7PaloqcyPtuXBFfdp2BlpSkRoWGu5YQ79ZJi6XI5Sj7MD3
Rto2aMqtNUfXD1qUhAwFxzX4SObL7iUUjZBbliLvsN4E7lypLcOxjzV91CXpfgvX
2pPVZ9o72uLb7wcO/OEu2eY1W22LddoJXDfi62muEgfF/GG17d2eupparhSdfpH5
HvqNVlfe5oXyqoeE86tT8eP58z8LLDBxADtDIXPzWdSqS7srxYxNBNcn4cKy91SN
rDp1JMGk2rOy6pj3RGFRK5hVjIHt436K8LY2gahGPPwlIHoE/wMDOdmiB/n1io7r
sCM6T+65AgMBAAECggEATivWyZD680u4W/sA0D6Vqys8EuzNTOrptDEsWImXNPeg
tqxQhJtKQrjx17+z0Kwe6lQIpKPxt7byJslkzK1ChqXa/nofva/2zrZHqQ++sWmh
KbvoyD63DZ1aariNcLXHCrT98JavnTT6DQml/xcHaEEm5GY6AQ4jVw12bYIsfnl9
9BO5cByhEPsuLWg03/9T+s7Rvih6nynX4scGzSzCsH04eknHDaPC2b1jfXoHR3i1
WCYwPt+227w3t+R8imPS+pnu/I5+2tVXu4QVSo4SBSh0yv9IvU+KBX2mw2Xexh+e
Lot5NzzIysPA/0aMv6qjy2bsNTnEIoDhdysFkHCgLQKBgQDg4ZK9Zz1sGH5XwXk6
pmQuegp9Hdwx06TERySd8jttGo5XZPCii7kl/xXpFvQmPnI3n+czJEDT/ZzDeVLU
OaT05VSOWIaRlqCPCKYZ+0rEuHq4KPi8QRvkpTO/mlQPhru9UWeHAoS5qM51Sn38
RTAUOLjra+twFwaEDHuYLr37BwKBgQDa/pH4B1MyBrLZ1mfFv26TfF5mThx72QtU
Fixy4vSymL3Mt/tYV9ImOgcLHVAMkT4BnSn8KWAEWi68Hc/XaaF/DTQg80tHUqZS
dvZL3L6/zXcLVojTMt9oKFogQpefRCavUH6kMb+LSiZ7Dwxi3p+YOhK7gwFF5OOT
SZh9l6WYPwKBgQCayQjMj2QKpC1KT+QWh3LLPrs7dTMbpLZzVxiQEqvuo+m3o8Wx
zARrb9Fv95mjPTY2rTxgyiJJB/Y/4aEubGLrIXJ669nsGcZ3zRcvKPVExEnLun/C
a/o7/a3Jwvr7GNzeKUrd9dDPTa6VsulWm3TFZml5uXV7WI3mlAT6MaoYPwKBgDR1
dNv4TTqXljJOhO8+yyszSJ2zKmmUdX1ADoe6zCkYI6ctj1z7NJEJp3RHIkzQYg0a
69rGwoRoYfeYIJiWaiQ4MnuOLEM6jjME4j0L9PmXK2Qg54fIEPIvcF939EAnoCiw
3JVSgXLJYWxrD2mDsLFTf/dBC4YFrWoz3/593CIbAoGAVXMVhLpNJCo8Qq3Tcjlx
IqSdRi6fYDBhEd1sPQvYijhReFBCBtuJgG1j5cp/jS5CwKwZbjAVdmwh7a7t186Q
aKnmeaA1Scvq+ZEWir8x4RtBBjdJ9BTqNmCdP1RTu5T6OckWMUTR7C7HS/vqcYxG
EzRJnm7WWLnAE/Tk7OAlyNI=
-----END PRIVATE KEY-----
```

## 上传后验证

- 上传成功会跳回证书列表，并提示「证书已上传入库」。
- 在列表中点击该证书 **详情**，可看到系统自动解析出的：
  - 主域名(CN)：`example.com`
  - 适用域名(SAN)：`example.com, www.example.com`
  - 签发者、生效时间、到期时间、序列号、签名算法、公钥算法
  - 状态：未过期则显示 `VALID`，已过期显示 `EXPIRED`
- 若上传时填写了「关联域名」，可在 **域名管理** 的域名详情中对照查看 SSL 状态。

## 常见问题

- **提示“证书解析失败”**：确认证书文本完整，首尾分别是
  `-----BEGIN CERTIFICATE-----` 与 `-----END CERTIFICATE-----`，
  且没有被截断或混入了多余空格。
- **私钥可不可以不上传？**：可以。留空则只保存证书（用于展示/巡检），
  不保存私钥；需要私钥的场景（如部署/续期）建议一并上传。
- **证书链怎么传？**：把服务器证书和中间证书按“服务器证书在上、中间证书在下”拼接后
  一起粘贴到「证书内容」框即可。
