# 使用手册

本页补充 [README](../README.md) 中的 CA 选择、验证命令和旧包兼容说明。示例中的 `fakeca` 代表对应平台的构建产物；待签名文件需自行准备。

## CA 与路径

```sh
fakeca list
fakeca list --json
```

| CA ID | 用途 |
|---|---|
| dv-tls-g3b、dv-tls-g3c | TLS |
| ov-tls-g3b、ov-tls-g3c | TLS |
| ev-tls-g3b、ev-tls-g3c | TLS |
| ov-cs-g3b、ov-cs-g3c | 软件/JAR |

`--ca` 省略时只在用途相符的 CA 中随机选择。`--chain` 独立指定路径，默认 `ecc`：

| 参数 | 终端证书之后的路径 |
|---|---|
| ecc | 失守中间 CA → emSign Root TLS/CS CA - G3 交叉签名证书 → emSign ECC Root CA - G3 |
| native | 失守中间 CA → emSign Root TLS/CS CA - G3 自签名根 |
| aaa | 失守中间 CA 的交叉签名版 → AAA Certificate Services |

8 个身份 × 3 条路径 = 24 种测试组合。`ecc` 与 `native` 复用第一张中间证书，因此实际存放的涉事中间证书为 16 张。根和用途在各个平台上的信任情况不同，不能用一个路径代替全部路径。

## TLS 配置与访问

```sh
# 仅 IP，可包含 IPv4/IPv6
fakeca generate --type tls --ip "192.168.2.2,2001:db8::20" --out out/ip-test

# 多域名与通配符
fakeca generate --type tls --domain "*.example.internal,example.internal,api.other.internal" --valid-for 24h --out out/dns-test
```

- SAN 中的 IP 是证书身份，不会为服务器新增网卡地址。生成证书可以填写待测 IP，监听时必须使用本机实际可绑定的地址。
- `--domain` 接受 ASCII/punycode 域名，不包含协议、端口或路径。
- 通配符只允许最左侧完整标签：`*.example.internal`。不覆盖根域名及多级子域名。
- 通过域名访问时，另行配置测试 DNS/hosts。程序不修改这些系统设置。
- `serve` 默认只监听 `127.0.0.1:8443`；内网访问需要指定服务器内网接口。

```sh
fakeca serve --bundle out/ip-test --listen 192.168.2.2:8443
curl -q --no-insecure --noproxy '*' -v https://192.168.2.2:8443/
```

`-q` 必须是 curl 的第一个参数，用于忽略默认 curlrc；`--no-insecure` 明确启用校验；`--noproxy '*'` 排除显式代理。仍需核对实际证书、信任库、自定义 CA 配置及中间网络设备。正常受信任端点应作为正向对照。

TLS 测试端点最低支持 TLS 1.2。仅支持更旧协议的设备失败时，应记录为协议问题。客户端也可能因 CT、证书期限或用途限制先行拒绝，不能据此判断吊销检查结果。

## Nginx 部署

将同一新版 TLS 包中的 `fullchain.pem` 和 `private.key` 放在例如 `/etc/nginx/fakeca/`，在 `http {}` 内添加：

```nginx
server {
    listen 8443 ssl default_server;
    server_name 192.168.2.2;

    ssl_certificate     /etc/nginx/fakeca/fullchain.pem;
    ssl_certificate_key /etc/nginx/fakeca/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        default_type text/plain;
        return 200 "FakeCA TLS trust test\n";
    }
}
```

同一监听地址和端口只能有一个 `default_server`；这里便于通过 IP 访问时取得指定测试证书。若 FakeCA 服务已占用相同端口，需停止该端点或调整端口。

运行 `nginx -t` 检查，通过后执行 `nginx -s reload`。私钥必须允许 Nginx 主进程读取，并放在网站可访问目录之外。客户端依旧按自身原有的信任策略验证。

## 软件和 JAR 验证

`software` 使用 osslsigncode，格式范围由其版本决定。可以使用 `--tool` 指定完整路径；跨平台运行此功能仍产生 Windows Authenticode 签名。

Windows PowerShell 示例：

```powershell
Get-AuthenticodeSignature out/input-signed.exe |
    Format-List Status,StatusMessage,SignerCertificate
```

记录原始 `Status` 和 `StatusMessage`，并在实际 WDAC/AppLocker、安装器、更新器或加载器中复测。普通运行程序成功不等于进行了签名信任检查。

JAR 默认验证与显式吊销检查分别保留结果：

```sh
jarsigner -verify -strict -verbose -certs out/test-signed.jar
jarsigner -verify -strict -verbose -certs -J-Dcom.sun.security.enableCRLDP=true -revCheck out/test-signed.jar
```

非严格 `jarsigner -verify` 可能在存在信任警告时仍成功退出。JVM 通常使用自己的信任库；普通 `java -jar` 也不必然验证签名信任。程序不执行时间戳签名，以免时间戳及历史有效期规则干扰测试。

## PKCS#12 密码

未指定密码环境变量时，程序生成随机密码并写入 `password.txt`。指定环境变量后，不写入该文件，后续 JAR 签名也需提供同一个变量名。

```sh
# 先使用自己的秘密管理方式设置 FAKECA_P12_PASSWORD。
fakeca generate --type jar --out out/jar-env --password-env FAKECA_P12_PASSWORD
fakeca sign --type jar --bundle out/jar-env --input test.jar --output out/env-signed.jar --password-env FAKECA_P12_PASSWORD
```

Web 模式需在启动服务前设置变量。变量值不会进入 jarsigner 命令行；当前导出的 P12 私钥别名为 `1`。Authenticode 使用 PEM 私钥，不需要 P12 密码。

## 新旧证书包

新版报告为 `version: 2`；旧版为 `version: 1`。程序按版本选择布局，不猜测文件含义，也不自动重命名旧目录。

| 旧文件名 | 新文件名 |
|---|---|
| leaf.pem | cert.pem |
| leaf.key | private.key |
| ca.pem | issuing-ca.pem |
| chain.pem | fullchain.pem |
| issuers.pem | intermediates.pem |
| chain-with-root.pem | fullchain-with-root.pem |

`root.pem`、`identity.p12`、`password.txt`、`report.json` 保持不变。旧包部署 Nginx 时仍使用旧 `chain.pem` 和 `leaf.key`。不要只修改报告版本号，或手工混合新旧布局。

导入、签名及 TLS 启动会检查实际证书与私钥、固定 CA 指纹、完整路径、用途、SAN 及报告。JAR 签名前还会解密核对 P12。过期但完整的包可导入查看，不能用于新增签名或启动测试服务。

## 完整覆盖

随机选择适合抽查。下面的 PowerShell 示例遍历 24 条路径，TLS 使用测试域名，代码签名路径生成软件签名身份：

```powershell
$paths = fakeca list --json | ConvertFrom-Json
$stamp = Get-Date -Format yyyyMMdd-HHmmss
foreach ($ca in $paths) {
    $type = if ($ca.usage -eq 'tls') { 'tls' } else { 'software' }
    $params = @('generate', '--type', $type, '--ca', $ca.id,
        '--chain', $ca.chain, '--out', "out/matrix-$stamp/$($ca.id)-$($ca.chain)")
    if ($type -eq 'tls') { $params += @('--domain', 'ca-test.example.internal') }
    & fakeca @params
    if ($LASTEXITCODE -ne 0) { throw "Generation failed: $($ca.id)/$($ca.chain)" }
}
```

该脚本仅生成身份。还需要在实际设备上逐项访问或验证，并记录应用版本、信任库、网络路径、CA/链路、叶证书指纹、验证时间、原始错误及正向对照结果。

## 常见判读问题

- **显示 `SSL certificate verify ok` 是否安全？** 这表示当前 curl 验证通过，不能说明其检查了被吊销的中间 CA；对本工具的负向测试链而言，需要调查该验证路径。
- **为什么浏览器拒绝，curl 却接受？** 它们可能使用不同的 TLS 后端、信任库和封禁机制，应分别检查。
- **能否通过导入 root.pem 来测试？** 导入会改变被测设备原有信任条件，不适合作为默认信任策略的验收方式。
- **`--cert-status` 失败能证明吊销生效吗？** 该选项检查 OCSP stapling；服务器不提供装订响应导致的失败，不能作为中间 CA 吊销已落实的证明。
- **为什么不只交付一个软件摘要？** Authenticode 涉及特定文件摘要规则，JAR 涉及清单及条目摘要；签名器需要原始文件。
