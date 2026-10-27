# FakeCA

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.27.3%2B-00ADD8.svg)](go.mod)
[![UI](https://img.shields.io/badge/UI-Vue%203%20%2B%20Element%20Plus-42b883.svg)](web/package.json)

**用真实失守 CA 链，检查设备和应用是否正确拒绝证书。**

FakeCA 是面向授权内网测试的 CLI 与 Web 工作台，支持 TLS 证书生成、HTTPS 测试端点、Windows Authenticode 和 JAR 签名。它针对 eMudhra 弱密钥事件提供可复现的负向信任测试，并记录实际使用的 CA、证书链和指纹，便于不同设备重复验证。

> ⚠️ 测试产物使用已失守、被吊销的中间 CA。生成或签名成功表示产物已生成，客户端是否拒绝仍需在真实验证路径中检查。不要为让测试通过而向被测设备导入测试根证书。

[快速开始](#快速开始) · [构建与平台](#构建与平台) · [CLI 示例](#cli-示例) · [输出文件](#输出文件) · [结果判读](#结果判读) · [详细使用手册](docs/USAGE.md)

## 功能概览

| 功能 | 支持内容 |
|---|---|
| 🌐 TLS 身份 | 单域名、多域名、通配符、IPv4/IPv6，可同时写入同一张证书 |
| 🔗 CA 与链路 | 8 组失守密钥、16 张涉事中间 CA 证书、24 种身份/链路组合 |
| 🧪 HTTPS 测试 | 使用指定证书包监听端口，支持 TLS 1.2/1.3、握手诊断和多端点管理 |
| ✍️ 文件签名 | 调用 osslsigncode 处理 Windows 软件、调用 JDK jarsigner 处理 JAR |
| 🖥️ 网页工作台 | 参数表单、CA 筛选、证书包导入、文件上传、报告及下载、服务启停 |
| 📦 单文件运行 | Vue 3 + Element Plus 资源内嵌，运行 Web 不依赖 Node、npm 或 CDN |
| 📋 可复测记录 | CA ID、路径、SAN、实际有效期、终端及父链指纹，保存在 report.json |

程序核对内置证书的固定 SHA-256 和父子签名，在内存中恢复事件中已公开失守的 CA 签名密钥；不导出 CA 私钥。每个新终端证书使用独立的 RSA-3072 私钥。公开证书的来源见 [SOURCES.md](internal/catalog/SOURCES.md)。

支持在 Windows、Linux、macOS 上构建和运行。`software` 指 **Windows Authenticode 文件签名**；不提供 Apple Developer ID 签名或 macOS 公证。

## 快速开始

不需要自行编译时，可以在 [Releases](https://github.com/iddddg/FakeCA/releases) 下载对应系统和架构的压缩包，解压后运行 `fakeca.exe web` 或 `./fakeca web`。每个包包含许可证、第三方声明及构建元信息，可用同一版本的 `SHA256SUMS.txt` 核对下载内容。

### 1. 获取源码

```sh
git clone https://github.com/iddddg/FakeCA.git
cd FakeCA
```

### 2. 构建当前平台

Windows（CMD 或 PowerShell）：

```powershell
.\build.bat host
```

Linux / macOS：

```sh
sh build.sh host
```

普通构建只需要 Go，直接复用仓库中的网页生产资源。首次构建需要下载 Go 模块，以及当前环境尚未缓存的工具链。

### 3. 启动网页工作台

Windows x64：

```powershell
.\bin\fakeca-windows-amd64.exe web
```

Linux / macOS（自动选择当前宿主文件名）：

```sh
./bin/fakeca-"$(go env GOHOSTOS)"-"$(go env GOHOSTARCH)" web
```

默认监听 `http://127.0.0.1:8080/`，程序尝试打开带本次令牌的完整地址；也可以从终端复制完整地址访问。按 `Ctrl+C` 停止管理端及其启动的 TLS 测试端点。

以下示例用 `fakeca` 代表构建产物；使用时替换为上面的完整文件路径，或将可执行文件放入 `PATH`。

## 构建与平台

| 依赖 | 用途 |
|---|---|
| Go 1.27.3+ | 编译程序；最低版本由 go.mod 指定 |
| Node 22+、npm | 仅在修改网页或使用 --frontend 时需要 |
| JDK jarsigner | JAR 文件签名；已用 JDK 17 实测 |
| osslsigncode | Windows Authenticode 文件签名；可在 PATH 中提供或指定 --tool |

Go 的自动工具链下载只作用于构建，不修改系统默认 Go 安装。离线构建环境需要预先安装或缓存工具链及依赖。

两个脚本使用相同的目标名称，支持一个或多个目标、自动去重，以及 `host` 和 `all`：

```powershell
# Windows：指定多个目标，或构建全部组合
.\build.bat windows-amd64 linux-amd64 darwin-arm64
.\build.bat all --out bin\release
.\build.bat host --frontend
.\build.bat --help
```

```sh
# Linux / macOS
sh build.sh linux-amd64 darwin-arm64
sh build.sh all --out bin/release
sh build.sh host --frontend
sh build.sh --list
```

| 目标 | 平台 | 默认输出 |
|---|---|---|
| windows-amd64 | Windows x64 | bin/fakeca-windows-amd64.exe |
| windows-arm64 | Windows ARM64 | bin/fakeca-windows-arm64.exe |
| linux-amd64 | Linux x64 | bin/fakeca-linux-amd64 |
| linux-arm64 | Linux ARM64 | bin/fakeca-linux-arm64 |
| darwin-amd64 | macOS Intel | bin/fakeca-darwin-amd64 |
| darwin-arm64 | macOS Apple Silicon | bin/fakeca-darwin-arm64 |

- `--out DIR`：输出目录，相对路径以项目根目录为基准；同名构建产物会更新。
- `--frontend`：先运行 `npm ci` 和 `npm run build`，再构建 Go。
- 无目标参数：构建当前 Go 宿主平台。构建遇错即停止，已成功的产物保留。
- Windows 帮助默认等待回车，内容不会在退出时清屏。自动化使用 `--no-pause`；需要查看构建结束结果时使用 `--pause`。输入被重定向时也不会等待。

脚本使用 `CGO_ENABLED=0`、`-trimpath`、`-ldflags="-s -w"`，不改变调用终端的环境变量。产物为命令行可执行文件，不生成安装包，也不执行测试、发布者签名或公证。复制到 Linux/macOS 后若执行权限丢失，运行 `chmod +x 文件名`。

不使用脚本时，也可以直接运行 `go build -o bin/fakeca .`；Windows 可将输出文件名改为 `bin/fakeca.exe`。

## CLI 示例

### 帮助与 CA 清单

```sh
fakeca --help
fakeca help generate
fakeca list
fakeca list --json
```

无参数运行显示介绍。`generate`、`serve`、`sign` 无参数时显示各自帮助；`web` 无参数直接启动工作台。`list --json` 只输出 JSON，适合脚本读取。

### TLS 证书与测试服务

```sh
# 域名、通配符、根域名与 IP 可以共存
fakeca generate --type tls --domain "*.example.internal,example.internal" --ip 192.168.2.2 --ca dv-tls-g3c --chain ecc --out out/tls-test
fakeca serve --bundle out/tls-test --listen 192.168.2.2:8443
```

随后使用证书 SAN 中的域名或 IP 访问 `https://192.168.2.2:8443/`。监听 IP 必须属于运行服务器；通过域名访问时，需另外配置测试 DNS/hosts。只使用 IP 时可以省略 `--domain`。

`*.example.internal` 匹配 `a.example.internal`，不匹配根域名或多级子域名；需要访问根域名时应另外列出 `example.internal`。多个域名/IP 使用逗号分隔。

⏱️ 默认有效期为 **365 天（8760h）**，TLS、软件和 JAR 类型一致。`--valid-for 24h` 可修改期限；支持数字和时长单位，示例 `24h`、`30m`，不支持 `365d`。实际到期时间受父链限制，起始时间额外回溯 5 分钟以容忍时钟偏差。

### 软件和 JAR 签名

以下 `input.exe`、`test.jar` 是你自行准备的无害测试样本；仓库不附带待签名程序。签名需要原始文件，不能只提供摘要。

```sh
# 先生成代码签名身份，再签名
fakeca generate --type software --ca ov-cs-g3b --chain aaa --subject "Internal Test Publisher" --out out/code
fakeca sign --type software --bundle out/code --input input.exe --output out/input-signed.exe

# 也可一次生成 JAR 身份并签名
fakeca generate --type jar --ca ov-cs-g3c --chain aaa --out out/jar --input test.jar --output out/test-signed.jar
```

需要使用不在 PATH 中的签名工具时，加上 `--tool "工具完整路径"`。程序保留输入文件、拒绝覆盖既有输出，不执行被签名的程序。

PKCS#12 默认使用随机密码，保存在输出目录的 `password.txt`。也可在启动程序前设置密码环境变量，并使用 `--password-env FAKECA_P12_PASSWORD`；此时不生成密码文件。JAR 的密码通过子进程环境传递，不写入命令行。

签名验证、环境变量用法及完整测试矩阵见 [详细使用手册](docs/USAGE.md)。

## Web 工作台

```sh
fakeca web --listen 127.0.0.1:8088 --data-dir out/web --open=false
```

- **生成证书**：完整生成参数、随机或指定 CA、生成后同时签名。
- **证书与签名**：导入 CLI 证书包，查看报告和用途说明，上传原始文件、签名及下载单文件/ZIP。
- **TLS 测试服务**：多端点启动/停止、监听配置和握手诊断。
- **CA 清单**：24 种组合的用途、链路、期限和指纹，可一键带入表单。
- **使用指南**：参数说明、CLI 命令和验证结果判读。

所有路径均指向**运行 FakeCA 的服务器**。上传单文件最大 64 MiB；更大文件使用服务器本地路径。签名器及密码环境变量也需在服务器上准备。

默认数据目录 `out/web/` 保存历史索引、证书包和上传文件。重启保留历史，但不会自动恢复 TLS 端点。已有 CLI 证书包可按目录导入；CLI 独立启动的 `serve` 不归 Web 实例管理。

🔑 每次启动生成新的管理令牌，通过请求头验证并拒绝跨站请求。浏览器接收 URL 片段中的令牌后移除片段，在当前标签页会话中保存。持有令牌的操作员可下载身份文件、调用签名工具及配置监听端点。内网设备测试时只需开放独立的 TLS 测试端口，管理端可以继续监听回环地址。

## 输出文件

| 文件 | 内容 |
|---|---|
| cert.pem | 新生成的终端证书 |
| private.key | 终端证书的 PKCS#8 私钥，不是 CA 私钥 |
| issuing-ca.pem | 直接签发终端证书的涉事中间 CA |
| fullchain.pem | 终端证书 + 中间链，不含末端自签名根 |
| intermediates.pem | 仅中间链，不含终端证书和根 |
| root.pem | 路径末端根证书，供诊断审阅 |
| fullchain-with-root.pem | 终端证书、中间链及根，供离线审阅 |
| identity.p12 | 软件/JAR 类型额外输出的 PKCS#12 身份 |
| password.txt | 未指定密码环境变量时生成的 P12 密码 |
| report.json | CA、用途、路径、指纹、SAN 和有效期等记录 |

🌐 **Nginx 使用同一包中的 `fullchain.pem` 和 `private.key`**，无需自己拼接：

```nginx
ssl_certificate     /etc/nginx/fakeca/fullchain.pem;
ssl_certificate_key /etc/nginx/fakeca/private.key;
```

新包报告使用 `version: 2`。旧 `version: 1` 包仍可导入、下载、签名和启动服务，文件名保持不变；旧包部署 Nginx 时使用 `chain.pem` 和 `leaf.key`。完整对应表见 [新旧文件兼容](docs/USAGE.md#新旧证书包)。

生成目录必须尚不存在；既有证书目录和签名输出不会覆盖。Unix 文件使用 0700 目录/0600 文件；Windows 继承目录 ACL。私钥和密码应受限保存，不能放在网站公开目录内。

## 结果判读

| 现象 | 可以判断的范围 |
|---|---|
| 默认严格验证下接受页面或签名 | 当前验证路径仍接受此链，需排查信任、吊销/封禁和代理策略 |
| 明确报中间 CA 已吊销或封禁 | 支持该测试路径已落实相应拒绝策略的判断 |
| 报根不受信任 | 当前路径无法建链，不能据此认定执行了在线吊销检查 |
| 报 SAN、有效期、CT、用途或算法错误 | 证书被拒绝，但不足以证明吊销检查有效 |
| TCP 超时、代理认证或协议不兼容 | 无法判断证书策略 |

请同时测试正常、受信任且名称匹配的正向对照端点，记录设备/应用版本、CA ID、路径、叶证书指纹及原始错误。随机 CA 适合抽查，完整覆盖需要遍历各身份和三条路径。

不同应用可能使用不同的信任库。macOS 上某个 curl 接受证书，不能推广到所有浏览器或 JVM；反向也一样。软件默认能运行、JAR 非严格验证退出成功，也不等于签名信任策略接受。

本工具的终端证书不包含叶级 OCSP/CDP 或 CT SCT，不伪造吊销服务，也不把 Go `x509.Verify` 的结果当作设备吊销机制的证明。更详细的验证命令与限制见 [使用手册](docs/USAGE.md)。

## 开发与贡献

版本发布使用标签触发的 GitHub Actions，自动测试、构建六个平台、打包及上传 Release；具体操作和重跑规则见 [发布指南](docs/RELEASING.md)。

项目目录、前端重建、测试方式及提交约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全相关问题请参阅 [SECURITY.md](SECURITY.md)。

仓库提交 `internal/webui/dist/`，使普通 Go 构建无需 Node；依赖锁文件保留。`.gitignore` 排除本机缓存、临时检查脚本、生成的证书和私钥、签名产物、可执行文件及 node_modules。公开 CA 证书在 `internal/catalog/certs/` 中随源码保存。

```sh
go test ./... -count=1
go vet ./...
```

签名器集成步骤在工具可用或显式配置时执行，具体条件见贡献指南。被跳过或被系统策略阻止的测试不能视作通过；签名结构验证也不代替目标设备验收。

## 许可与来源

原创代码和文档采用 [MIT License](LICENSE)。第三方代码及公开证书资料保留各自权利和使用条件，详见 [第三方声明](THIRD_PARTY_NOTICES.md) 与 [证书来源](internal/catalog/SOURCES.md)。

- [Mozilla：eMudhra 私钥失守事件](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [eMudhra 官方证书仓库](https://repository.emsign.com/)
- [curl：TLS 证书校验与信任库](https://curl.se/docs/sslcerts.html)
- [Apple：涉事 eMudhra 中间 CA 说明](https://support.apple.com/en-us/149555)
- [Nginx：HTTPS 与证书链配置](https://nginx.org/en/docs/http/configuring_https_servers.html)
- [Oracle：jarsigner](https://docs.oracle.com/en/java/javase/26/docs/specs/man/jarsigner.html)
- [osslsigncode](https://github.com/mtrojnar/osslsigncode)
