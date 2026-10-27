# FakeCA

用于内网终端、代理、服务和签名验证器的 **eMudhra 弱密钥事件负向信任测试** CLI。

内置 Mozilla 事件附件中的 16 张真实中间 CA 公钥证书，对应 8 组失守密钥。运行时核对固定 SHA-256，验证父子证书签名，并在内存中恢复已公开失守的 CA 签名密钥。生成的终端证书使用新的 RSA-3072 密钥；不导出 CA 私钥。

提供 TLS 证书及测试服务、代码签名证书/PKCS#12、Windows Authenticode 和 JAR 文件签名。指定 `--ca` 选择 CA，省略时在用途相符的 CA 中随机选择。每次记录实际选择和指纹，便于复测。

## 构建

Go 1.27.3 或更高版本（`go.mod` 已固定最低版本，支持自动工具链的 Go 会在首次构建时下载所需版本）：

```powershell
go test ./...
go build -o bin/fakeca.exe .
.\bin\fakeca.exe --help
```

Linux/macOS 可使用 `go build -o bin/fakeca .`。构建时下载 go.mod 中的 PKCS#12 依赖；构建后的 CLI 生成证书和启动 TLS 服务均不需要联网。实际客户端的在线吊销检查可能需要访问 CA 的 CRL 服务。

首次构建需要取得项目要求的工具链；离线构建机需预先缓存或安装该版本。工具链选择只作用于本项目，不修改系统默认 Go。

### 跨平台构建脚本

Windows 使用 `build.bat`，Linux/macOS 使用 POSIX Shell 脚本 `build.sh`（也可在 Windows 的 Git Bash 中使用）。脚本可从任意工作目录调用，不带参数时构建当前 Go 宿主平台；多个目标用空格分隔，`all` 构建全部六种组合。

```powershell
# Windows：构建一个或多个目标
.\build.bat windows-amd64
.\build.bat windows-amd64 linux-amd64 darwin-arm64
.\build.bat all --out bin\release
.\build.bat host --frontend
.\build.bat --help
# 自动化读取帮助，不等待按键
.\build.bat --help --no-pause
```

```sh
# Linux/macOS：使用相同的目标和参数
sh build.sh linux-amd64 darwin-arm64
sh build.sh all --out bin/release
sh build.sh host --frontend
sh build.sh --list
```

| 目标 | 系统与架构 | 默认输出 |
|---|---|---|
| `windows-amd64` | Windows x64 | `bin/fakeca-windows-amd64.exe` |
| `windows-arm64` | Windows ARM64 | `bin/fakeca-windows-arm64.exe` |
| `linux-amd64` | Linux x64 | `bin/fakeca-linux-amd64` |
| `linux-arm64` | Linux ARM64 | `bin/fakeca-linux-arm64` |
| `darwin-amd64` | macOS Intel | `bin/fakeca-darwin-amd64` |
| `darwin-arm64` | macOS Apple Silicon | `bin/fakeca-darwin-arm64` |

`--out DIR` 指定输出目录，相对路径以项目根目录为基准；同名构建产物会更新。`--frontend` 先执行 `npm ci` 和 `npm run build`，需要 Node 22+ 与 npm；默认复用已提交的网页资源。脚本使用 `CGO_ENABLED=0`、`-trimpath` 和 `-ldflags="-s -w"`，不改变调用终端的环境变量。构建遇错即停止，已成功的其他目标产物保留。

Windows 的 `--help`、`-h`、`/?` 输出帮助后默认等待回车，便于在 CMD 中阅读；回车后返回命令行，帮助内容仍保留。普通构建和 `--list` 默认不暂停；需要保留临时窗口查看构建结果时使用 `--pause`。自动化、CI 或重定向帮助文本时可使用 `--no-pause`，该参数优先于暂停设置；检测到输入被重定向时也不暂停。BAT 在单文件内调用 Windows 自带 PowerShell 处理参数和 Unicode 输出，不切换控制台代码页，避免 CMD 清屏及中文解析问题。

产物是命令行可执行文件，包含内嵌 Web，不生成安装包，也不执行测试、Windows 代码签名或 macOS 公证。跨平台构建不要求目标系统的编译器；运行软件/JAR 签名功能时，目标设备仍需安装对应平台的 osslsigncode/JDK。复制到 Linux/macOS 后若执行权限丢失，可运行 `chmod +x 文件名`。

FakeCA 程序不带参数运行会显示中文应用介绍、命令清单和快速开始示例。也支持 `fakeca --help`、`fakeca -h`、`fakeca help generate`、`fakeca generate --help`。`generate`、`serve`、`sign` 不带参数时显示对应帮助；`list` 不带参数时直接列出 CA。

CLI 自有提示统一使用中文，以 ✅ 标记操作完成、ℹ️ 标记操作说明、❌ 标记失败；HTTPS 测试页使用 ⚠️ 提示当前为负向信任测试。成功生成或签名不代表目标设备应信任该产物。JSON 字段、命令参数和 CA ID 保持稳定；底层系统及外部签名工具的原始诊断保留，方便排障。请使用支持 UTF-8 的终端查看中文和表情。

## 网页工作台

```powershell
.\bin\fakeca.exe web
# 自定义端口和数据目录；不自动打开浏览器
.\bin\fakeca.exe web --listen 127.0.0.1:8088 --data-dir out/web --open=false
.\bin\fakeca.exe help web
```

`web` 不带参数会直接启动服务，默认地址为 `http://127.0.0.1:8080/`。程序自动打开带有本次会话令牌的完整地址；也可以从终端复制该地址手动打开。网页使用 Vue 3 与 Element Plus，生产资源通过 Go embed 内嵌在可执行文件中，运行时不需要 Node、npm 或外部 CDN。

网页提供五个功能区：

| 功能区 | 能力 |
|---|---|
| 生成证书 | TLS/软件/JAR 类型，单域名、多域名、泛域名、IP，随机或指定 CA，三条链路，名称、组织、有效期、目录、密码环境变量、生成后同时签名 |
| 证书与签名 | 导入已有 CLI 证书包，查看实际有效期和指纹，JSON 报告，单文件/完整 ZIP 下载，已有代码签名证书包签名，签名日志 |
| TLS 测试服务 | 多端点启动与停止，监听地址配置，运行状态和握手诊断日志 |
| CA 证书清单 | 24 种组合的用途、链路、CA 期限和指纹，搜索筛选，一键带入生成表单 |
| 使用指南 | 参数说明、常用 CLI 命令、链路选择和验证结果判读 |

网页参数与 CLI 共用业务逻辑，默认有效期同为 365 天。所有路径都指向**运行 FakeCA 的服务器**；原始签名文件可以直接填写服务器路径，也可以上传（单文件最大 64 MiB，超过时使用本地路径）。软件/JAR 签名仍需要 osslsigncode / JDK jarsigner，支持在表单中指定工具路径。密码环境变量需在启动 Web 服务前设置。

默认工作目录 `out/web/` 中保存 `registry.json` 历史索引、`bundles/` 默认生成产物和 `uploads/` 上传文件。自定义输出目录的证书包也会进入历史索引；已有 CLI 证书包可通过“导入目录”加入。重启保留证书与签名历史，不自动重新启动测试端点。关闭工作台会停止由其启动的 TLS 服务。CLI 单独启动的 `serve` 不归 Web 实例管理。

管理 API 每次启动生成新的访问令牌，使用请求头认证，并拒绝跨站请求；浏览器通过 URL 片段接收令牌后会移除片段并在当前标签页会话中保留。持有令牌的操作员能访问文件产物、调用签名工具和配置监听端点，应按本机管理权限保管完整地址。管理端默认只监听回环地址；内网设备访问 TLS 测试端点时，在“TLS 测试服务”中配置服务器内网接口即可，无需同时开放管理端。文件下载包含终端私钥及可能存在的 P12 密码，请妥善保管。

### 修改网页与重新构建

仓库已包含 `internal/webui/dist/` 生产资源，所以直接 `go build` 即可编译完整程序。修改 `web/src/` 后，需先构建前端再构建 Go；前端依赖要求 Node 22 或更高版本，以及 npm：

```powershell
cd web
npm ci
npm run build
cd ..
go build -o bin/fakeca.exe .
```

`web/package-lock.json` 固定前端依赖，Vite 将资源输出到 `internal/webui/dist/`。页面时间以浏览器本地时区显示，JSON 报告保留带时区的标准时间。

## 查看及选择 CA

```powershell
.\bin\fakeca.exe list
.\bin\fakeca.exe list --json
```

| CA ID | 用途 |
|---|---|
| `dv-tls-g3b`, `dv-tls-g3c` | TLS |
| `ov-tls-g3b`, `ov-tls-g3c` | TLS |
| `ev-tls-g3b`, `ev-tls-g3c` | TLS |
| `ov-cs-g3b`, `ov-cs-g3c` | 软件/JAR 代码签名 |

`--chain` 独立指定链路，默认 `ecc`：

| 参数 | 实际证书路径（终端证书之后） |
|---|---|
| `ecc` | 失守中间 CA → emSign Root TLS/CS CA - G3 的交叉签名版 → emSign ECC Root CA - G3 |
| `native` | 失守中间 CA → emSign Root TLS/CS CA - G3 自签名根 |
| `aaa` | 失守中间 CA 的 Sectigo 交叉签名版 → AAA Certificate Services |

8 个身份 × 3 条路径 = 24 种测试组合；`ecc` 与 `native` 复用同一张失守中间证书，所以失守中间证书仍为 16 张。各平台原本信任的根和用途不同，列出的路径不表示所有平台原本都信任它们。测试一种路径不能覆盖其他路径。

## TLS 域名/IP 测试

```powershell
.\bin\fakeca.exe generate --type tls --domain ca-test.example.internal --ip 192.168.10.20 --ca dv-tls-g3b --chain aaa --out out/tls-aaa
.\bin\fakeca.exe serve --bundle out/tls-aaa --listen 192.168.10.20:8443
```

让被测设备通过测试 DNS/hosts 把 `ca-test.example.internal` 解析到测试服务器，再使用实际业务使用的浏览器、代理、SDK 或 TLS 客户端访问 `https://ca-test.example.internal:8443/`。也可以使用证书 SAN 中的 IP 访问。只对测试域名修改解析。CLI 不修改 DNS、hosts、防火墙或系统信任库。

`--domain` 和 `--ip` 均支持逗号分隔。域名使用 ASCII/punycode，不包含协议或端口。支持最左侧完整标签通配符，例如 `*.example.internal`：匹配 `a.example.internal`，不匹配 `example.internal` 或 `a.b.example.internal`。如果也要访问根域名，使用 `--domain "*.example.internal,example.internal"`。命令行中建议用引号包住通配符，避免 shell 展开。

```powershell
.\bin\fakeca.exe generate --type tls --domain "*.example.internal,example.internal" --out out/wildcard-test
```

`serve` 默认只绑定 `127.0.0.1:8443`；内网访问需明确指定服务器接口地址，并确保网络连通。

测试端点最低支持 TLS 1.2。若设备仅支持更旧协议，应将失败记录为协议不兼容，不能据此认定证书吊销检查有效。

生成证书默认从生成时刻起 365 天（8760 小时），适用于 TLS、软件和 JAR 类型。`--valid-for 24h` 可自定义为任意正时长，不再设置原先的 168 小时上限；实际到期时间不会超过父链证书期限。参数填写数字与单位：`h` 表示小时，`m` 表示分钟，例如 `24h`（1 天）、`8760h`（365 天）、`30m`（30 分钟），不支持 `365d`。证书起始时间另有 5 分钟回溯，以容忍轻微时钟偏差。**已吊销的中间 CA 在日期上仍可能有效，正是本工具要覆盖的情况。**

## 软件及 JAR 签名

签名证书通常不绑定某一个软件摘要。签名文件需要原始文件：Authenticode 有专用文件摘要算法，JAR 还涉及清单和归档条目摘要。本工具要求 `--input` 原始文件，不接受把一个摘要直接当作 EXE/JAR 签名。

只生成代码签名身份：

```powershell
.\bin\fakeca.exe generate --type software --ca ov-cs-g3b --chain aaa --subject "Internal Test Publisher" --out out/code
```

### Windows 软件

安装 [osslsigncode 官方发行版](https://github.com/mtrojnar/osslsigncode/releases)，放入 PATH 或用 `--tool` 指定。使用标准 Authenticode 工具处理 EXE/DLL/MSI 等文件格式；具体格式由安装的 osslsigncode 版本决定。

```powershell
.\bin\fakeca.exe sign --type software --bundle out/code --input fixtures/hello.exe --output out/hello-signed.exe --tool C:/Tools/osslsigncode/bin/osslsigncode.exe
Get-AuthenticodeSignature out/hello-signed.exe | Format-List Status,StatusMessage,SignerCertificate
```

亦可一次生成并签名：

```powershell
.\bin\fakeca.exe generate --type software --ca ov-cs-g3c --chain native --out out/code-native --input fixtures/hello.exe --output out/hello-native.exe --tool C:/Tools/osslsigncode/bin/osslsigncode.exe
```

CLI 只生成/签名文件，不执行被签名的程序。Windows 签名检查与系统是否阻止执行是两个问题：默认系统可以运行未签名程序，须在实际部署的 WDAC/AppLocker/更新器等验证路径中检查策略结果。

### JAR

需要 JDK 的 `jarsigner`，已用 JDK 17 实测。`--type jar` 使用代码签名 CA，输出 PKCS#12 后调用 jarsigner；不会修改输入归档。

```powershell
.\bin\fakeca.exe generate --type jar --ca ov-cs-g3c --chain aaa --out out/jar --input fixtures/test.jar --output out/test-signed.jar --tool "C:/Program Files/Java/jdk-17.0.20.1/bin/jarsigner.exe"
jarsigner -verify -strict -verbose -certs out/test-signed.jar
jarsigner -verify -strict -verbose -certs -J-Dcom.sun.security.enableCRLDP=true -revCheck out/test-signed.jar
```

保留两种验证结果：第一种观察原有默认行为；第二种观察显式开启吊销检查后的行为。`jarsigner -verify` 的非严格模式可能在存在证书信任警告时仍退出成功，不能仅根据退出码认定信任。JVM 信任库通常独立于 Windows/浏览器；普通 `java -jar` 也不必然执行签名信任检查，需测试实际加载器/安装器策略。

PKCS#12 默认生成随机密码并存入输出目录的 `password.txt`。也可以指定环境变量，避免密码进入命令行：

```powershell
# 先通过自己的秘密管理方式设置 FAKECA_P12_PASSWORD。
.\bin\fakeca.exe generate --type jar --out out/jar-env --password-env FAKECA_P12_PASSWORD
.\bin\fakeca.exe sign --type jar --bundle out/jar-env --input fixtures/test.jar --output out/env-signed.jar --password-env FAKECA_P12_PASSWORD
```

jarsigner 密码通过子进程环境传递，不写入命令行。当前导出 P12 中私钥别名为 `1`。软件签名使用生成的 PEM 叶证书私钥，不需要 P12 密码。不进行时间戳签名，避免时间戳及历史有效期规则干扰本次测试。

## 输出文件

| 文件 | 内容 |
|---|---|
| `leaf.pem`, `leaf.key` | 新生成的终端证书和 PKCS#8 私钥 |
| `ca.pem` | 选中的真实失守中间 CA 公钥证书 |
| `chain.pem` | 终端证书和中间链；不含自签名根，适合 TLS 服务/签名工具 |
| `issuers.pem` | 中间链，不含终端证书和自签名根 |
| `root.pem` | 路径末端根证书，仅用于审阅/诊断，不应导入被测设备 |
| `chain-with-root.pem` | 完整证书链，供离线审阅 |
| `identity.p12` | 代码签名类型额外输出的 PKCS#12 身份 |
| `password.txt` | 仅未指定密码环境变量时输出 |
| `report.json` | CA 身份、用途、链路、序列号、指纹、SAN 和有效期 |

输出目录必须是新目录，现有目录和现有签名输出文件均拒绝覆盖。Unix 使用 0700 目录/0600 文件；Windows 仍继承目录 ACL，应在受限工作目录保存叶私钥和密码。

## 如何判断测试结果

为每个设备/应用记录：版本、信任库来源、网络路径、CA ID、链路、叶证书指纹、实际错误、时间及正向对照结果。

| 现象 | 可得出的结论 |
|---|---|
| 默认验证下成功获取测试页面，或实际签名验证策略接受文件 | 该验证路径仍接受此失守链，或本来就绕过了验证；需要调查 |
| 明确报中间 CA 已吊销/被封禁 | 支持该测试路径已落实吊销/封禁的判断 |
| 报不受信任的根 | 当前路径不能建立信任；不能据此断定进行了在线吊销查询 |
| 报 SAN、有效期、CT、用途、算法错误 | 证书被拒绝，但不能证明吊销机制有效 |
| TCP 超时、代理认证失败、TLS 协议不兼容 | 无法判断证书策略 |

使用同一网络和应用访问一个正常、受信任、域名匹配的正向对照端点。不要用跳过证书校验或导入这些根的方式进行设备安全验收。

生成的叶证书不包含 SCT、叶级 OCSP/CDP，不伪造 CA 的吊销服务。严格浏览器可能因 CT 先行拒绝。只有检查终端证书吊销的客户端也可能漏过已吊销中间 CA。本程序不把 Go `x509.Verify` 的结果当成设备吊销状态证明：Go 的通用验证接口不执行常规在线 CRL/OCSP 检查，且部分 Go 版本另有特定密钥封禁。

随机选择适合抽查；完整覆盖应遍历所有 CA 和三条路径。例：

```powershell
$paths = .\bin\fakeca.exe list --json | ConvertFrom-Json
$stamp = Get-Date -Format yyyyMMdd-HHmmss
foreach ($ca in $paths) {
  $type = if ($ca.usage -eq 'tls') { 'tls' } else { 'software' }
  $params = @('generate','--type',$type,'--ca',$ca.id,'--chain',$ca.chain,'--out',"out/matrix-$stamp/$($ca.id)-$($ca.chain)")
  if ($type -eq 'tls') { $params += @('--domain','ca-test.example.internal') }
  & .\bin\fakeca.exe @params
  if ($LASTEXITCODE -ne 0) { throw "Generation failed: $($ca.id)/$($ca.chain)" }
}
```

## 验证与资料

### 项目结构

| 路径 | 用途 |
|---|---|
| `main.go`、`help.go`、`serve.go`、`web.go` | CLI 入口、中文帮助及服务命令 |
| `build.bat`、`build.sh`、`.gitattributes` | 跨平台构建入口及脚本换行约定 |
| `internal/catalog/` | 公开 CA 证书、来源说明、固定指纹及链路选择 |
| `internal/lab/` | 证书生成、证书包校验、文件签名及 TLS 测试端点 |
| `internal/webui/` | 管理 API 与通过 Go embed 内嵌的网页生产资源 |
| `web/src/`、`web/vite.config.js` | Vue 页面、样式及前端构建配置 |
| `go.mod`、`go.sum` | Go 工具链要求、模块版本与完整性校验 |
| `web/package.json`、`web/package-lock.json` | 前端依赖、构建命令与锁定版本 |
| `*_test.go` | 随源码维护的单元测试及可选签名器集成测试 |

`internal/webui/dist/` 是直接执行 `go build` 所需的内嵌资源，随源码提交。临时检查脚本、下载缓存、测试生成的证书/签名文件、可执行文件和 `node_modules/` 不提交；本地生成的私钥及 PKCS#12 文件也由 `.gitignore` 排除。

### 运行测试

```powershell
# 外部签名器集成测试是可选项，指定后会实际运行。
$env:FAKECA_JARSIGNER = 'C:/Program Files/Java/jdk-17.0.20.1/bin/jarsigner.exe'
$env:FAKECA_OSSLSIGNCODE = 'C:/Tools/osslsigncode/bin/osslsigncode.exe'
go test ./... -count=1
go vet ./...
```

测试覆盖全部事件证书的固定指纹、链路签名、弱密钥与公钥匹配、用途筛选、叶证书/SAN、P12 密钥匹配、拒绝覆盖，以及可用时的 JAR 实际签名和 Windows PE Authenticode 签名。PE 测试使用显式测试根验证产物的密码学正确性，不执行该文件；这不是操作系统信任或吊销测试。这些测试不代替内网设备安全验收。

导入、文件签名和 TLS 启动会核对证书包中的实际证书、私钥、完整链路及报告指纹。JAR 签名前还会核对 PKCS#12 身份与 PEM 身份一致；损坏、混入其他身份或报告不匹配的证书包会被拒绝。过期证书包可导入查看，但不能用于启动服务或新增文件签名。

- [Mozilla 事件记录和原始附件](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [证书来源与指纹说明](internal/catalog/SOURCES.md)
- [eMudhra 官方证书仓库](https://repository.emsign.com/)
- [Go x509 验证文档](https://pkg.go.dev/crypto/x509#Certificate.Verify)
- [Oracle jarsigner 文档](https://docs.oracle.com/en/java/javase/26/docs/specs/man/jarsigner.html)
- [osslsigncode 参数文档](https://github.com/mtrojnar/osslsigncode/blob/master/osslsigncode.md)
