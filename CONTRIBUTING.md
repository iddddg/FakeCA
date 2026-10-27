# 参与开发

欢迎通过 Issue 反馈问题，或通过 Pull Request 提交改进。较大改动建议先说明使用场景和预期行为。

## 开发环境

- Go：遵循 `go.mod`，当前最低为 1.27.3。
- 修改网页时需要 Node 22+ 与 npm。
- 签名集成测试按需使用 JDK 的 `jarsigner` 和 `osslsigncode`。

```sh
go mod download
go test ./... -count=1
go vet ./...
```

前端资源需在修改后重新构建并随源码一起提交：

```sh
cd web
npm ci
npm run build
cd ..
go build -o bin/fakeca .
```

Windows 可使用 `build.bat host --frontend`；Linux/macOS 可使用 `sh build.sh host --frontend`。构建脚本参数见 [README](README.md#构建与平台)。

## 签名集成测试

Windows PowerShell 可通过环境变量指定外部工具：

```powershell
$env:FAKECA_JARSIGNER = 'C:/Tools/jdk/bin/jarsigner.exe'
$env:FAKECA_OSSLSIGNCODE = 'C:/Tools/osslsigncode/bin/osslsigncode.exe'
go test ./... -count=1
```

lab 的 JAR 测试在未指定变量时尝试从 PATH 查找 jarsigner；Web 的 JAR 签名集成需要显式配置 `FAKECA_JARSIGNER`。PE 签名集成需要 Windows 和 `FAKECA_OSSLSIGNCODE`。测试自动生成专用样本，不执行签名后的程序。

PE 结构验证使用显式测试根，只用于产物密码学检查，不会把测试根导入系统。这类结构验证不能作为系统吊销策略有效的证明。

## 提交前检查

1. Go 文件执行 `gofmt`，运行与改动有关的测试及 `go vet ./...`。
2. 修改网页后更新 `internal/webui/dist/`；该目录用于让普通 Go 构建不依赖 Node。
3. 修改证书包文件布局时保留按报告版本读取的兼容逻辑，更新测试、CLI、Web 和文档。
4. 修改依赖后同步锁文件及第三方声明，保留依赖提供的版权和许可文本。
5. 不提交私钥、密码、真实管理令牌、生成的证书包、签名样本、缓存及本机检查记录。

外部签名器集成测试需明确记录是否实际执行；测试被跳过或被系统策略拦截时，不应写成验证通过。签名结构验证与客户端信任/吊销验证应分别描述。

## Pull Request

说明解决的问题、用户可观察到的变化和验证结果。提交信息可使用中文配合 emoji，例如 `🐛 修复旧证书包下载说明`。新增文件遵循 [MIT License](LICENSE)；第三方资料保留其原有许可及来源。
