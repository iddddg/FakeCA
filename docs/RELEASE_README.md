# FakeCA {{VERSION}}

平台：`{{TARGET}}`

源码提交：`{{COMMIT}}`

## 运行

Windows 使用 `fakeca.exe`，Linux/macOS 使用 `./fakeca`：

```text
fakeca --help
fakeca web
```

可执行文件包含网页资源；普通运行不需要 Node 或 Go。JAR/Windows 软件签名需要自行安装对应平台的 JDK jarsigner/osslsigncode。软件签名功能指 Windows Authenticode，不提供 Apple Developer ID 签名或 macOS 公证。

Linux/macOS 包已记录执行权限；复制后若权限丢失，可运行 `chmod +x fakeca`。发布产物未进行发布者签名或 macOS 公证，请遵循本机软件执行策略。

## 校验与许可

下载同一 Release 的 `SHA256SUMS.txt`，核对压缩包 SHA-256。`release-info.json` 记录版本、目标平台、源码提交与 Go 工具链；包内只包含程序、说明、许可及构建元信息，不包含生成的证书或私钥。

原创代码许可见 `LICENSE`，完整第三方版权和许可见 `THIRD_PARTY_NOTICES.txt`。Web 工作台也可查看随程序内嵌的第三方声明。

## 用途

本程序用于授权环境中的证书信任与吊销策略测试。生成和签名成功不代表客户端应该信任测试产物；请保留客户端原有信任配置，并使用正常受信任端点作正向对照。

[源码与使用说明](https://github.com/iddddg/FakeCA) · [详细手册](https://github.com/iddddg/FakeCA/blob/main/docs/USAGE.md) · [安全反馈](https://github.com/iddddg/FakeCA/blob/main/SECURITY.md)
