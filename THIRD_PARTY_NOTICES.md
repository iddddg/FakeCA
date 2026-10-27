# 第三方代码与证书资料

FakeCA 原创代码和文档采用 [MIT License](LICENSE)。第三方代码、依赖及公开证书资料保留各自的权利和使用条件，项目的 MIT 许可不用于重新授权这些材料。

## 依赖

| 组成部分 | 来源 | 许可 |
|---|---|---|
| Go PKCS#12 | [SSLMate go-pkcs12](https://software.sslmate.com/src/go-pkcs12) | BSD-3-Clause |
| Go 密码学组件 | [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | BSD-3-Clause |
| Go 标准库与运行时 | [Go](https://go.dev/) | BSD-3-Clause 及其随附声明 |
| Vue、Element Plus 及前端依赖 | 版本见 `web/package-lock.json` | MIT、BSD、ISC 等，以各依赖文件为准 |

锁定版本、依赖提供的版权和许可全文保存在 [完整第三方声明](web/public/third-party-notices.txt)。该文件由 Vite 复制到内嵌网页资源，Web 服务的 `/third-party-notices.txt` 可直接查看；分发单独的二进制文件时，请同时保留根目录的 LICENSE 和第三方声明。

声明覆盖已安装的锁定前端依赖（包括部分构建工具），不表示所有依赖均被打入最终网页。依赖更新后应同步核对声明。个别 npm 发布包没有附带单独的 LICENSE 文件时，按其 `package.json` 和发布者公开的 npm 元信息标注，具体情况在完整声明中说明。

## 公开 CA 证书

`internal/catalog/certs/` 保存公开的 X.509 中间 CA 及根证书，用于事件复现和信任链检查。颁发者信息、固定指纹和来源见 [证书来源说明](internal/catalog/SOURCES.md)。这些材料不属于 FakeCA 原创代码，也不代表 CA、Mozilla 或相关根计划对本项目的背书。

仓库没有存放 CA 私钥文件。程序在运行时根据公开事件中已失守密钥的特征恢复签名能力；新生成的终端私钥和密码属于本地测试产物，不随源码分发。

## 外部工具

`jarsigner` 和 `osslsigncode` 由用户另行安装，不包含在本仓库或构建产物中，分别遵循其发行方提供的许可。
