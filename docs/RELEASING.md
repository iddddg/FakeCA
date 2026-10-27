# 版本发布

发布流程位于 [release.yml](../.github/workflows/release.yml)。推送 `v1.0.0` 形式的版本标签后，自动完成：

1. 读取标签对应的提交，校验版本格式。
2. 使用 go.mod 指定的 Go、Node 24 和 JDK 17 重建网页、检查内嵌资源并执行测试。
3. 通过 build.sh 交叉编译六个平台；实际运行 Linux amd64 产物做基础检查。
4. 核对各程序的目标平台、CGO、源码提交和干净状态，生成 Windows ZIP、Linux/macOS TAR.GZ。
5. 生成 SHA256SUMS.txt，上传草稿 Release，再下载全部附件校验，最后公开发布。

所有 Actions 固定到官方仓库的提交 SHA。构建任务只有内容读取权限，发布任务单独获得 contents: write，不需要自行配置 PAT。CI 执行 JAR 集成测试，Windows PE 实际签名应另外在 Windows 环境验证。

## 发布新版本

先确认 main 上的改动已提交并推送，再创建新的版本标签：

```sh
git tag -a v1.0.0 -m "🚀 发布 v1.0.0"
git push origin v1.0.0
```

每次使用新版本号。`v1.1.0-rc.1` 形式会发布为预发行版，不设为 Latest。仅支持三段版本号及可选预发行后缀。

在仓库 Actions 页查看 Release 工作流进度。也可以手动运行此工作流，填写**已存在的版本标签**。失败的草稿可通过重跑恢复；同名已有附件不覆盖，已公开版本只校验不修改。若源码或压缩包与已发布版本不同，应使用新的标签和版本号。

## 产物内容

每个平台包仅包含：

- fakeca.exe 或 fakeca
- README.md
- LICENSE
- THIRD_PARTY_NOTICES.txt
- release-info.json

不包含待测程序、生成的证书、私钥、密码或本机历史记录。Linux/macOS TAR.GZ 记录执行权限；压缩包时间戳来自源码提交。

## 本地打包

需要 Python 3.10+、Go 和干净的已提交工作区：

```sh
sh build.sh all --out bin/release/raw
python3 scripts/package_release.py --version v1.0.0
```

Windows 先用 `build.bat all --out bin\release\raw --no-pause` 构建，再用本机 Python 执行同一个打包脚本。输出为 `bin/release/assets/`；该目录必须为空，避免混入旧文件，也可以用 `--output-dir` 指定新的输出目录。

打包工具会先检查六个程序的 Go 构建元信息，拒绝来自其他提交、平台不匹配、启用 CGO 或含未提交改动的产物。请先提交源码，再执行正式构建。
