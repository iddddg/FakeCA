package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var commandHelp = map[string]string{
	"list": `列出内置 CA 的用途、链路和 SHA-256 指纹。

⌘ 用法
  fakeca list [--json]

🚀 示例
  fakeca list --json

8 个 CA 身份对应 16 张涉事中间证书；加上不同父链，共 24 种测试组合。
--json 只输出 JSON，便于脚本读取；普通输出显示中文说明。
🔗 链路：ecc 经 ECC G3 根，native 使用 emSign TLS/CS 自签名根，aaa 经 Sectigo AAA 根。
`,
	"generate": `生成测试用终端证书及证书链，输出 report.json 记录本次选择。

⌘ 用法
  fakeca generate --type tls|software|jar [参数]

🚀 常用示例
  fakeca generate --type tls --domain ca-test.example.internal --ip 192.168.10.20 --out out/tls-test
  fakeca generate --type tls --domain ca-test.example.internal --ca dv-tls-g3b --chain aaa --out out/tls-aaa
  fakeca generate --type tls --domain "*.demo.com,demo.com" --out out/tls-wildcard-root
  fakeca generate --type tls --domain "api.demo.com,www.demo.com,demo.com" --out out/tls-multi
  fakeca generate --type software --ca ov-cs-g3b --out out/code-test
  fakeca generate --type jar --out out/jar-test --input test.jar --output out/signed.jar

🌐 域名与 IP
TLS 至少提供 --domain 或 --ip，支持逗号分隔多个值。
--domain 和 --ip 只设置证书身份，不配置 DNS 解析或服务监听地址。
多个域名填写在同一个 --domain 参数中，用逗号分隔，建议用引号包住整个值。
例如 --domain "*.demo.com,demo.com"，一张证书同时包含泛域名和根域名。
其中 *.demo.com 匹配 api.demo.com，不匹配 demo.com 或 a.b.demo.com，
所以访问根域名时需要额外列出 demo.com；也可以混合填写其他普通域名。
📦 软件与 JAR
软件/JAR 可只生成证书；如需同时签名，必须一起提供 --input 和 --output。
代码签名额外导出 identity.p12；未指定密码环境变量时生成 password.txt。
📁 证书文件
cert.pem 为终端证书，private.key 为私钥；fullchain.pem 包含终端证书和中间链。
Nginx 使用 fullchain.pem 和 private.key；其余 CA/链路文件供审阅及诊断。
⏱️ 有效期
默认 365 天，实际到期时间受父链限制；--valid-for 24h 可自定义时长，不支持 365d 写法。

🔗 CA 与链路
不指定 --ca 时随机选择用途匹配的 CA；运行 fakeca list 查看可选 ID。
链路：ecc 经 ECC G3 根，native 使用 emSign TLS/CS 自签名根，aaa 经 Sectigo AAA 根。
`,
	"serve": `使用已有 TLS 证书包启动 HTTPS 测试服务，按 Ctrl+C 停止。

⌘ 用法
  fakeca serve --bundle DIR [--listen 地址:端口]

🚀 示例
  fakeca serve --bundle out/tls-test
  fakeca serve --bundle out/tls-test --listen 192.168.10.20:8443

🌐 访问方式
默认仅监听 127.0.0.1:8443；内网访问需指定服务器内网接口地址。
测试服务最低支持 TLS 1.2；协议不兼容与证书吊销拒绝应分别记录。
使用证书 SAN 中的域名/IP 访问，必要时配置测试 DNS/hosts。
自动识别新旧证书包文件名，已有 leaf.key / chain.pem 证书包仍可使用。
📋 结果判读
记录客户端实际验证错误，并使用正常受信任的端点进行正向对照。
`,
	"sign": `使用已有代码签名证书包给原始文件签名，保留输入文件。

⌘ 用法
  fakeca sign --type software|jar --bundle DIR --input FILE --output FILE [参数]

🚀 示例
  fakeca sign --type software --bundle out/code-test --input hello.exe --output out/hello-signed.exe
  fakeca sign --type jar --bundle out/jar-test --input test.jar --output out/signed.jar

🧩 签名工具
software 调用 osslsigncode，jar 调用 JDK jarsigner；使用 --tool 指定工具路径。

📁 输入与输出
签名工具需要原始文件，不能仅凭软件摘要生成可验证的 EXE/JAR 签名。
已有输出文件不会被覆盖；本命令不会执行被签名的文件。
`,
	"web": `启动内嵌的 Vue 3 + Element Plus 网页工作台，支持 CLI 的全部业务功能。

⌘ 用法
  fakeca web [--listen 地址:端口] [--data-dir DIR] [--open=false]

🚀 示例
  fakeca web
  fakeca web --listen 127.0.0.1:8088 --open=false
  fakeca web --data-dir out/my-web-workspace

🧭 网页功能
  🌐 TLS / 软件 / JAR 证书生成，支持全部生成参数和同时签名。
  📁 导入 CLI 证书包、查看报告、下载单个文件或完整 ZIP。
  ✍️ 上传原始文件或指定服务器路径，调用签名工具并查看日志。
  🔗 CA 清单筛选、身份选择、链路及有效期查看。
  🧪 TLS 测试服务启动、停止和诊断日志查看。

🔑 访问与文件
默认监听 127.0.0.1:8080，自动打开带本次访问令牌的地址。
工作台静态资源内嵌，无需 Node 或 CDN；软件/JAR 签名仍需对应工具。
路径参数均指向运行 FakeCA 的服务器；上传文件上限 64 MiB。
历史索引、上传文件和默认产物保存在 --data-dir；关闭工作台会停止其 TLS 服务。
`,
}

var flagHelp = map[string]string{
	"json":         "以 JSON 输出完整 CA 清单",
	"type":         "证书类型：tls（域名/IP）、software（软件签名）、jar（JAR 签名）",
	"ca":           "CA ID；省略时随机选择用途匹配的 CA，使用 list 查看清单",
	"chain":        "证书链路：ecc、native 或 aaa",
	"domain":       "TLS DNS SAN，多域名用逗号分隔，例如 \"*.demo.com,demo.com\"；不包含协议或端口",
	"ip":           "TLS IP SAN，多个 IP 用逗号分隔",
	"subject":      "终端证书名称 / 测试发布者名称",
	"organization": "测试组织名称",
	"valid-for":    "终端证书有效期，例如 24h、8760h；默认 365 天，实际到期时间受父证书链限制",
	"out":          "新输出目录；省略时使用 out/<UTC时间戳>，拒绝覆盖现有目录",
	"password-env": "PKCS#12 密码所在的环境变量名；未指定时 generate 创建 password.txt，sign 从该文件读取",
	"input":        "待签名的原始软件/JAR 文件路径",
	"output":       "签名后的新文件路径，不能覆盖现有文件",
	"tool":         "签名工具路径；默认在 PATH 查找 osslsigncode 或 jarsigner",
	"bundle":       "generate 生成的证书包目录",
	"listen":       "HTTPS 监听地址；内网测试指定服务器内网 IP:端口",
	"data-dir":     "Web 工作目录，保存历史索引、上传文件和默认生成产物",
	"open":         "自动打开浏览器；使用 --open=false 关闭自动打开",
}

func configureHelp(f *flag.FlagSet) {
	f.SetOutput(os.Stdout)
	f.VisitAll(func(v *flag.Flag) {
		if s, ok := flagHelp[v.Name]; ok {
			v.Usage = s
		}
		if f.Name() == "sign" && v.Name == "type" {
			v.Usage = "签名类型（必填）：software（软件签名）或 jar（JAR 签名）"
		}
		if f.Name() == "web" && v.Name == "listen" {
			v.Usage = "管理端 HTTP 监听地址；默认仅本机可访问"
		}
	})
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "🔎 FakeCA — "+f.Name())
		fmt.Fprintln(f.Output())
		fmt.Fprintln(f.Output(), commandHelp[f.Name()])
		fmt.Fprintln(f.Output(), "⚙️ 参数说明")
		printFlag := func(v *flag.Flag) {
			value := " <值>"
			if v.Name == "json" || v.Name == "open" {
				value = ""
			}
			if v.Name == "valid-for" {
				value = " <时长>"
			}
			fmt.Fprintf(f.Output(), "  --%s%s\n      %s", v.Name, value, v.Usage)
			if v.DefValue != "" && v.DefValue != "false" {
				def := v.DefValue
				if v.Name == "valid-for" {
					def = "365 天 / 8760h"
				}
				if v.Name == "open" {
					def = "开启"
				}
				fmt.Fprintf(f.Output(), "（默认：%s）", def)
			}
			fmt.Fprintln(f.Output())
		}
		groups := []struct {
			title string
			names []string
		}{
			{"🌐 类型与身份", []string{"type", "domain", "ip", "subject", "organization"}},
			{"🔗 CA 与证书链", []string{"ca", "chain", "bundle"}},
			{"📁 有效期与产物", []string{"valid-for", "out", "password-env"}},
			{"✍️ 文件签名", []string{"input", "output", "tool"}},
			{"🖥️ 服务与显示", []string{"listen", "open", "data-dir", "json"}},
		}
		seen := map[string]bool{}
		for _, g := range groups {
			printed := false
			for _, name := range g.names {
				if v := f.Lookup(name); v != nil {
					if !printed {
						fmt.Fprintln(f.Output(), "\n"+g.title)
						printed = true
					}
					printFlag(v)
					seen[name] = true
				}
			}
		}
		f.VisitAll(func(v *flag.Flag) {
			if !seen[v.Name] {
				printFlag(v)
			}
		})
	}
}

func typeLabel(value string) string {
	switch value {
	case "tls":
		return "TLS 域名 / IP 证书"
	case "software":
		return "软件代码签名"
	case "jar":
		return "JAR 代码签名"
	case "codesign":
		return "代码签名"
	default:
		return value
	}
}
func chainLabel(value string) string {
	switch value {
	case "ecc":
		return "ecc（经 emSign ECC G3 根）"
	case "native":
		return "native（emSign TLS/CS 自签名根）"
	case "aaa":
		return "aaa（经 Sectigo AAA 根）"
	default:
		return value
	}
}

func joinValues(values []string) string {
	if len(values) == 0 {
		return "未设置"
	}
	return strings.Join(values, ", ")
}
