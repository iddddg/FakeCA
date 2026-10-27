package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fakeca/internal/catalog"
	"fakeca/internal/lab"
)

const usage = `🔎 FakeCA — 内网证书与软件签名信任验证工具

使用 eMudhra 事件中已失守、已吊销的 CA 生成测试证书或签名文件，
用于检查设备和应用是否仍接受这些证书链。内置 16 张涉事 CA 证书，
支持 8 个 CA 身份和 3 种链路，共 24 种测试组合。

用法：
  fakeca <命令> [参数]

🧭 命令导航
  list       列出内置 CA、用途、链路和证书指纹
  generate   生成 TLS / 软件 / JAR 签名证书，可同时签名文件
  serve      使用生成的 TLS 证书启动 HTTPS 测试服务
  sign       使用已有证书包签名软件或 JAR 文件
  web        启动 Vue 3 网页工作台，自动打开浏览器
  help       查看帮助；help <命令> 查看详细参数

🚀 快速开始
  fakeca web
  fakeca list
  fakeca generate --type tls --domain ca-test.example.internal --out out/tls-test
  fakeca generate --type tls --domain "*.demo.com,demo.com" --out out/tls-multi
  fakeca serve --bundle out/tls-test --listen 127.0.0.1:8443
  fakeca generate --type software --ca ov-cs-g3b --chain aaa --out out/code-test

📌 参数要点
  --ca 不指定时，在用途匹配的 CA 中随机选择；--chain 默认 ecc。
  证书默认有效期为 365 天，实际到期时间受父证书链限制。
  TLS 至少提供 --domain 或 --ip；软件/JAR 签名需要原始文件。
  多域名用逗号分隔，例如 "*.demo.com,demo.com"，同时覆盖一级子域名和根域名。
  软件签名依赖 osslsigncode；JAR 签名依赖 JDK jarsigner。
  输出目录必须是新目录；程序不会修改系统信任库。
  设备拒绝连接不一定代表吊销检查生效，需记录具体错误原因。

📚 更多帮助
  fakeca --help
  fakeca help generate
  fakeca sign --help
  完整测试方法参阅 README.md。
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "❌ 操作失败：", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		if len(args) > 2 {
			return fmt.Errorf("用法：fakeca help [命令]")
		}
		if len(args) == 2 {
			if _, ok := commandHelp[args[1]]; !ok {
				return fmt.Errorf("未知命令 %q；使用 fakeca --help 查看帮助", args[1])
			}
			return run([]string{args[1], "--help"})
		}
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		if len(args) > 1 {
			return fmt.Errorf("总帮助不接受额外参数；查看子命令请使用 fakeca help <命令>")
		}
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "list":
		return list(args[1:])
	case "generate":
		return generate(args[1:])
	case "serve":
		return serve(args[1:])
	case "sign":
		return sign(args[1:])
	case "web":
		return web(args[1:])
	default:
		return fmt.Errorf("未知命令 %q；运行 fakeca --help 查看可用命令", args[0])
	}
}
func parse(f *flag.FlagSet, args []string) error {
	configureHelp(f)
	if len(args) == 0 && f.Name() != "list" && f.Name() != "web" {
		f.Usage()
		return flag.ErrHelp
	}
	// Keep flag's internal diagnostics available as causes, but show one
	// concise, localized error instead of an English error + full usage dump.
	output := f.Output()
	f.SetOutput(io.Discard)
	err := f.Parse(args)
	f.SetOutput(output)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			f.Usage()
			return err
		}
		message := err.Error()
		switch {
		case strings.HasPrefix(message, "flag provided but not defined: "):
			message = "未知参数：" + strings.TrimPrefix(message, "flag provided but not defined: ")
		case strings.HasPrefix(message, "flag needs an argument: "):
			message = "参数缺少值：" + strings.TrimPrefix(message, "flag needs an argument: ")
		case strings.Contains(message, "for flag -valid-for"):
			message = "--valid-for 的时长格式无效，请使用 24h 或 8760h，不支持 365d"
		case strings.Contains(message, "for flag -json") || strings.Contains(message, "for -json:"):
			message = "--json 的值无效；请直接使用 --json，或指定 --json=true / --json=false"
		case strings.Contains(message, "for -open:"):
			message = "--open 的值无效；请使用 --open=true 或 --open=false"
		case strings.HasPrefix(message, "bad flag syntax: "):
			message = "参数格式无效：" + strings.TrimPrefix(message, "bad flag syntax: ")
		default:
			message = "参数解析失败：" + message
		}
		return fmt.Errorf("%s；运行 fakeca help %s 查看参数说明", message, f.Name())
	}
	if f.NArg() != 0 {
		return fmt.Errorf("无法识别位置参数 %q；参数值含空格时请加引号；运行 fakeca help %s 查看示例", f.Args(), f.Name())
	}
	return nil
}
func split(s string) []string {
	if s == "" {
		return nil
	}
	p := strings.Split(s, ",")
	for i := range p {
		p[i] = strings.TrimSpace(p[i])
	}
	return p
}
func password(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return "", fmt.Errorf("密码环境变量 %s 未设置或为空；请先设置该变量，再通过 --password-env 指定变量名", name)
	}
	return v, nil
}
func generate(args []string) error {
	f := flag.NewFlagSet("generate", flag.ContinueOnError)
	typ := f.String("type", "tls", "tls, software, jar")
	ca := f.String("ca", "", "CA ID; default random compatible CA")
	chain := f.String("chain", "ecc", "ecc, native, aaa")
	domain := f.String("domain", "", "comma-separated DNS SANs")
	ips := f.String("ip", "", "comma-separated IP SANs")
	subject := f.String("subject", lab.DefaultSubject, flagHelp["subject"])
	org := f.String("organization", lab.DefaultOrganization, flagHelp["organization"])
	valid := f.Duration("valid-for", lab.DefaultValidity, "leaf validity; default 365 days, capped by parent chain expiry")
	out := f.String("out", "", "new output directory")
	passenv := f.String("password-env", "", "environment variable for PKCS#12 password; otherwise generate password.txt")
	input := f.String("input", "", "optional software/JAR input to sign")
	output := f.String("output", "", "signed output path")
	tool := f.String("tool", "", "path to jarsigner or osslsigncode")
	if err := parse(f, args); err != nil {
		return err
	}
	if (*input == "") != (*output == "") {
		return fmt.Errorf("--input 与 --output 必须同时提供，分别指定原始文件和签名后的新文件")
	}
	if *input != "" && *typ == "tls" {
		return fmt.Errorf("--type tls 只生成证书，不支持文件签名；签名文件请使用 --type software 或 jar")
	}
	if *tool != "" && *input == "" {
		return fmt.Errorf("--tool 仅用于同时签名文件，请一起提供 --input 和 --output")
	}
	if *typ == "tls" && *passenv != "" {
		return fmt.Errorf("--password-env 仅用于软件或 JAR 的 PKCS#12 身份，TLS 类型不需要此参数")
	}
	pass, err := password(*passenv)
	if err != nil {
		return err
	}
	if *out == "" {
		*out = filepath.Join("out", time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	opts := lab.Options{Type: *typ, Domains: split(*domain), IPs: split(*ips), Subject: *subject, Organization: *org, ValidFor: *valid, Out: *out, Password: pass}
	if err = lab.Validate(opts); err != nil {
		return err
	}
	entries, err := catalog.Load()
	if err != nil {
		return err
	}
	kind := "codesign"
	if *typ == "tls" {
		kind = "tls"
	}
	selected, err := catalog.Select(entries, *ca, *chain, kind)
	if err != nil {
		return err
	}
	report, err := lab.Generate(selected, opts)
	if err != nil {
		return fmt.Errorf("生成证书包失败：%w", err)
	}
	abs, err := filepath.Abs(*out)
	if err != nil {
		return fmt.Errorf("解析输出目录路径失败：%w", err)
	}
	fmt.Printf("✅ 证书包已生成\n  输出目录：%s\n  证书类型：%s\n  选用 CA：%s\n  证书链路：%s\n  生效时间：%s\n  到期时间：%s\n  CA 指纹（SHA-256）：%s\n  终端证书指纹（SHA-256）：%s\n  详细报告：%s\n", abs, typeLabel(*typ), selected.ID, chainLabel(selected.Chain), report.NotBefore.Format(time.RFC3339), report.NotAfter.Format(time.RFC3339), selected.SHA256, report.LeafSHA256, filepath.Join(abs, "report.json"))
	if *typ == "tls" {
		fmt.Printf("  🌐 Nginx 证书链：%s\n  🔑 Nginx 私钥：%s\n", filepath.Join(abs, "fullchain.pem"), filepath.Join(abs, "private.key"))
	}
	if *input != "" {
		return lab.Sign(lab.SignOptions{Type: *typ, Bundle: abs, Input: *input, Output: *output, Tool: *tool, Password: pass})
	}
	return nil
}
func sign(args []string) error {
	f := flag.NewFlagSet("sign", flag.ContinueOnError)
	typ := f.String("type", "", "software or jar")
	bundle := f.String("bundle", "", "code signing bundle directory")
	input := f.String("input", "", "original file")
	output := f.String("output", "", "new signed file")
	tool := f.String("tool", "", "path to signing executable")
	passenv := f.String("password-env", "", "environment variable for PKCS#12 password")
	if err := parse(f, args); err != nil {
		return err
	}
	pass, err := password(*passenv)
	if err != nil {
		return err
	}
	return lab.Sign(lab.SignOptions{Type: *typ, Bundle: *bundle, Input: *input, Output: *output, Tool: *tool, Password: pass})
}
