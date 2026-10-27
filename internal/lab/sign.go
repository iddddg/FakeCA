package lab

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"strings"
	"time"
)

type SignOptions struct {
	Type, Bundle, Input, Output, Tool, Password string
	Context                                     context.Context
	Log                                         io.Writer
}

func Sign(o SignOptions) error {
	writer := o.Log
	if writer == nil {
		writer = os.Stdout
	}
	if o.Type != "jar" && o.Type != "software" {
		return fmt.Errorf("签名类型必须为 software 或 jar；例如 fakeca sign --type jar --bundle DIR --input FILE --output FILE")
	}
	if o.Input == "" || o.Output == "" || o.Bundle == "" {
		return fmt.Errorf("签名缺少必要参数：请同时提供 --bundle、--input 和 --output")
	}
	bundle, err := filepath.Abs(o.Bundle)
	if err != nil {
		return fmt.Errorf("解析 --bundle 路径失败：%w", err)
	}
	input, err := filepath.Abs(o.Input)
	if err != nil {
		return fmt.Errorf("解析 --input 路径失败：%w", err)
	}
	output, err := filepath.Abs(o.Output)
	if err != nil {
		return fmt.Errorf("解析 --output 路径失败：%w", err)
	}
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("无法读取原始文件 %s，请检查 --input 路径：%w", input, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("--input 必须指向普通文件，不能是目录或设备：%s", input)
	}
	if _, err = os.Lstat(output); err == nil {
		return fmt.Errorf("输出文件已存在：%s；为保留现有文件，请指定新的 --output 路径", output)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("无法检查输出文件状态：%w", err)
	}
	loaded, err := LoadBundle(bundle)
	if err != nil {
		return err
	}
	report := loaded.Report
	if report.Type != "jar" && report.Type != "software" {
		return fmt.Errorf("该证书包不用于代码签名；请使用 generate --type software 或 jar 生成")
	}
	if err = loaded.CheckCurrent(); err != nil {
		return err
	}
	if o.Type == "jar" {
		z, err := zip.OpenReader(input)
		if err != nil {
			return fmt.Errorf("无法读取 JAR 文件；--input 必须是有效的 JAR/ZIP 归档：%w", err)
		}
		z.Close()
	}
	tool := o.Tool
	if tool == "" {
		if o.Type == "jar" {
			tool = "jarsigner"
		} else {
			tool = "osslsigncode"
		}
	}
	resolved, err := exec.LookPath(tool)
	if err != nil {
		return fmt.Errorf("未找到签名工具 %q；software 需要 osslsigncode，jar 需要 JDK jarsigner；请安装并加入 PATH，或通过 --tool 指定路径：%w", tool, err)
	}
	if err = os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return fmt.Errorf("无法创建签名输出目录：%w", err)
	}
	temp, err := os.MkdirTemp(filepath.Dir(output), ".fakeca-sign-")
	if err != nil {
		return fmt.Errorf("无法创建签名临时目录：%w", err)
	}
	defer os.RemoveAll(temp)
	staged := filepath.Join(temp, filepath.Base(output))
	var args []string
	env := os.Environ()
	if o.Type == "jar" {
		password := o.Password
		if password == "" {
			p, err := os.ReadFile(filepath.Join(bundle, "password.txt"))
			if err != nil {
				return fmt.Errorf("无法读取 password.txt；请通过 --password-env 指定 PKCS#12 密码所在的环境变量：%w", err)
			}
			password = strings.TrimSpace(string(p))
		}
		p12, err := os.ReadFile(filepath.Join(bundle, "identity.p12"))
		if err != nil {
			return fmt.Errorf("读取 identity.p12 失败：%w", err)
		}
		key, cert, parents, err := pkcs12.DecodeChain(p12, password)
		if err != nil {
			return fmt.Errorf("无法解密或解析 identity.p12，请检查密码环境变量或 password.txt：%w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok || !bytes.Equal(cert.Raw, loaded.Leaf.Raw) || len(parents) != len(loaded.Parents) {
			return fmt.Errorf("identity.p12 的身份或证书链与报告不一致")
		}
		public, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !public.Equal(loaded.Leaf.PublicKey) {
			return fmt.Errorf("identity.p12 的私钥与终端证书不匹配")
		}
		for i, parent := range parents {
			if !bytes.Equal(parent.Raw, loaded.Parents[i].Raw) {
				return fmt.Errorf("identity.p12 的父证书链与报告不一致")
			}
		}
		filtered := env[:0]
		for _, v := range env {
			if !strings.HasPrefix(strings.ToUpper(v), "FAKECA_SIGN_PASSWORD=") {
				filtered = append(filtered, v)
			}
		}
		env = append(filtered, "FAKECA_SIGN_PASSWORD="+password)
		args = []string{"-J-Dfile.encoding=UTF-8", "-J-Dsun.stdout.encoding=UTF-8", "-J-Dsun.stderr.encoding=UTF-8", "-keystore", filepath.Join(bundle, "identity.p12"), "-storetype", "PKCS12", "-storepass:env", "FAKECA_SIGN_PASSWORD", "-keypass:env", "FAKECA_SIGN_PASSWORD", "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256", "-signedjar", staged, input, "1"}
	} else {
		args = []string{"sign", "-certs", filepath.Join(bundle, loaded.Files.FullChain), "-key", filepath.Join(bundle, loaded.Files.PrivateKey), "-h", "sha256", "-n", "FakeCA internal negative trust test", "-in", input, "-out", staged}
	}
	parent := o.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Env = env
	cmd.Stdout = writer
	cmd.Stderr = writer
	if o.Log == nil {
		cmd.Stderr = os.Stderr
	}
	fmt.Fprintf(writer, "ℹ️ 正在调用签名工具：%s\n  原始文件：%s\n  以下为签名工具的原始输出：\n", resolved, input)
	if err = cmd.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			return fmt.Errorf("签名操作已取消，证书包仍保留在 %s", bundle)
		}
		if ctx.Err() != nil {
			return fmt.Errorf("签名操作超时（限时 2 分钟），请检查签名工具和输入文件：%w", ctx.Err())
		}
		return fmt.Errorf("签名工具执行失败，请查看上方原始输出；证书包仍保留在 %s：%w", bundle, err)
	}
	in, err := os.Open(staged)
	if err != nil {
		return fmt.Errorf("签名工具未生成可读取的结果文件：%w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("无法创建签名结果文件 %s；请检查权限或文件是否已存在：%w", output, err)
	}
	_, err = io.Copy(out, in)
	ce := out.Close()
	if err != nil {
		return fmt.Errorf("写入签名结果失败，%s 可能是不完整文件：%w", output, err)
	}
	if ce != nil {
		return fmt.Errorf("保存签名结果失败：%w", ce)
	}
	fmt.Fprintf(writer, "✅ 文件签名已完成\n  输出文件：%s\n  这表示签名文件已生成，是否被信任仍需在目标设备的实际验证路径中检查。\n", output)
	return nil
}
