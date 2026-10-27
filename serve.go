package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/iddddg/FakeCA/internal/catalog"
	"github.com/iddddg/FakeCA/internal/lab"
)

func list(args []string) error {
	f := flag.NewFlagSet("list", flag.ContinueOnError)
	j := f.Bool("json", false, flagHelp["json"])
	if err := parse(f, args); err != nil {
		return err
	}
	entries, err := catalog.Load()
	if err != nil {
		return err
	}
	if *j {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(entries)
	}
	fmt.Println("🔎 内置 CA 清单（8 个身份，24 种链路组合）")
	fmt.Println("CA ID         用途          链路    证书指纹（SHA-256）")
	for _, e := range entries {
		usage := "TLS"
		if e.Usage == "codesign" {
			usage = "代码签名"
		}
		fmt.Printf("%-13s %-9s %-7s %s\n", e.ID, usage, e.Chain, e.SHA256)
	}
	fmt.Println("\n🔗 链路说明：ecc 经 ECC G3 根；native 使用 emSign TLS/CS 自签名根；aaa 经 Sectigo AAA 根。")
	return nil
}

func serve(args []string) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	bundle := f.String("bundle", "", flagHelp["bundle"])
	listen := f.String("listen", "127.0.0.1:8443", flagHelp["listen"])
	if err := parse(f, args); err != nil {
		return err
	}
	if *bundle == "" {
		return fmt.Errorf("缺少 --bundle；请指定 generate 生成的 TLS 证书包目录")
	}
	running, err := lab.StartTLS(*bundle, *listen, os.Stderr)
	if err != nil {
		return err
	}
	defer running.Stop()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Printf("✅ HTTPS 测试服务已启动\n  🌐 监听地址：%s\n  🔗 选用 CA：%s\n  证书链路：%s\n  证书域名：%s\n  证书 IP：%s\n\n📋 请使用证书中包含的域名或 IP 访问，并记录客户端实际验证错误。\n  按 Ctrl+C 停止服务。\n", running.Address, running.Report.CA.ID, chainLabel(running.Report.CA.Chain), joinValues(running.Report.Domains), joinValues(running.Report.IPs))
	select {
	case <-ctx.Done():
		fmt.Println("ℹ️ HTTPS 测试服务已停止。")
		return nil
	case err := <-running.Done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTPS 测试服务异常停止：%w", err)
		}
		return nil
	}
}
