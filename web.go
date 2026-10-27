package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"

	"github.com/iddddg/FakeCA/internal/webui"
)

func web(args []string) error {
	f := flag.NewFlagSet("web", flag.ContinueOnError)
	listen := f.String("listen", "127.0.0.1:8080", "管理界面监听地址")
	dir := f.String("data-dir", "out/web", "Web 工作目录")
	open := f.Bool("open", true, "自动打开浏览器")
	if err := parse(f, args); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("无法启动 Web 服务，请检查监听地址及端口占用：%w", err)
	}
	defer listener.Close()
	app, token, err := webui.New(*dir)
	if err != nil {
		return fmt.Errorf("初始化 Web 工作台失败：%w", err)
	}
	defer app.Close()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return err
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	address := "http://" + net.JoinHostPort(host, port) + "/#token=" + token
	server := &http.Server{Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 3 * time.Minute, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Printf("🌐 FakeCA 网页工作台已启动\n\n  🔗 访问地址：%s\n  📁 工作目录：%s\n  🧩 Vue 3 + Element Plus，静态资源已内嵌，无需联网。\n\n  🔑 地址包含本次会话的访问令牌，请仅交给管理人员。\n  🛑 按 Ctrl+C 关闭工作台及其启动的 TLS 测试服务。\n", address, app.Directory())
	if *open {
		if err = openBrowser(address); err != nil {
			fmt.Fprintf(os.Stderr, "ℹ️ 无法自动打开浏览器，请手动访问上方地址：%v\n", err)
		}
	}
	select {
	case <-ctx.Done():
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = server.Shutdown(c); err != nil {
			_ = server.Close()
		}
		fmt.Println("ℹ️ 网页工作台已停止。")
		return nil
	case err = <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("Web 服务异常停止：%w", err)
		}
		return nil
	}
}

func openBrowser(address string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address)
	case "darwin":
		command = exec.Command("open", address)
	default:
		command = exec.Command("xdg-open", address)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go command.Wait()
	return nil
}
