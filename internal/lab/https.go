package lab

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// TLSServer is the same test endpoint for both CLI and web management.
type TLSServer struct {
	Server  *http.Server
	Address string
	Report  Report
	Done    chan error
}

func StartTLS(bundle, address string, diagnostics io.Writer) (*TLSServer, error) {
	loaded, err := LoadBundle(bundle)
	if err != nil {
		return nil, err
	}
	report := loaded.Report
	if report.Type != "tls" {
		return nil, fmt.Errorf("该证书包不是 TLS 类型，请先生成 TLS 证书")
	}
	if err = loaded.CheckCurrent(); err != nil {
		return nil, err
	}
	cert := loaded.Pair
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("无法监听 %s，请检查接口地址、端口占用和网络权限：%w", address, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "⚠️ FakeCA — 证书信任负向测试\n\n🔗 选用 CA：%s\n证书链路：%s\n终端证书指纹（SHA-256）：%s\n\n📋 当前请求已完成 TLS 握手并获取本测试页。\n如果没有手动忽略证书错误，请检查客户端及中间代理的证书验证策略。\n此结果只适用于当前请求路径，不能代表设备上所有应用的验证行为。\n", report.CA.ID, report.CA.Chain, report.LeafSHA256)
	})
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: log.New(diagnostics, "ℹ️ HTTPS 诊断：", log.LstdFlags), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	running := &TLSServer{Server: server, Address: listener.Addr().String(), Report: report, Done: make(chan error, 1)}
	go func() { running.Done <- server.Serve(tls.NewListener(listener, server.TLSConfig)); close(running.Done) }()
	return running, nil
}

func (s *TLSServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.Server.Shutdown(ctx)
	if err != nil {
		_ = s.Server.Close()
	}
	return err
}
