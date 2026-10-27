package lab

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iddddg/FakeCA/internal/catalog"
)

type Bundle struct {
	Report  Report
	Files   BundleFiles
	Pair    tls.Certificate
	Leaf    *x509.Certificate
	Parents []*x509.Certificate
}

// LoadBundle checks the actual files, pinned incident chain and report agree.
// It does not consult system trust or revocation, and permits viewing expired
// bundles; serving/signing calls CheckCurrent separately.
func LoadBundle(path string) (Bundle, error) {
	var b Bundle
	data, err := os.ReadFile(filepath.Join(path, "report.json"))
	if err != nil {
		return b, fmt.Errorf("读取证书包 report.json 失败：%w", err)
	}
	if len(data) > 1<<20 {
		return b, fmt.Errorf("证书包报告超过 1 MiB，无法读取")
	}
	if err = json.Unmarshal(data, &b.Report); err != nil {
		return b, fmt.Errorf("证书包报告不是有效的 JSON：%w", err)
	}
	r := b.Report
	b.Files, err = BundleFilesForVersion(r.Version)
	if err != nil {
		return b, err
	}
	if r.Type != "tls" && r.Type != "software" && r.Type != "jar" {
		return b, fmt.Errorf("证书包类型无效：%q", r.Type)
	}
	entries, err := catalog.Load()
	if err != nil {
		return b, err
	}
	kind := "codesign"
	if r.Type == "tls" {
		kind = "tls"
	}
	if r.CA.ID == "" {
		return b, fmt.Errorf("证书包报告缺少 CA ID")
	}
	ca, err := catalog.Select(entries, r.CA.ID, r.CA.Chain, kind)
	if err != nil {
		return b, err
	}
	if r.CA.SHA256 != ca.SHA256 || r.CA.SPKISHA256 != ca.SPKISHA256 || r.CA.Usage != ca.Usage {
		return b, fmt.Errorf("报告中的 CA 身份或指纹与内置证书不一致")
	}
	f := b.Files
	b.Pair, err = tls.LoadX509KeyPair(filepath.Join(path, f.FullChain), filepath.Join(path, f.PrivateKey))
	if err != nil {
		return b, fmt.Errorf("加载 %s 或 %s 失败，证书与私钥必须匹配：%w", f.FullChain, f.PrivateKey, err)
	}
	b.Leaf, err = x509.ParseCertificate(b.Pair.Certificate[0])
	if err != nil {
		return b, fmt.Errorf("解析终端证书失败：%w", err)
	}
	b.Parents = append([]*x509.Certificate{ca.Cert}, ca.Parents...)
	expected := map[string][]*x509.Certificate{
		f.Certificate: {b.Leaf}, f.IssuingCA: {ca.Cert}, f.Root: {ca.Parents[len(ca.Parents)-1]},
		f.Intermediates:     b.Parents[:len(b.Parents)-1],
		f.FullChainWithRoot: append([]*x509.Certificate{b.Leaf}, b.Parents...),
	}
	if len(b.Pair.Certificate) != len(b.Parents) {
		return b, fmt.Errorf("%s 的证书数量不符合所选链路", f.FullChain)
	}
	for i, c := range b.Parents[:len(b.Parents)-1] {
		if !bytes.Equal(b.Pair.Certificate[i+1], c.Raw) {
			return b, fmt.Errorf("%s 的第 %d 张证书与所选链路不一致", f.FullChain, i+2)
		}
	}
	for name, want := range expected {
		raw, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			return b, fmt.Errorf("读取证书包 %s 失败：%w", name, err)
		}
		for i, c := range want {
			block, rest := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, c.Raw) {
				return b, fmt.Errorf("%s 的第 %d 张证书与所选链路不一致", name, i+1)
			}
			raw = rest
		}
		if len(bytes.TrimSpace(raw)) != 0 {
			return b, fmt.Errorf("%s 含有多余或无效内容", name)
		}
	}
	if !bytes.Equal(b.Leaf.RawIssuer, ca.Cert.RawSubject) {
		return b, fmt.Errorf("终端证书的颁发者与所选 CA 不一致")
	}
	if err = b.Leaf.CheckSignatureFrom(ca.Cert); err != nil {
		return b, fmt.Errorf("终端证书未通过 CA 签名校验：%w", err)
	}
	usage := x509.ExtKeyUsageCodeSigning
	if kind == "tls" {
		usage = x509.ExtKeyUsageServerAuth
	}
	if b.Leaf.IsCA || len(b.Leaf.ExtKeyUsage) != 1 || b.Leaf.ExtKeyUsage[0] != usage {
		return b, fmt.Errorf("终端证书的用途与报告类型不一致")
	}
	if r.LeafSHA256 != catalog.Hash(b.Leaf.Raw) || !strings.EqualFold(r.LeafSerial, b.Leaf.SerialNumber.Text(16)) || !r.NotBefore.Equal(b.Leaf.NotBefore) || !r.NotAfter.Equal(b.Leaf.NotAfter) {
		return b, fmt.Errorf("终端证书的指纹、序列号或有效期与报告不一致")
	}
	if len(r.ChainSHA256) != len(b.Parents) {
		return b, fmt.Errorf("报告中的证书链指纹数量不正确")
	}
	for i, c := range b.Parents {
		if r.ChainSHA256[i] != catalog.Hash(c.Raw) {
			return b, fmt.Errorf("报告中的第 %d 个父证书指纹不正确", i+1)
		}
	}
	if len(r.Domains) != len(b.Leaf.DNSNames) || len(r.IPs) != len(b.Leaf.IPAddresses) {
		return b, fmt.Errorf("报告中的域名或 IP 与终端证书不一致")
	}
	for i, d := range r.Domains {
		if d != b.Leaf.DNSNames[i] {
			return b, fmt.Errorf("报告中的域名与终端证书不一致")
		}
	}
	for i, ip := range r.IPs {
		if parsed := net.ParseIP(ip); parsed == nil || !parsed.Equal(b.Leaf.IPAddresses[i]) {
			return b, fmt.Errorf("报告中的 IP 与终端证书不一致")
		}
	}
	return b, nil
}

func (b Bundle) CheckCurrent() error {
	now := time.Now()
	for _, cert := range append([]*x509.Certificate{b.Leaf}, b.Parents...) {
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return fmt.Errorf("证书 %s 尚未生效或已过期，请重新生成并核对系统时间", cert.Subject.CommonName)
		}
	}
	return nil
}
