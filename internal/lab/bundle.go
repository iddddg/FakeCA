package lab

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fakeca/internal/catalog"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const DefaultValidity = 365 * 24 * time.Hour
const DefaultSubject = "FakeCA Internal Trust Test"
const DefaultOrganization = "Internal Security Test"

type Options struct {
	Type         string
	Domains      []string
	IPs          []string
	Subject      string
	Organization string
	ValidFor     time.Duration
	Out          string
	Password     string
}
type Report struct {
	Version     int           `json:"version"`
	Created     time.Time     `json:"created_at"`
	Type        string        `json:"type"`
	CA          catalog.Entry `json:"ca"`
	LeafSHA256  string        `json:"leaf_sha256"`
	LeafSerial  string        `json:"leaf_serial"`
	NotBefore   time.Time     `json:"not_before"`
	NotAfter    time.Time     `json:"not_after"`
	Domains     []string      `json:"domains,omitempty"`
	IPs         []string      `json:"ips,omitempty"`
	ChainSHA256 []string      `json:"chain_sha256"`
	Notes       []string      `json:"notes"`
}

func Validate(o Options) error {
	if o.Type != "tls" && o.Type != "software" && o.Type != "jar" {
		return fmt.Errorf("--type 仅支持 tls、software 或 jar；运行 fakeca help generate 查看示例")
	}
	if o.ValidFor <= 0 {
		return fmt.Errorf("--valid-for 必须大于 0，例如 24h 或 8760h")
	}
	if o.Type == "tls" && len(o.Domains)+len(o.IPs) == 0 {
		return fmt.Errorf("TLS 证书至少需要 --domain 或 --ip；例如 --domain \"*.demo.com,demo.com\"")
	}
	if o.Type != "tls" && len(o.Domains)+len(o.IPs) > 0 {
		return fmt.Errorf("--domain 和 --ip 仅适用于 --type tls；代码签名请使用 --subject 指定测试发布者")
	}
	if strings.TrimSpace(o.Subject) == "" {
		return fmt.Errorf("--subject 不能为空，请填写证书名称或测试发布者名称")
	}
	for _, d := range o.Domains {
		if !validDomain(d) {
			return fmt.Errorf("域名 %q 无效：请使用 ASCII/punycode，不含协议或端口；泛域名仅支持最左侧完整标签，例如 *.demo.com；多域名用逗号分隔", d)
		}
	}
	for _, ip := range o.IPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("IP 地址 %q 无效，请填写 IPv4 或 IPv6 地址，不含协议、端口或网段掩码", ip)
		}
	}
	return nil
}
func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	// A wildcard occupies exactly the entire leftmost DNS label. Keep it
	// in the SAN; validate the remaining labels with the ordinary rules.
	s = strings.TrimPrefix(s, "*.")
	if len(s) == 0 || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Generate writes a new directory without changing any trust store.
func Generate(e catalog.Entry, o Options) (Report, error) {
	var report Report
	if err := Validate(o); err != nil {
		return report, err
	}
	if (o.Type == "tls") != (e.Usage == "tls") {
		return report, fmt.Errorf("所选 CA 的用途与证书类型不匹配；TLS 与代码签名需要使用各自对应的 CA")
	}
	caKey, err := catalog.SigningKey(e)
	if err != nil {
		return report, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return report, fmt.Errorf("生成终端证书私钥失败：%w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return report, fmt.Errorf("生成证书序列号失败：%w", err)
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: o.Subject}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(o.ValidFor), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if o.Organization != "" {
		tmpl.Subject.Organization = []string{o.Organization}
	}
	if o.Type == "tls" {
		tmpl.DNSNames = o.Domains
		for _, ip := range o.IPs {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
		}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	// No invented leaf OCSP/CRL endpoint: the revoked CA must be checked.
	for _, c := range append([]*x509.Certificate{e.Cert}, e.Parents...) {
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return report, fmt.Errorf("父证书 %s 尚未生效或已过期，请选择其他链路并检查系统时间", c.Subject.CommonName)
		}
		if tmpl.NotBefore.Before(c.NotBefore) {
			tmpl.NotBefore = c.NotBefore
		}
		if tmpl.NotAfter.After(c.NotAfter) {
			tmpl.NotAfter = c.NotAfter
		}
	}
	if !tmpl.NotAfter.After(now) || !tmpl.NotAfter.After(tmpl.NotBefore) {
		return report, fmt.Errorf("所选证书链已过期或没有可用的有效期，请选择其他 CA/链路，并检查系统时间")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, e.Cert, &leafKey.PublicKey, caKey)
	if err != nil {
		return report, fmt.Errorf("签发终端证书失败：%w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return report, fmt.Errorf("解析新生成的终端证书失败：%w", err)
	}
	if err = leaf.CheckSignatureFrom(e.Cert); err != nil {
		return report, fmt.Errorf("新生成的终端证书未通过 CA 签名校验：%w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return report, fmt.Errorf("编码终端证书私钥失败：%w", err)
	}
	parents := append([]*x509.Certificate{e.Cert}, e.Parents...)
	full := append([]*x509.Certificate{leaf}, parents[:len(parents)-1]...)
	report = Report{Version: CurrentBundleVersion, Created: now, Type: o.Type, CA: e, LeafSHA256: catalog.Hash(leaf.Raw), LeafSerial: leaf.SerialNumber.Text(16), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Domains: o.Domains, IPs: o.IPs, Notes: []string{"证书信任负向测试：所选 CA 的私钥已失守，CA 证书已吊销。", "连接失败不等于吊销检查生效：请记录实际验证错误，并测试正常受信任的正向对照端点。", "终端证书不含吊销查询地址或 CT SCT；请检查整条 CA 链，不要通过导入测试根证书使测试通过。"}}
	for _, c := range parents {
		report.ChainSHA256 = append(report.ChainSHA256, catalog.Hash(c.Raw))
	}
	files, err := BundleFilesForVersion(report.Version)
	if err != nil {
		return report, err
	}
	contents := map[string][]byte{files.Certificate: catalog.PEM(leaf), files.PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), files.IssuingCA: catalog.PEM(e.Cert), files.FullChain: catalog.PEM(full...), files.Intermediates: catalog.PEM(parents[:len(parents)-1]...), files.Root: catalog.PEM(parents[len(parents)-1]), files.FullChainWithRoot: catalog.PEM(append([]*x509.Certificate{leaf}, parents...)...)}
	if o.Type != "tls" {
		password := o.Password
		if password == "" {
			var b [24]byte
			if _, err = rand.Read(b[:]); err != nil {
				return report, fmt.Errorf("生成 PKCS#12 随机密码失败：%w", err)
			}
			password = base64.RawURLEncoding.EncodeToString(b[:])
			contents["password.txt"] = []byte(password + "\n")
		}
		p12, err := pkcs12.Modern.Encode(leafKey, leaf, parents, password)
		if err != nil {
			return report, fmt.Errorf("导出 PKCS#12 证书身份失败：%w", err)
		}
		contents["identity.p12"] = p12
	}
	rb, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return report, fmt.Errorf("生成证书包报告失败：%w", err)
	}
	contents["report.json"] = append(rb, '\n')
	if err = os.MkdirAll(filepath.Dir(o.Out), 0700); err != nil {
		return report, fmt.Errorf("创建输出父目录失败：%w", err)
	}
	if err = os.Mkdir(o.Out, 0700); err != nil {
		return report, fmt.Errorf("无法创建输出目录 %s；目录必须尚不存在，请使用新的 --out 路径：%w", o.Out, err)
	}
	for name, data := range contents {
		if err = os.WriteFile(filepath.Join(o.Out, name), data, 0600); err != nil {
			return report, fmt.Errorf("写入 %s 失败，目录 %s 中可能保留部分文件；请检查后使用新目录重试：%w", name, o.Out, err)
		}
	}
	return report, nil
}
