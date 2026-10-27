// Package catalog contains the public certificates from Mozilla bug 2083449.
package catalog

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

//go:embed certs/*.pem
var files embed.FS

type Entry struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Usage      string              `json:"usage"`
	Chain      string              `json:"chain"`
	SHA256     string              `json:"sha256"`
	SPKISHA256 string              `json:"spki_sha256"`
	Serial     string              `json:"serial"`
	Issuer     string              `json:"issuer"`
	Cert       *x509.Certificate   `json:"-"`
	Parents    []*x509.Certificate `json:"-"`
}

var pins = map[string][2]string{
	"dv-tls-g3b": {"42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493", "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE"},
	"dv-tls-g3c": {"0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19", "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72"},
	"ev-tls-g3b": {"E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838", "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512"},
	"ev-tls-g3c": {"432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3", "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F"},
	"ov-tls-g3b": {"98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B", "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699"},
	"ov-tls-g3c": {"CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F", "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489"},
	"ov-cs-g3b":  {"9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4", "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8"},
	"ov-cs-g3c":  {"4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1", "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"},
}

var rootPins = map[string]string{
	"root-aaa.pem":       "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4",
	"root-ecc.pem":       "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B",
	"root-tls-self.pem":  "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D",
	"root-cs-self.pem":   "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5",
	"root-tls-cross.pem": "3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD",
	"root-cs-cross.pem":  "7137FA71AD46BA686F746D1014AC57E8E6C6E9AF4AA2F73C0C44A5CF27DEBB59",
}

func Hash(b []byte) string { h := sha256.Sum256(b); return strings.ToUpper(hex.EncodeToString(h[:])) }
func read(name string) (*x509.Certificate, error) {
	b, e := files.ReadFile("certs/" + name)
	if e != nil {
		return nil, fmt.Errorf("读取内置证书 %s 失败：%w", name, e)
	}
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("内置证书 %s 的 PEM 格式无效", name)
	}
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析内置证书 %s 失败：%w", name, err)
	}
	return c, nil
}
func Load() ([]Entry, error) {
	var entries []Entry
	for _, id := range []string{"dv-tls-g3b", "dv-tls-g3c", "ov-tls-g3b", "ov-tls-g3c", "ev-tls-g3b", "ev-tls-g3c", "ov-cs-g3b", "ov-cs-g3c"} {
		usage := "tls"
		parent := "tls"
		if strings.Contains(id, "-cs-") {
			usage = "codesign"
			parent = "cs"
		}
		for _, chain := range []string{"ecc", "native", "aaa"} {
			parts := strings.Split(id, "-")
			filename := "EM-" + strings.ToUpper(parts[0]+"-"+parts[1]+"-CA-"+parts[2])
			idx := 0
			if chain == "aaa" {
				filename += "-AAA"
				idx = 1
			}
			c, e := read(filename + ".crt.pem")
			if e != nil {
				return nil, e
			}
			if Hash(c.Raw) != pins[id][idx] {
				return nil, fmt.Errorf("内置证书 %s 的 SHA-256 指纹与固定记录不符，请检查程序构建素材", filename)
			}
			var parents []*x509.Certificate
			names := []string{"root-" + parent + "-self.pem"}
			if chain == "ecc" {
				names = []string{"root-" + parent + "-cross.pem", "root-ecc.pem"}
			}
			if chain == "aaa" {
				names = []string{"root-aaa.pem"}
			}
			for _, n := range names {
				p, e := read(n)
				if e != nil {
					return nil, e
				}
				if Hash(p.Raw) != rootPins[n] {
					return nil, fmt.Errorf("父证书 %s 的 SHA-256 指纹与固定记录不符", n)
				}
				parents = append(parents, p)
			}
			child := c
			for _, p := range parents {
				if !bytes.Equal(child.RawIssuer, p.RawSubject) {
					return nil, fmt.Errorf("证书链颁发者不匹配：%s", child.Subject)
				}
				if e := child.CheckSignatureFrom(p); e != nil {
					return nil, fmt.Errorf("证书链 %s/%s 的签名校验失败：%w", id, chain, e)
				}
				child = p
			}
			// The anchor is pinned above. Its historical SHA-1 self-signature
			// (AAA) is not a path signature and need not be trusted or enabled.
			if !bytes.Equal(child.RawIssuer, child.RawSubject) {
				return nil, fmt.Errorf("证书链末端根证书不是自颁发证书")
			}
			entries = append(entries, Entry{ID: id, Name: c.Subject.CommonName, Usage: usage, Chain: chain, SHA256: Hash(c.Raw), SPKISHA256: Hash(c.RawSubjectPublicKeyInfo), Serial: strings.ToUpper(c.SerialNumber.Text(16)), Issuer: c.Issuer.CommonName, Cert: c, Parents: parents})
		}
	}
	return entries, nil
}

func Select(entries []Entry, id, chain, usage string) (Entry, error) {
	if chain != "ecc" && chain != "native" && chain != "aaa" {
		return Entry{}, fmt.Errorf("--chain 仅支持 ecc、native 或 aaa；运行 fakeca help generate 查看链路说明")
	}
	id = strings.ToLower(id)
	var candidates []Entry
	for _, e := range entries {
		if e.Chain == chain && e.Usage == usage && (id == "" || id == e.ID) {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return Entry{}, fmt.Errorf("未找到用途匹配的 CA（ID=%q，用途=%s，链路=%s）；运行 fakeca list 查看清单，TLS 与代码签名的 CA 不能混用", id, usage, chain)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return Entry{}, err
	}
	return candidates[n.Int64()], nil
}

// SigningKey is restricted to the eight pinned incident identities. No arbitrary
// certificate or private key is accepted. The CA key is never written to disk.
func SigningKey(e Entry) (*ecdsa.PrivateKey, error) {
	allowed, ok := pins[e.ID]
	if !ok || e.Cert == nil {
		return nil, fmt.Errorf("只能使用内置事件清单中的 CA 身份")
	}
	fingerprint := Hash(e.Cert.Raw)
	if fingerprint != allowed[0] && fingerprint != allowed[1] {
		return nil, fmt.Errorf("所选 CA 的证书指纹不在固定事件清单中")
	}
	pub, ok := e.Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, fmt.Errorf("所选 CA 的公钥类型异常，预期为 P-384 椭圆曲线公钥")
	}
	for i := int64(1); i < 256; i++ {
		d := big.NewInt(i)
		x, y := pub.Curve.ScalarBaseMult(d.Bytes())
		if x.Cmp(pub.X) == 0 && y.Cmp(pub.Y) == 0 {
			return &ecdsa.PrivateKey{PublicKey: *pub, D: d}, nil
		}
	}
	return nil, fmt.Errorf("所选 CA 公钥不符合本次事件公开的弱密钥特征，无法恢复测试签名密钥")
}

func PEM(certs ...*x509.Certificate) []byte {
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}
