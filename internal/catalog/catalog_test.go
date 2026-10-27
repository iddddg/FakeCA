package catalog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestIncidentCatalog(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 24 {
		t.Fatalf("got %d path combinations", len(entries))
	}
	unique := map[string]bool{}
	for _, e := range entries {
		t.Run(e.ID+"/"+e.Chain, func(t *testing.T) {
			unique[e.SHA256] = true
			key, err := SigningKey(e)
			if err != nil {
				t.Fatal(err)
			}
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "test.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, e.Cert, &leafKey.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if err = c.CheckSignatureFrom(e.Cert); err != nil {
				t.Fatal(err)
			}
		})
	}
	if len(unique) != 16 {
		t.Fatalf("got %d distinct incident certs", len(unique))
	}
}
func TestSelection(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"tls", "codesign"} {
		for _, p := range []string{"ecc", "native", "aaa"} {
			e, err := Select(entries, "", p, u)
			if err != nil || e.Usage != u || e.Chain != p {
				t.Fatalf("selection: %+v %v", e, err)
			}
		}
	}
	for _, tc := range [][3]string{{"dv-tls-g3b", "aaa", "codesign"}, {"ov-cs-g3b", "ecc", "tls"}, {"missing", "ecc", "tls"}, {"", "missing", "tls"}} {
		if _, err = Select(entries, tc[0], tc[1], tc[2]); err == nil {
			t.Fatalf("accepted incompatible selection %v", tc)
		}
	}
}
