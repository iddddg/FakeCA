package lab

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/iddddg/FakeCA/internal/catalog"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func entry(t *testing.T, id, chain, usage string) catalog.Entry {
	t.Helper()
	entries, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, err := catalog.Select(entries, id, chain, usage)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestTLSBundle(t *testing.T) {
	e := entry(t, "dv-tls-g3b", "ecc", "tls")
	out := filepath.Join(t.TempDir(), "tls")
	o := Options{Type: "tls", Domains: []string{"ca-test.example.internal", "*.wild.example.internal"}, IPs: []string{"127.0.0.1"}, Subject: "Internal test", Organization: "Test", ValidFor: DefaultValidity, Out: out}
	report, err := Generate(e, o)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(out, "fullchain.pem"), filepath.Join(out, "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Certificate) != 3 {
		t.Fatalf("server should send leaf + two intermediates, got %d", len(pair.Certificate))
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca-test.example.internal", "127.0.0.1", "a.wild.example.internal"} {
		if err = leaf.VerifyHostname(name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"wild.example.internal", "a.b.wild.example.internal"} {
		if err = leaf.VerifyHostname(name); err == nil {
			t.Fatalf("wildcard unexpectedly matched %s", name)
		}
	}
	if err = leaf.CheckSignatureFrom(e.Cert); err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("invalid leaf purpose")
	}
	if len(leaf.CRLDistributionPoints) != 0 || len(leaf.OCSPServer) != 0 {
		t.Fatal("invented leaf revocation service")
	}
	if report.LeafSHA256 != catalog.Hash(leaf.Raw) {
		t.Fatal("report fingerprint differs")
	}
	if leaf.NotAfter.Sub(report.Created) != 365*24*time.Hour {
		t.Fatalf("expected default expiry 365 days after generation, got %s", leaf.NotAfter.Sub(report.Created))
	}
	rb, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved Report
	if err = json.Unmarshal(rb, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.CA.ID != e.ID || len(saved.ChainSHA256) != 3 {
		t.Fatal("incomplete manifest")
	}
	// Existing output must be untouched even when another bundle is requested.
	if _, err = Generate(e, o); err == nil {
		t.Fatal("overwrote existing directory")
	}
	after, _ := os.ReadFile(filepath.Join(out, "report.json"))
	if string(rb) != string(after) {
		t.Fatal("existing bundle changed")
	}
}
func TestCodeSigningBundles(t *testing.T) {
	for _, typ := range []string{"software", "jar"} {
		t.Run(typ, func(t *testing.T) {
			e := entry(t, "ov-cs-g3c", "aaa", "codesign")
			out := filepath.Join(t.TempDir(), typ)
			_, err := Generate(e, Options{Type: typ, Subject: "Test publisher", Organization: "Test", ValidFor: time.Hour, Out: out})
			if err != nil {
				t.Fatal(err)
			}
			p12, err := os.ReadFile(filepath.Join(out, "identity.p12"))
			if err != nil {
				t.Fatal(err)
			}
			password, err := os.ReadFile(filepath.Join(out, "password.txt"))
			if err != nil {
				t.Fatal(err)
			}
			key, leaf, parents, err := pkcs12.DecodeChain(p12, strings.TrimSpace(string(password)))
			if err != nil {
				t.Fatal(err)
			}
			if len(parents) != 2 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
				t.Fatal("wrong code signing chain")
			}
			if err = leaf.CheckSignatureFrom(e.Cert); err != nil {
				t.Fatal(err)
			}
			if !key.(*rsa.PrivateKey).PublicKey.Equal(leaf.PublicKey) {
				t.Fatal("P12 key mismatch")
			}
			if typ == "jar" {
				testJAR(t, out)
			} else {
				testSoftware(t, out)
			}
		})
	}
}

func testSoftware(t *testing.T, bundle string) {
	t.Helper()
	tool := os.Getenv("FAKECA_OSSLSIGNCODE")
	if tool == "" || runtime.GOOS != "windows" {
		t.Log("PE integration skipped: requires Windows and FAKECA_OSSLSIGNCODE")
		return
	}
	input, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "signed-test-runner.exe")
	if err = Sign(SignOptions{Type: "software", Bundle: bundle, Input: input, Output: out, Tool: tool}); err != nil {
		t.Fatal(err)
	}
	// An explicit fixture root is ONLY for cryptographic artifact validation.
	// It says nothing about OS trust or revocation. Never execute the artifact.
	result, err := exec.Command(tool, "verify", "-CAfile", filepath.Join(bundle, "root.pem"), "-in", out).CombinedOutput()
	if err != nil {
		t.Fatalf("Authenticode structure/signature: %v\n%s", err, result)
	}
	if !strings.Contains(string(result), "Signature verification: ok") {
		t.Fatalf("missing verified Authenticode signature: %s", result)
	}
}
func testJAR(t *testing.T, bundle string) {
	t.Helper()
	tool := os.Getenv("FAKECA_JARSIGNER")
	if tool == "" {
		var err error
		tool, err = exec.LookPath("jarsigner")
		if err != nil {
			t.Log("JAR external integration skipped: jarsigner unavailable")
			return
		}
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "test.jar")
	out := filepath.Join(dir, "signed.jar")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, err := z.Create("test.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("Harmless internal certificate validation fixture\n")); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	if err = Sign(SignOptions{Type: "jar", Bundle: bundle, Input: input, Output: out, Tool: tool, Log: &logs}); err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(logs.Bytes()) {
		t.Fatal("JAR signing diagnostics are not UTF-8")
	}
	result, err := exec.Command(tool, "-verify", "-verbose", "-certs", out).CombinedOutput()
	if err != nil {
		t.Fatalf("JAR signature verification: %v\n%s", err, result)
	}
	// This verifies archive signature structure, not platform trust/revocation.
	signed, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Close()
	hasSF, hasRSA := false, false
	for _, f := range signed.File {
		if strings.HasPrefix(f.Name, "META-INF/") {
			hasSF = hasSF || strings.HasSuffix(f.Name, ".SF")
			hasRSA = hasRSA || strings.HasSuffix(f.Name, ".RSA")
		}
	}
	if !hasSF || !hasRSA {
		t.Fatal("JAR missing signature entries")
	}
	if err = Sign(SignOptions{Type: "jar", Bundle: bundle, Input: input, Output: out, Tool: tool}); err == nil {
		t.Fatal("overwrote signed output")
	}
}
func TestValidation(t *testing.T) {
	base := Options{Type: "tls", Domains: []string{"test.invalid"}, Subject: "Test", ValidFor: time.Hour}
	cases := []Options{base, base, base, base, base, base, base}
	cases[0].Domains = nil
	cases[1].Domains = []string{"https://test.invalid"}
	cases[2].IPs = []string{"bad"}
	cases[3].ValidFor = 0
	cases[4].Type = "jar"
	cases[5].Domains = []string{"-bad.test"}
	cases[6].ValidFor = -time.Hour
	for i, c := range cases {
		if err := Validate(c); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if err := Validate(base); err != nil {
		t.Fatal(err)
	}
	base.ValidFor = DefaultValidity
	if err := Validate(base); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"*", "*.", "foo*.example.internal", "a.*.example.internal", "*.*.example.internal", "*.127.0.0.1"} {
		if validDomain(name) {
			t.Fatalf("accepted malformed wildcard %q", name)
		}
	}
	base.Domains = []string{"*.example.internal", "example.internal"}
	if err := Validate(base); err != nil {
		t.Fatal(err)
	}
}
func TestPEMParse(t *testing.T) {
	e := entry(t, "ov-cs-g3b", "native", "codesign")
	p, _ := pem.Decode(catalog.PEM(e.Cert))
	if p == nil {
		t.Fatal("missing certificate")
	}
}
