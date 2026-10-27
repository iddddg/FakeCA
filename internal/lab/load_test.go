package lab

import (
	"archive/zip"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBundleIntegrity(t *testing.T) {
	e := entry(t, "dv-tls-g3b", "ecc", "tls")
	path := filepath.Join(t.TempDir(), "bundle")
	_, err := Generate(e, Options{Type: "tls", Domains: []string{"test.invalid"}, Subject: "Audit", ValidFor: time.Hour, Out: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = LoadBundle(path); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"leaf.pem", "ca.pem", "root.pem", "issuers.pem", "chain-with-root.pem", "chain.pem", "leaf.key"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(path, name)
			original, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(p, original, 0600)
			if err = os.WriteFile(p, []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = LoadBundle(path); err == nil {
				t.Fatal("accepted corrupt bundle file")
			}
		})
	}
	p := filepath.Join(path, "report.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	report.LeafSHA256 = strings.Repeat("0", 64)
	changed, _ := json.Marshal(report)
	if err = os.WriteFile(p, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadBundle(path); err == nil {
		t.Fatal("accepted report/certificate mismatch")
	}
}

func TestFutureParentRejected(t *testing.T) {
	e := entry(t, "dv-tls-g3b", "native", "tls")
	copy := *e.Parents[0]
	copy.NotBefore = time.Now().Add(time.Hour)
	e.Parents = append([]*x509.Certificate(nil), e.Parents...)
	e.Parents[0] = &copy
	if _, err := Generate(e, Options{Type: "tls", Domains: []string{"test.invalid"}, Subject: "Audit", ValidFor: 24 * time.Hour, Out: filepath.Join(t.TempDir(), "must-not-exist")}); err == nil {
		t.Fatal("accepted not-yet-valid parent")
	}
}

func TestJARRejectsWrongPasswordAndUnrelatedIdentity(t *testing.T) {
	dir := t.TempDir()
	e := entry(t, "ov-cs-g3b", "aaa", "codesign")
	path := filepath.Join(dir, "a")
	if _, err := Generate(e, Options{Type: "jar", Subject: "Audit", ValidFor: time.Hour, Out: path, Password: "correct-a"}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "input.jar")
	file, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(file)
	w, err := z.Create("test.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("harmless fixture"))
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	file.Close()
	// This executable is only a resolvable tool placeholder. Identity validation
	// must reject the request before a process is ever started.
	tool, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "must-not-exist.jar")
	if err = Sign(SignOptions{Type: "jar", Bundle: path, Input: input, Output: output, Tool: tool, Password: "wrong"}); err == nil || !strings.Contains(err.Error(), "解密") {
		t.Fatalf("wrong password not rejected: %v", err)
	}
	other := filepath.Join(dir, "b")
	if _, err = Generate(e, Options{Type: "jar", Subject: "Other identity", ValidFor: time.Hour, Out: other, Password: "correct-b"}); err != nil {
		t.Fatal(err)
	}
	p12, err := os.ReadFile(filepath.Join(other, "identity.p12"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(path, "identity.p12"), p12, 0600); err != nil {
		t.Fatal(err)
	}
	if err = Sign(SignOptions{Type: "jar", Bundle: path, Input: input, Output: output, Tool: tool, Password: "correct-b"}); err == nil || !strings.Contains(err.Error(), "身份或证书链") {
		t.Fatalf("unrelated P12 not rejected: %v", err)
	}
	if _, err = os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid identity produced an output file")
	}
}
