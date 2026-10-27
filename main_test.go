package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iddddg/FakeCA/internal/catalog"
	"github.com/iddddg/FakeCA/internal/lab"
)

func captureCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "cli-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	old := os.Stdout
	os.Stdout = file
	defer func() { os.Stdout = old }()
	err = run(args)
	if err2 := file.Sync(); err2 != nil {
		t.Fatal(err2)
	}
	data, err2 := os.ReadFile(file.Name())
	if err2 != nil {
		t.Fatal(err2)
	}
	return string(data), err
}

func TestCLIHelpAndErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"-h"}, {"help"}, {"help", "generate"}, {"generate", "--help"}, {"serve"}, {"sign"}, {"web", "--help"}, {"help", "list"}} {
		out, err := captureCLI(t, args...)
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("help %v: %v", args, err)
		}
		if !strings.Contains(out, "FakeCA") {
			t.Fatalf("help empty: %v", args)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"--help", "unexpected"}, {"help", "unknown"}, {"generate", "--unknown"}, {"generate", "--domain"}, {"generate", "--valid-for", "365d"}, {"list", "--json=bad"}, {"web", "--open=bad"}, {"generate", "--type", "tls"}, {"generate", "--domain", "https://demo.com"}, {"generate", "--domain", "demo.com", "--valid-for", "0"}, {"generate", "--type", "jar", "--ca", "dv-tls-g3b"}} {
		_, err := captureCLI(t, args...)
		if err == nil || errors.Is(err, flag.ErrHelp) {
			t.Fatalf("accepted invalid CLI arguments: %v", args)
		}
	}
	out, err := captureCLI(t, "list", "--json")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(out), "[") || strings.Contains(out, "🔎") {
		t.Fatal("list JSON contains prose")
	}
}

func TestCLIGenerationMatrix(t *testing.T) {
	entries, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, ca := range entries {
		kind := "tls"
		if ca.Usage == "codesign" {
			kind = "software"
		}
		kinds := []string{kind}
		if kind == "software" {
			kinds = append(kinds, "jar")
		}
		for _, kind := range kinds {
			t.Run(ca.ID+"/"+ca.Chain+"/"+kind, func(t *testing.T) {
				out := filepath.Join(dir, ca.ID+"-"+ca.Chain+"-"+kind)
				args := []string{"generate", "--type", kind, "--ca", ca.ID, "--chain", ca.Chain, "--out", out}
				if kind == "tls" {
					args = append(args, "--domain", "*.demo.com,demo.com", "--ip", "127.0.0.1,::1")
				}
				text, err := captureCLI(t, args...)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(text, "✅ 证书包已生成") {
					t.Fatal("missing result summary")
				}
				loaded, err := lab.LoadBundle(out)
				if err != nil {
					t.Fatal(err)
				}
				if loaded.Report.CA.ID != ca.ID || loaded.Report.CA.Chain != ca.Chain || loaded.Report.Type != kind {
					t.Fatal("parameters not preserved")
				}
				if loaded.Report.NotAfter.Sub(loaded.Report.Created) != 365*24*time.Hour {
					t.Fatal("default validity differs")
				}
				if kind == "tls" {
					for _, name := range []string{"demo.com", "www.demo.com", "127.0.0.1", "::1"} {
						if err = loaded.Leaf.VerifyHostname(name); err != nil {
							t.Fatal(err)
						}
					}
					if err = loaded.Leaf.VerifyHostname("a.b.demo.com"); err == nil {
						t.Fatal("wildcard covered multiple labels")
					}
				}
			})
		}
	}
}

func TestCLIEnvironmentPasswordAndParentExpiry(t *testing.T) {
	t.Setenv("FAKECA_TEST_P12_PASSWORD", "Audit-Password-123!")
	dir := t.TempDir()
	out := filepath.Join(dir, "code")
	if _, err := captureCLI(t, "generate", "--type", "jar", "--ca", "ov-cs-g3b", "--chain", "aaa", "--valid-for", "87600h", "--organization", "", "--password-env", "FAKECA_TEST_P12_PASSWORD", "--out", out); err != nil {
		t.Fatal(err)
	}
	loaded, err := lab.LoadBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Report.NotAfter.Year() != 2028 {
		t.Fatal("parent expiry not applied")
	}
	if len(loaded.Leaf.Subject.Organization) != 0 {
		t.Fatal("empty organization not preserved")
	}
	if _, err = os.Stat(filepath.Join(out, "password.txt")); !os.IsNotExist(err) {
		t.Fatal("environment password was written to disk")
	}
	if _, err = captureCLI(t, "generate", "--type", "jar", "--password-env", "FAKECA_NONEXISTENT_AUDIT_ENV", "--out", filepath.Join(dir, "must-not-exist")); err == nil {
		t.Fatal("accepted missing password environment variable")
	}
}
