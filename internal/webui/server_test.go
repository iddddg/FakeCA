package webui

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func request(t *testing.T, app *App, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	req.Header.Set("X-FakeCA-Token", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	out := httptest.NewRecorder()
	app.Handler().ServeHTTP(out, req)
	return out
}
func setup(t *testing.T) (*App, string, string) {
	t.Helper()
	dir := t.TempDir()
	app, token, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	return app, token, dir
}
func parseBundle(t *testing.T, r *httptest.ResponseRecorder) Bundle {
	t.Helper()
	if r.Code != 200 {
		t.Fatalf("request failed %d: %s", r.Code, r.Body)
	}
	var b Bundle
	if err := json.Unmarshal(r.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAuthenticationAndStaticAssets(t *testing.T) {
	app, token, _ := setup(t)
	if r := request(t, app, "", "GET", "/api/bootstrap", nil); r.Code != 401 {
		t.Fatal("API accepted missing token")
	}
	r := httptest.NewRequest("POST", "/api/generate", strings.NewReader(`{}`))
	r.Header.Set("X-FakeCA-Token", token)
	r.Header.Set("Origin", "https://other.example")
	out := httptest.NewRecorder()
	app.Handler().ServeHTTP(out, r)
	if out.Code != 403 {
		t.Fatal("API accepted foreign origin")
	}
	r = httptest.NewRequest("GET", "/api/bootstrap", nil)
	r.Header.Set("X-FakeCA-Token", token)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	out = httptest.NewRecorder()
	app.Handler().ServeHTTP(out, r)
	if out.Code != 403 {
		t.Fatal("API accepted cross-site request")
	}
	out = request(t, app, token, "GET", "/api/bootstrap", nil)
	if out.Code != 200 {
		t.Fatal(out.Body)
	}
	var data struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &data); err != nil || len(data.Entries) != 24 {
		t.Fatal("CA catalog incomplete")
	}
	out = request(t, app, "", "GET", "/", nil)
	if out.Code != 200 || !strings.Contains(out.Body.String(), "信任验证工作台") {
		t.Fatal("built UI unavailable")
	}
	if !strings.Contains(out.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("missing UI policy")
	}
}

func TestWebBundleLifecycle(t *testing.T) {
	app, token, dir := setup(t)
	invalid := request(t, app, token, "POST", "/api/generate", map[string]string{"type": "tls", "domain": "https://bad.example"})
	if invalid.Code != 400 {
		t.Fatal("accepted invalid domain")
	}
	b := parseBundle(t, request(t, app, token, "POST", "/api/generate", map[string]string{"type": "tls", "domain": "*.demo.com,demo.com", "ip": "127.0.0.1", "ca": "dv-tls-g3b", "chain": "aaa"}))
	if b.Report.NotAfter.Sub(b.Report.Created) != 365*24*time.Hour {
		t.Fatal("default duration changed")
	}
	if b.Report.CA.ID != "dv-tls-g3b" || len(b.Report.Domains) != 2 {
		t.Fatal("generation parameters lost")
	}
	r := request(t, app, token, "GET", "/api/files/"+b.ID, nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), "leaf.key") {
		t.Fatal("files missing")
	}
	r = request(t, app, token, "GET", "/api/download/"+b.ID+"/leaf.pem", nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("certificate download failed")
	}
	r = request(t, app, token, "GET", "/api/download/"+b.ID+"/registry.json", nil)
	if r.Code != 404 {
		t.Fatal("download escaped bundle file list")
	}
	r = request(t, app, token, "GET", "/api/archive/"+b.ID, nil)
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	z, err := zip.NewReader(bytes.NewReader(r.Body.Bytes()), int64(r.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) < 7 {
		t.Fatal("archive incomplete")
	}
	imported := parseBundle(t, request(t, app, token, "POST", "/api/import", map[string]string{"path": b.Path}))
	if imported.ID != b.ID {
		t.Fatal("duplicate import created another bundle")
	}
	restored, newToken, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if newToken == token {
		t.Fatal("session token did not rotate")
	}
	if _, err = restored.getBundle(b.ID); err != nil {
		t.Fatal("history not restored")
	}
}

func TestTLSServiceControls(t *testing.T) {
	app, token, _ := setup(t)
	b := parseBundle(t, request(t, app, token, "POST", "/api/generate", map[string]string{"type": "tls", "ip": "127.0.0.1", "chain": "native", "ca": "ov-tls-g3c"}))
	r := request(t, app, token, "POST", "/api/services", map[string]string{"bundle_id": b.ID, "listen": "127.0.0.1:0"})
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	var s service
	if err := json.Unmarshal(r.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	// This checks transport and lifecycle ONLY; no claim about client trust.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://" + s.Address)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !strings.Contains(string(body), "证书信任负向测试") {
		t.Fatal("unexpected test endpoint")
	}
	r = request(t, app, token, "DELETE", "/api/services/"+s.ID, nil)
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	r = request(t, app, token, "GET", "/api/state", nil)
	var state struct {
		Services []any `json:"services"`
	}
	if err = json.Unmarshal(r.Body.Bytes(), &state); err != nil || len(state.Services) != 0 {
		t.Fatal("service did not stop")
	}
}

func TestUploadAndJARSign(t *testing.T) {
	app, token, _ := setup(t)
	var jar bytes.Buffer
	z := zip.NewWriter(&jar)
	entry, err := z.Create("test.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("Harmless trust-verification fixture"))
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	var form bytes.Buffer
	writer := multipart.NewWriter(&form)
	part, err := writer.CreateFormFile("file", "test.jar")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(jar.Bytes())
	writer.Close()
	req := httptest.NewRequest("POST", "/api/upload", &form)
	req.Header.Set("X-FakeCA-Token", token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	r := httptest.NewRecorder()
	app.Handler().ServeHTTP(r, req)
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	var uploaded struct {
		Path string `json:"path"`
	}
	if err = json.Unmarshal(r.Body.Bytes(), &uploaded); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(uploaded.Path); err != nil {
		t.Fatal(err)
	}
	tool := os.Getenv("FAKECA_JARSIGNER")
	if tool == "" {
		t.Log("external JAR API integration skipped: set FAKECA_JARSIGNER")
		return
	}
	b := parseBundle(t, request(t, app, token, "POST", "/api/generate", map[string]string{"type": "jar", "chain": "aaa", "ca": "ov-cs-g3b"}))
	output := filepath.Join(t.TempDir(), "signed.jar")
	r = request(t, app, token, "POST", "/api/sign", map[string]string{"type": "jar", "bundle_id": b.ID, "input": uploaded.Path, "output": output, "tool": tool})
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	saved, err := app.getBundle(b.ID)
	if err != nil || len(saved.Signed) != 1 || !strings.Contains(saved.Logs, "文件签名已完成") {
		t.Fatal("signed artifact not registered")
	}
	r = request(t, app, token, "GET", "/api/download/"+b.ID+"/signed-0-signed.jar", nil)
	if r.Code != 200 {
		t.Fatal("signed artifact download failed")
	}
}

func TestExplicitEmptyParametersAndCorruptHistory(t *testing.T) {
	app, token, dir := setup(t)
	for _, field := range []string{"type", "chain", "subject", "valid_for"} {
		params := map[string]string{"type": "tls", "domain": "test.invalid"}
		params[field] = ""
		r := request(t, app, token, "POST", "/api/generate", params)
		if r.Code != 400 {
			t.Fatalf("accepted explicit empty %s: %s", field, r.Body)
		}
	}
	r := request(t, app, token, "POST", "/api/import", map[string]string{"path": t.TempDir()})
	if r.Code != 400 {
		t.Fatal("imported missing bundle")
	}
	if err := os.WriteFile(filepath.Join(dir, "registry.json"), []byte("[null]"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(dir); err == nil {
		t.Fatal("accepted corrupt registry")
	}
}

func TestTamperedImportRejected(t *testing.T) {
	app, token, _ := setup(t)
	b := parseBundle(t, request(t, app, token, "POST", "/api/generate", map[string]string{"type": "tls", "domain": "test.invalid"}))
	if err := os.WriteFile(filepath.Join(b.Path, "leaf.pem"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	r := request(t, app, token, "POST", "/api/import", map[string]string{"path": b.Path})
	if r.Code != 400 {
		t.Fatal("import accepted corrupt certificate")
	}
	r = request(t, app, token, "POST", "/api/services", map[string]string{"bundle_id": b.ID, "listen": "127.0.0.1:0"})
	if r.Code != 400 {
		t.Fatal("service accepted corrupt certificate")
	}
}
