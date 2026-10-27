// Package webui embeds the Vue management console and serves authenticated APIs.
package webui

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iddddg/FakeCA/internal/catalog"
	"github.com/iddddg/FakeCA/internal/lab"
)

type Artifact struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}
type Bundle struct {
	ID     string     `json:"id"`
	Path   string     `json:"path"`
	Report lab.Report `json:"report"`
	Signed []Artifact `json:"signed"`
	Logs   string     `json:"logs"`
}
type service struct {
	ID       string         `json:"id"`
	BundleID string         `json:"bundle_id"`
	Address  string         `json:"address"`
	Started  time.Time      `json:"started_at"`
	CA       string         `json:"ca"`
	Running  *lab.TLSServer `json:"-"`
	Log      *logBuffer     `json:"-"`
}
type logBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.b = append(b.b, p...)
	if len(b.b) > 65536 {
		b.b = b.b[len(b.b)-65536:]
	}
	return len(p), nil
}
func (b *logBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.b) }

type App struct {
	context    context.Context
	cancel     context.CancelFunc
	dir, token string
	entries    []catalog.Entry
	mu         sync.Mutex
	ops        sync.Mutex
	bundles    map[string]*Bundle
	services   map[string]*service
}

func New(dir string) (*App, string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, "", err
	}
	entries, err := catalog.Load()
	if err != nil {
		return nil, "", err
	}
	token, err := newID()
	if err != nil {
		return nil, "", err
	}
	a := &App{dir: abs, token: token, entries: entries, bundles: map[string]*Bundle{}, services: map[string]*service{}}
	data, err := os.ReadFile(filepath.Join(abs, "registry.json"))
	if err == nil {
		var saved []*Bundle
		if err = json.Unmarshal(data, &saved); err != nil {
			return nil, "", fmt.Errorf("读取 Web 历史记录失败：%w", err)
		}
		for i, b := range saved {
			if b == nil || b.ID == "" || b.Path == "" || !filepath.IsAbs(b.Path) {
				return nil, "", fmt.Errorf("Web 历史记录第 %d 项无效，请检查 %s", i+1, filepath.Join(abs, "registry.json"))
			}
			if _, exists := a.bundles[b.ID]; exists {
				return nil, "", fmt.Errorf("Web 历史记录包含重复证书包 ID：%s", b.ID)
			}
			a.bundles[b.ID] = b
		}
	} else if !os.IsNotExist(err) {
		return nil, "", err
	}
	a.context, a.cancel = context.WithCancel(context.Background())
	return a, token, nil
}
func newID() (string, error) {
	var b [24]byte
	_, err := rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), err
}
func (a *App) Close() {
	a.cancel()
	a.ops.Lock()
	defer a.ops.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.services {
		_ = s.Running.Stop()
	}
	a.services = map[string]*service{}
}
func (a *App) Directory() string { return a.dir }

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/bootstrap", a.bootstrap)
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("POST /api/generate", a.generate)
	mux.HandleFunc("POST /api/import", a.importBundle)
	mux.HandleFunc("POST /api/upload", a.upload)
	mux.HandleFunc("POST /api/sign", a.sign)
	mux.HandleFunc("POST /api/services", a.startService)
	mux.HandleFunc("DELETE /api/services/{id}", a.stopService)
	mux.HandleFunc("GET /api/files/{id}", a.files)
	mux.HandleFunc("GET /api/download/{id}/{name}", a.download)
	mux.HandleFunc("GET /api/archive/{id}", a.archive)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		failure(w, 404, fmt.Errorf("接口不存在或请求方法不匹配"))
	})
	assets, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if !strings.HasPrefix(r.URL.Path, "/api/") && r.Method != "GET" && r.Method != "HEAD" {
			failure(w, 405, fmt.Errorf("静态页面仅支持 GET 或 HEAD 请求"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-FakeCA-Token")), []byte(a.token)) != 1 {
				failure(w, 401, fmt.Errorf("访问令牌无效或已过期，请使用终端中本次启动的完整地址打开工作台"))
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, e := url.Parse(origin)
				if e != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
					failure(w, 403, fmt.Errorf("拒绝跨站请求，请从工作台页面发起操作"))
					return
				}
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				failure(w, 403, fmt.Errorf("拒绝跨站请求"))
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" {
				a.ops.Lock()
				defer a.ops.Unlock()
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func failure(w http.ResponseWriter, status int, err error) {
	respond(w, status, map[string]string{"error": err.Error()})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		failure(w, 400, fmt.Errorf("请求参数无效：%w", err))
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		failure(w, 400, fmt.Errorf("请求必须只包含一个 JSON 对象"))
		return false
	}
	return true
}
func (a *App) save() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	all := make([]*Bundle, 0, len(a.bundles))
	for _, b := range a.bundles {
		all = append(all, b)
	}
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(a.dir, "registry-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err = temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(a.dir, "registry.json"))
}
func (a *App) bootstrap(w http.ResponseWriter, r *http.Request) {
	type detail struct {
		catalog.Entry
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
	}
	list := make([]detail, 0, len(a.entries))
	for _, e := range a.entries {
		list = append(list, detail{e, e.Cert.NotBefore, e.Cert.NotAfter})
	}
	tools := map[string]any{}
	for _, name := range []string{"jarsigner", "osslsigncode"} {
		path, err := exec.LookPath(name)
		tools[name] = map[string]any{"available": err == nil, "path": path}
	}
	respond(w, 200, map[string]any{"entries": list, "tools": tools, "directory": a.dir, "default_valid_for": "8760h", "default_days": 365})
}
func (a *App) state(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	bundles := make([]*Bundle, 0, len(a.bundles))
	for _, b := range a.bundles {
		bundles = append(bundles, b)
	}
	sort.Slice(bundles, func(i, j int) bool {
		if bundles[i].Report.Created.Equal(bundles[j].Report.Created) {
			return bundles[i].ID < bundles[j].ID
		}
		return bundles[i].Report.Created.After(bundles[j].Report.Created)
	})
	services := make([]map[string]any, 0, len(a.services))
	for _, s := range a.services {
		services = append(services, map[string]any{"id": s.ID, "bundle_id": s.BundleID, "address": s.Address, "started_at": s.Started, "ca": s.CA, "logs": s.Log.String()})
	}
	sort.Slice(services, func(i, j int) bool { return services[i]["id"].(string) < services[j]["id"].(string) })
	respond(w, 200, map[string]any{"bundles": bundles, "services": services})
}
func (a *App) getBundle(id string) (Bundle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.bundles[id]
	if !ok {
		return Bundle{}, fmt.Errorf("证书包不存在，请刷新列表或导入已有目录")
	}
	copy := *b
	copy.Signed = append([]Artifact(nil), b.Signed...)
	return copy, nil
}
func readBundle(path string) (lab.Report, error) {
	bundle, err := lab.LoadBundle(path)
	return bundle.Report, err
}
func (a *App) register(path string, report lab.Report) (Bundle, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Bundle{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.bundles {
		if b.Path == abs || (runtime.GOOS == "windows" && strings.EqualFold(b.Path, abs)) {
			if b.Report.LeafSHA256 != report.LeafSHA256 {
				b.Signed = []Artifact{}
				b.Logs = ""
			}
			b.Report = report
			return *b, nil
		}
	}
	id, err := newID()
	if err != nil {
		return Bundle{}, err
	}
	b := &Bundle{ID: id, Path: abs, Report: report, Signed: []Artifact{}}
	a.bundles[id] = b
	return *b, nil
}
func (a *App) importBundle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Path == "" {
		failure(w, 400, fmt.Errorf("请填写已有证书包在服务器上的目录"))
		return
	}
	report, err := readBundle(req.Path)
	if err != nil {
		failure(w, 400, err)
		return
	}
	b, err := a.register(req.Path, report)
	if err == nil {
		err = a.save()
	}
	if err != nil {
		failure(w, 500, err)
		return
	}
	respond(w, 200, b)
}

type generateRequest struct {
	Type         string `json:"type"`
	Domain       string `json:"domain"`
	IP           string `json:"ip"`
	CA           string `json:"ca"`
	Chain        string `json:"chain"`
	Subject      string `json:"subject"`
	Organization string `json:"organization"`
	ValidFor     string `json:"valid_for"`
	Out          string `json:"out"`
	PasswordEnv  string `json:"password_env"`
	Input        string `json:"input"`
	Output       string `json:"output"`
	Tool         string `json:"tool"`
}

func csv(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
func envPassword(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("密码环境变量 %s 未设置或为空；请在启动 Web 服务前设置", name)
	}
	return value, nil
}
func (a *App) generate(w http.ResponseWriter, r *http.Request) {
	req := generateRequest{Type: "tls", Chain: "ecc", ValidFor: lab.DefaultValidity.String(), Subject: lab.DefaultSubject, Organization: lab.DefaultOrganization}
	if !decode(w, r, &req) {
		return
	}
	if (req.Input == "") != (req.Output == "") {
		failure(w, 400, fmt.Errorf("同时签名时，必须一起填写原始文件和输出文件"))
		return
	}
	if req.Type == "tls" && req.Input != "" {
		failure(w, 400, fmt.Errorf("TLS 类型不支持文件签名"))
		return
	}
	if req.Tool != "" && req.Input == "" {
		failure(w, 400, fmt.Errorf("签名工具路径仅用于同时签名，请一起填写原始文件和输出文件"))
		return
	}
	if req.Type == "tls" && req.PasswordEnv != "" {
		failure(w, 400, fmt.Errorf("密码环境变量仅用于软件或 JAR 的 PKCS#12 身份，TLS 类型不需要此参数"))
		return
	}
	duration, err := time.ParseDuration(req.ValidFor)
	if err != nil {
		failure(w, 400, fmt.Errorf("有效期格式无效，请使用 24h 或 8760h"))
		return
	}
	opts := lab.Options{Type: req.Type, Domains: csv(req.Domain), IPs: csv(req.IP), Subject: req.Subject, Organization: req.Organization, ValidFor: duration, Password: ""}
	if err = lab.Validate(opts); err != nil {
		failure(w, 400, err)
		return
	}
	password, err := envPassword(req.PasswordEnv)
	if err != nil {
		failure(w, 400, err)
		return
	}
	path := req.Out
	if path == "" {
		id, err := newID()
		if err != nil {
			failure(w, 500, err)
			return
		}
		path = filepath.Join(a.dir, "bundles", id)
	}
	kind := "codesign"
	if req.Type == "tls" {
		kind = "tls"
	}
	selected, err := catalog.Select(a.entries, req.CA, req.Chain, kind)
	if err != nil {
		failure(w, 400, err)
		return
	}
	opts.Out = path
	opts.Password = password
	report, err := lab.Generate(selected, opts)
	if err != nil {
		failure(w, 400, err)
		return
	}
	b, err := a.register(path, report)
	if err != nil {
		failure(w, 500, err)
		return
	}
	if err = a.save(); err != nil {
		respond(w, 500, map[string]any{"error": fmt.Sprintf("证书已生成在 %s，但保存历史索引失败：%v", b.Path, err), "bundle": b})
		return
	}
	if req.Input != "" {
		logs, err := a.signBundle(b, req.Type, req.Input, req.Output, req.Tool, password)
		if err != nil {
			b, _ = a.getBundle(b.ID)
			respond(w, 400, map[string]any{"error": err.Error(), "bundle": b, "logs": logs})
			return
		}
		b, _ = a.getBundle(b.ID)
	}
	respond(w, 200, b)
}
func (a *App) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 65<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		failure(w, 400, fmt.Errorf("上传失败，单个文件上限为 64 MiB：%w", err))
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	input, header, err := r.FormFile("file")
	if err != nil {
		failure(w, 400, fmt.Errorf("请选择要上传的原始文件"))
		return
	}
	defer input.Close()
	if header.Size > 64<<20 {
		failure(w, 400, fmt.Errorf("上传文件超过 64 MiB，请改用服务器本地路径"))
		return
	}
	id, err := newID()
	if err != nil {
		failure(w, 500, err)
		return
	}
	dir := filepath.Join(a.dir, "uploads", id)
	if err = os.MkdirAll(dir, 0700); err != nil {
		failure(w, 500, err)
		return
	}
	name := filepath.Base(strings.ReplaceAll(header.Filename, "\\", "/"))
	if name == "." || name == "/" || strings.Contains(name, ":") {
		failure(w, 400, fmt.Errorf("文件名无效"))
		return
	}
	path := filepath.Join(dir, name)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		failure(w, 500, err)
		return
	}
	_, err = io.Copy(out, input)
	closeErr := out.Close()
	if err != nil || closeErr != nil {
		failure(w, 500, fmt.Errorf("写入上传文件失败"))
		return
	}
	respond(w, 200, map[string]string{"path": path, "name": name})
}

type signRequest struct {
	Type        string `json:"type"`
	BundleID    string `json:"bundle_id"`
	Input       string `json:"input"`
	Output      string `json:"output"`
	Tool        string `json:"tool"`
	PasswordEnv string `json:"password_env"`
}

func (a *App) signBundle(b Bundle, kind, input, output, tool, password string) (string, error) {
	var logs logBuffer
	err := lab.Sign(lab.SignOptions{Type: kind, Bundle: b.Path, Input: input, Output: output, Tool: tool, Password: password, Log: &logs, Context: a.context})
	text := logs.String()
	a.mu.Lock()
	current := a.bundles[b.ID]
	current.Logs = text
	if err == nil {
		abs, _ := filepath.Abs(output)
		info, e := os.Stat(abs)
		if e == nil {
			current.Signed = append(current.Signed, Artifact{Name: filepath.Base(abs), Path: abs, Size: info.Size()})
		}
	}
	a.mu.Unlock()
	saveErr := a.save()
	if err == nil && saveErr != nil {
		err = fmt.Errorf("签名已完成，但保存索引失败：%w", saveErr)
	}
	return text, err
}
func (a *App) sign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if !decode(w, r, &req) {
		return
	}
	b, err := a.getBundle(req.BundleID)
	if err != nil {
		failure(w, 404, err)
		return
	}
	password, err := envPassword(req.PasswordEnv)
	if err != nil {
		failure(w, 400, err)
		return
	}
	logs, err := a.signBundle(b, req.Type, req.Input, req.Output, req.Tool, password)
	if err != nil {
		respond(w, 400, map[string]any{"error": err.Error(), "logs": logs})
		return
	}
	b, _ = a.getBundle(b.ID)
	respond(w, 200, map[string]any{"bundle": b, "logs": logs})
}

func (a *App) startService(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BundleID string `json:"bundle_id"`
		Listen   string `json:"listen"`
	}
	if !decode(w, r, &req) {
		return
	}
	b, err := a.getBundle(req.BundleID)
	if err != nil {
		failure(w, 404, err)
		return
	}
	if req.Listen == "" {
		req.Listen = "127.0.0.1:8443"
	}
	log := &logBuffer{}
	running, err := lab.StartTLS(b.Path, req.Listen, log)
	if err != nil {
		failure(w, 400, err)
		return
	}
	id, err := newID()
	if err != nil {
		_ = running.Stop()
		failure(w, 500, err)
		return
	}
	s := &service{ID: id, BundleID: b.ID, Address: running.Address, Started: time.Now().UTC(), CA: running.Report.CA.ID, Running: running, Log: log}
	a.mu.Lock()
	a.services[id] = s
	a.mu.Unlock()
	go func() {
		err := <-running.Done
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(log, "服务异常停止：%v", err)
		}
		a.mu.Lock()
		delete(a.services, id)
		a.mu.Unlock()
	}()
	respond(w, 200, s)
}
func (a *App) stopService(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	s, ok := a.services[r.PathValue("id")]
	a.mu.Unlock()
	if !ok {
		failure(w, 404, fmt.Errorf("测试服务不存在或已停止"))
		return
	}
	if err := s.Running.Stop(); err != nil {
		failure(w, 500, err)
		return
	}
	a.mu.Lock()
	delete(a.services, s.ID)
	a.mu.Unlock()
	respond(w, 200, map[string]bool{"stopped": true})
}

func artifactList(b Bundle) ([]Artifact, error) {
	files, err := lab.BundleFilesForVersion(b.Report.Version)
	if err != nil {
		return nil, err
	}
	out := []Artifact{}
	for _, name := range files.Names() {
		path := filepath.Join(b.Path, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			out = append(out, Artifact{Name: name, Path: path, Size: info.Size()})
		}
	}
	for i, s := range b.Signed {
		s.Name = fmt.Sprintf("signed-%d-%s", i, filepath.Base(strings.ReplaceAll(s.Name, "\\", "/")))
		out = append(out, s)
	}
	return out, nil
}
func (a *App) files(w http.ResponseWriter, r *http.Request) {
	b, err := a.getBundle(r.PathValue("id"))
	if err != nil {
		failure(w, 404, err)
		return
	}
	list, err := artifactList(b)
	if err != nil {
		failure(w, 400, err)
		return
	}
	respond(w, 200, list)
}
func (a *App) download(w http.ResponseWriter, r *http.Request) {
	b, err := a.getBundle(r.PathValue("id"))
	if err != nil {
		failure(w, 404, err)
		return
	}
	list, err := artifactList(b)
	if err != nil {
		failure(w, 400, err)
		return
	}
	for _, file := range list {
		if file.Name == r.PathValue("name") {
			downloadFile(w, r, file)
			return
		}
	}
	failure(w, 404, fmt.Errorf("文件不存在或不属于该证书包"))
}
func downloadFile(w http.ResponseWriter, r *http.Request, file Artifact) {
	input, err := os.Open(file.Path)
	if err != nil {
		failure(w, 404, err)
		return
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		failure(w, 500, err)
		return
	}
	if !info.Mode().IsRegular() {
		failure(w, 400, fmt.Errorf("下载目标不是普通文件"))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", url.PathEscape(file.Name)))
	http.ServeContent(w, r, file.Name, info.ModTime(), input)
}
func (a *App) archive(w http.ResponseWriter, r *http.Request) {
	b, err := a.getBundle(r.PathValue("id"))
	if err != nil {
		failure(w, 404, err)
		return
	}
	list, err := artifactList(b)
	if err != nil {
		failure(w, 400, err)
		return
	}
	temp, err := os.CreateTemp(a.dir, "download-*.zip")
	if err != nil {
		failure(w, 500, err)
		return
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	z := zip.NewWriter(temp)
	for _, file := range list {
		input, e := os.Open(file.Path)
		if e != nil {
			z.Close()
			failure(w, 500, e)
			return
		}
		entry, e := z.Create(file.Name)
		if e == nil {
			_, e = io.Copy(entry, input)
		}
		input.Close()
		if e != nil {
			z.Close()
			failure(w, 500, e)
			return
		}
	}
	if err = z.Close(); err != nil {
		failure(w, 500, err)
		return
	}
	if _, err = temp.Seek(0, io.SeekStart); err != nil {
		failure(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"fakeca-bundle.zip\"")
	http.ServeContent(w, r, "fakeca-bundle.zip", time.Now(), temp)
}

// Keep compile-time coverage that logBuffer implements io.Writer.
var _ io.Writer = (*logBuffer)(nil)
