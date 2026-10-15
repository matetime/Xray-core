package all

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/main/commands/base"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/curve25519"
)

var cmdWebUI = &base.Command{
	UsageLine: "{{.Exec}} webui [-listen 0.0.0.0:8080] [-token password] [-domain auto]",
	Short:     "Start compact HTTPS Web UI for VLESS + (RAW / XHTTP / gRPC) + REALITY",
	Long: `
Start an embedded HTTPS Web UI with automatic Let's Encrypt SSL certificate.

Arguments:
	-listen <addr:port> : Address and port for the Web UI (default: 0.0.0.0:8080)
	-token <string>     : Password for Web UI login (default: admin)
	-domain <string>    : Domain for Let's Encrypt SSL (default: auto via sslip.io)
	-state <file>       : Path to state file (default: webui_state.json)
`,
}

var (
	uiListen  string
	uiToken   string
	uiDomain  string
	stateFile string

	instanceMu   sync.Mutex
	xrayInstance *core.Instance
	currentState NodeState
)

type NodeState struct {
	Remark        string `json:"remark"`
	Protocol      string `json:"protocol"`
	ServerHost    string `json:"serverHost"`
	Port          int    `json:"port"`
	SNI           string `json:"sni"`
	Fingerprint   string `json:"fingerprint"`
	Flow          string `json:"flow"`
	TransportMode string `json:"transportMode"`
	TransportPath string `json:"transportPath"`
	UUID          string `json:"uuid"`
	PrivateKey    string `json:"privateKey"`
	PublicKey     string `json:"publicKey"`
	ShortID       string `json:"shortId"`
	Running       bool   `json:"running"`
	ShareLink     string `json:"shareLink"`
	CoreVersion   string `json:"coreVersion"`
}

func init() {
	cmdWebUI.Run = executeWebUI
	_ = cmdWebUI.Flag.String("listen", "0.0.0.0:8080", "Web UI listen address")
	_ = cmdWebUI.Flag.String("token", "admin", "Password for Web UI login")
	_ = cmdWebUI.Flag.String("domain", "", "Custom domain for Let's Encrypt (empty = auto sslip.io)")
	_ = cmdWebUI.Flag.String("state", "webui_state.json", "State file path")

	base.RootCommand.Commands = append(base.RootCommand.Commands, cmdWebUI)
}

func executeWebUI(cmd *base.Command, args []string) {
	cmd.Flag.Parse(args)
	uiListen = cmd.Flag.Lookup("listen").Value.String()
	uiToken = cmd.Flag.Lookup("token").Value.String()
	uiDomain = cmd.Flag.Lookup("domain").Value.String()
	stateFile = cmd.Flag.Lookup("state").Value.String()

	initDefaultState()

	outIP := detectOutboundIP()
	if uiDomain == "" && outIP != "127.0.0.1" {
		uiDomain = strings.ReplaceAll(outIP, ".", "-") + ".sslip.io"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/state", authMiddleware(handleState))
	mux.HandleFunc("/api/apply", authMiddleware(handleApply))
	mux.HandleFunc("/api/rekey", authMiddleware(handleRekey))
	mux.HandleFunc("/api/update/check", authMiddleware(handleUpdateCheck))
	mux.HandleFunc("/api/update/run", authMiddleware(handleUpdateRun))

	if currentState.ServerHost != "" {
		if err := restartXrayInstance(); err != nil {
			log.Printf("[Xray-WebUI] Autostart deferred: %v", err)
		}
	}

	_, portStr, err := net.SplitHostPort(uiListen)
	if err != nil {
		portStr = "8080"
	}

	log.Printf("[Xray-WebUI] Trusted HTTPS URL: https://%s:%s", uiDomain, portStr)

	go func() {
		if err := serveAutoHTTPS(uiListen, uiDomain, portStr, mux); err != nil {
			log.Fatalf("[Xray-WebUI] Server error: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	instanceMu.Lock()
	if xrayInstance != nil {
		xrayInstance.Close()
	}
	instanceMu.Unlock()
}

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
}

func (l *chanListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}
func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

func serveAutoHTTPS(addr, autoDomain, portStr string, handler http.Handler) error {
	fallbackCert, _ := generateSelfSignedCert(currentState.ServerHost)

	certManager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("webui_certs"),
		HostPolicy: func(ctx context.Context, host string) error {
			return nil
		},
	}

	// Port 80 listener for automatic Let's Encrypt HTTP-01 verification & redirect
	go func() {
		httpRedir := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHost := autoDomain
			if targetHost == "" {
				targetHost = r.Host
			}
			http.Redirect(w, r, "https://"+targetHost+":"+portStr+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
		_ = http.ListenAndServe(":80", certManager.HTTPHandler(httpRedir))
	}()

	baseLn, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	tlsLnChan := &chanListener{addr: baseLn.Addr(), ch: make(chan net.Conn, 128)}
	httpLnChan := &chanListener{addr: baseLn.Addr(), ch: make(chan net.Conn, 128)}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && net.ParseIP(hello.ServerName) == nil {
				if cert, err := certManager.GetCertificate(hello); err == nil {
					return cert, nil
				}
			}
			return &fallbackCert, nil
		},
	}
	tlsListener := tls.NewListener(tlsLnChan, tlsConfig)

	go http.Serve(tlsListener, handler)
	go http.Serve(httpLnChan, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHost := r.Host
		hostOnly, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			hostOnly = r.Host
		}
		// Redirect raw IP to sslip.io domain so browser gets a trusted Let's Encrypt certificate
		if net.ParseIP(hostOnly) != nil && autoDomain != "" {
			targetHost = autoDomain + ":" + portStr
		}
		http.Redirect(w, r, "https://"+targetHost+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))

	for {
		conn, err := baseLn.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			br := bufio.NewReader(c)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			b, err := br.Peek(1)
			_ = c.SetReadDeadline(time.Time{})
			if err != nil {
				c.Close()
				return
			}
			pc := &peekConn{Conn: c, r: br}
			if b[0] == 0x16 {
				tlsLnChan.ch <- pc
			} else {
				httpLnChan.ch <- pc
			}
		}(conn)
	}
}

func generateSelfSignedCert(hostIP string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if parsed := net.ParseIP(hostIP); parsed != nil {
		ips = append(ips, parsed)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(202603),
		Subject:      pkix.Name{CommonName: hostIP},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func isTokenValid(provided string) bool {
	if uiToken == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(uiToken)) == 1
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			if c, err := r.Cookie("xray_auth"); err == nil {
				token = c.Value
			}
		}
		if !isTokenValid(token) {
			http.Error(w, "Unauthorized: invalid password", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if !isTokenValid(req.Password) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "xray_auth",
		Value:    req.Password,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400 * 30,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func initDefaultState() {
	if data, err := os.ReadFile(stateFile); err == nil {
		if json.Unmarshal(data, &currentState) == nil && currentState.PrivateKey != "" {
			currentState.CoreVersion = core.Version()
			sanitizeProtocolState(&currentState)
			currentState.ShareLink = buildShareLink(currentState)
			return
		}
	}

	uuid, priv, pub, sid := generateCredentials()
	currentState = NodeState{
		Remark:      "Xray-RAW-Reality",
		Protocol:    "raw",
		ServerHost:  detectOutboundIP(),
		Port:        443,
		SNI:         "www.microsoft.com",
		Fingerprint: "chrome",
		Flow:        "xtls-rprx-vision",
		UUID:        uuid,
		PrivateKey:  priv,
		PublicKey:   pub,
		ShortID:     sid,
		CoreVersion: core.Version(),
	}
	currentState.ShareLink = buildShareLink(currentState)
}

func sanitizeProtocolState(s *NodeState) {
	if s.Fingerprint == "" {
		s.Fingerprint = "chrome"
	}
	switch s.Protocol {
	case "raw":
		if s.Flow != "xtls-rprx-vision" && s.Flow != "xtls-rprx-vision-udp443" {
			s.Flow = "xtls-rprx-vision"
		}
		s.TransportMode = ""
		s.TransportPath = ""
	case "xhttp":
		s.Flow = ""
		switch s.TransportMode {
		case "auto", "packet-up", "stream-up", "stream-one":
		default:
			s.TransportMode = "auto"
		}
		if s.TransportPath == "" || !strings.HasPrefix(s.TransportPath, "/") {
			s.TransportPath = "/xhttp"
		}
	case "grpc":
		s.Flow = ""
		if s.TransportMode != "gun" && s.TransportMode != "multi" {
			s.TransportMode = "gun"
		}
		if s.TransportPath == "" || strings.HasPrefix(s.TransportPath, "/") {
			s.TransportPath = "grpc_service"
		}
	default:
		s.Protocol = "raw"
		s.Flow = "xtls-rprx-vision"
		s.TransportMode = ""
		s.TransportPath = ""
	}
}

func generateCredentials() (uuid, privKey, pubKey, shortID string) {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	uuid = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])

	var scalar [32]byte
	rand.Read(scalar[:])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	pub, _ := curve25519.X25519(scalar[:], curve25519.Basepoint)
	privKey = base64.RawURLEncoding.EncodeToString(scalar[:])
	pubKey = base64.RawURLEncoding.EncodeToString(pub)

	sidBytes := make([]byte, 4)
	rand.Read(sidBytes)
	shortID = hex.EncodeToString(sidBytes)
	return
}

func detectOutboundIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func buildShareLink(s NodeState) string {
	fp := s.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", s.SNI)
	q.Set("fp", fp)
	q.Set("pbk", s.PublicKey)
	q.Set("sid", s.ShortID)

	switch s.Protocol {
	case "raw":
		q.Set("type", "tcp")
		q.Set("flow", s.Flow)
	case "xhttp":
		q.Set("type", "xhttp")
		q.Set("path", s.TransportPath)
		q.Set("mode", s.TransportMode)
	case "grpc":
		q.Set("type", "grpc")
		q.Set("serviceName", s.TransportPath)
		q.Set("mode", s.TransportMode)
	}

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		s.UUID, s.ServerHost, s.Port, q.Encode(), url.PathEscape(s.Remark))
}

func buildXrayJSON(s NodeState) ([]byte, error) {
	client := map[string]any{"id": s.UUID}
	if s.Protocol == "raw" && s.Flow != "" {
		client["flow"] = s.Flow
	}

	streamSettings := map[string]any{
		"network":  s.Protocol,
		"security": "reality",
		"realitySettings": map[string]any{
			"show":        false,
			"dest":        fmt.Sprintf("%s:443", s.SNI),
			"xver":        0,
			"serverNames": []string{s.SNI},
			"privateKey":  s.PrivateKey,
			"shortIds":    []string{s.ShortID},
		},
	}

	switch s.Protocol {
	case "raw":
		streamSettings["rawSettings"] = map[string]any{}
	case "xhttp":
		streamSettings["xhttpSettings"] = map[string]any{
			"path": s.TransportPath,
			"mode": s.TransportMode,
		}
	case "grpc":
		streamSettings["grpcSettings"] = map[string]any{
			"serviceName": s.TransportPath,
			"multiMode":   s.TransportMode == "multi",
		}
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"listen":   "0.0.0.0",
				"port":     s.Port,
				"protocol": "vless",
				"settings": map[string]any{
					"clients":    []any{client},
					"decryption": "none",
				},
				"streamSettings": streamSettings,
			},
		},
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct"},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func restartXrayInstance() error {
	instanceMu.Lock()
	defer instanceMu.Unlock()

	sanitizeProtocolState(&currentState)
	rawJSON, err := buildXrayJSON(currentState)
	if err != nil {
		return err
	}

	pbConfig, err := serial.LoadJSONConfig(bytes.NewReader(rawJSON))
	if err != nil {
		return err
	}

	if xrayInstance != nil {
		xrayInstance.Close()
		xrayInstance = nil
		currentState.Running = false
	}

	inst, err := core.New(pbConfig)
	if err != nil {
		return err
	}
	if err := inst.Start(); err != nil {
		return err
	}

	xrayInstance = inst
	currentState.Running = true
	currentState.CoreVersion = core.Version()
	currentState.ShareLink = buildShareLink(currentState)

	if data, err := json.MarshalIndent(currentState, "", "  "); err == nil {
		_ = os.WriteFile(stateFile, data, 0600)
	}
	return nil
}

func handleState(w http.ResponseWriter, r *http.Request) {
	instanceMu.Lock()
	defer instanceMu.Unlock()
	currentState.CoreVersion = core.Version()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(currentState)
}

func handleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req NodeState
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	instanceMu.Lock()
	currentState.Remark = req.Remark
	currentState.Protocol = req.Protocol
	currentState.ServerHost = req.ServerHost
	currentState.Port = req.Port
	currentState.SNI = req.SNI
	currentState.Fingerprint = req.Fingerprint
	currentState.Flow = req.Flow
	currentState.TransportMode = req.TransportMode
	currentState.TransportPath = req.TransportPath
	instanceMu.Unlock()

	if err := restartXrayInstance(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handleState(w, r)
}

func handleRekey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	uuid, priv, pub, sid := generateCredentials()
	instanceMu.Lock()
	currentState.UUID = uuid
	currentState.PrivateKey = priv
	currentState.PublicKey = pub
	currentState.ShortID = sid
	instanceMu.Unlock()

	if err := restartXrayInstance(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handleState(w, r)
}

func handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=15", nil)
	req.Header.Set("User-Agent", "Xray-WebUI-Updater")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "GitHub API connection failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var releases []struct {
		TagName    string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil || len(releases) == 0 {
		http.Error(w, "Failed to parse releases list", http.StatusInternalServerError)
		return
	}

	targetTag := releases[0].TagName
	for _, rel := range releases {
		if rel.Prerelease {
			targetTag = rel.TagName
			break
		}
	}

	cur := "v" + strings.TrimPrefix(core.Version(), "v")
	latest := "v" + strings.TrimPrefix(targetTag, "v")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"current":   cur,
		"latest":    latest,
		"hasUpdate": latest != "" && cur != latest,
	})
}

func handleUpdateRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Tag string `json:"tag"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	if out, err := exec.Command("git", "fetch", "--all", "--tags").CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("git fetch failed: %v (%s)", err, string(out)), http.StatusInternalServerError)
		return
	}

	if body.Tag != "" {
		if out, err := exec.Command("git", "checkout", body.Tag).CombinedOutput(); err != nil {
			http.Error(w, fmt.Sprintf("git checkout %s failed: %v (%s)", body.Tag, err, string(out)), http.StatusInternalServerError)
			return
		}
	}

	exePath, err := os.Executable()
	if err != nil {
		exePath = "./xray"
	}

	buildCmd := exec.Command("go", "build", "-o", exePath+".new", "-trimpath", "-ldflags", "-s -w", "./main")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("go build failed: %v (%s)", err, string(out)), http.StatusInternalServerError)
		return
	}

	if err := os.Rename(exePath+".new", exePath); err != nil {
		http.Error(w, "Binary replacement failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "updated",
		"message": fmt.Sprintf("Successfully rebuilt Xray Core (%s)! Restart service to apply.", body.Tag),
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Xray Reality Core — Web UI</title>
<style>
  :root {
    --navy-header: #0b1f32;
    --navy-dark: #061320;
    --core-pill-bg: #0d2236;
    --core-pill-border: rgba(56, 189, 248, 0.28);
    --royal-blue: #2e6ff2;
    --royal-hover: #1e5dd9;
    --card-white: #ffffff;
    --surface-gray: #edf0f6;
    --surface-border: #dfe5ef;
    --text-dark: #121f38;
    --text-muted: #7b88a1;
    --amber-star: #f5a623;
    --green-ok: #10b981;
    --red-err: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Inter", "Segoe UI", sans-serif;
    background-color: var(--card-white);
    color: var(--text-dark);
    height: 100dvh;
    overflow: hidden;
    display: flex;
    justify-content: center;
    align-items: flex-start;
  }
  .screen-inner {
    width: 100%;
    max-width: 460px;
    background: var(--card-white);
    height: 100dvh;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  /* Compact Honeycomb Mesh Header with X Logo */
  .navy-banner {
    position: relative;
    background-color: #081826;
    background-image:
      url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='56' height='98' viewBox='0 0 56 98'%3E%3Cg fill='none' stroke='%231d4968' stroke-width='1.3' stroke-opacity='0.55'%3E%3Cpath d='M28 66L0 50L0 16L28 0L56 16L56 50L28 66L28 100'/%3E%3Cpath d='M0 98L28 82L56 98'/%3E%3Cpath d='M28 0v-16'/%3E%3C/g%3E%3C/svg%3E"),
      radial-gradient(circle at 22% 45%, #154566 0%, #091d2e 55%, #05101a 100%);
    background-size: 42px 72px, 100% 100%;
    color: #ffffff;
    padding: 11px 16px 11px;
    border-bottom: 1px solid #163852;
    flex-shrink: 0;
  }
  .banner-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }
  .x-logo-wrap {
    display: flex;
    align-items: center;
  }
  .x-logo-svg {
    width: 66px;
    height: 36px;
    filter: drop-shadow(0 2px 8px rgba(56, 189, 248, 0.35));
  }
  .header-right {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: var(--core-pill-bg);
    border: 1px solid var(--core-pill-border);
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    color: #ffffff;
  }
  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--green-ok);
    box-shadow: 0 0 7px var(--green-ok);
  }
  .btn-lock {
    appearance: none;
    border: 1px solid rgba(255, 255, 255, 0.22);
    background: var(--core-pill-bg);
    color: #ffffff;
    font-size: 10.5px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 999px;
    cursor: pointer;
  }

  /* Core Version Bar */
  .banner-controls {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--core-pill-bg);
    border: 1px solid var(--core-pill-border);
    border-radius: 999px;
    padding: 4px 5px 4px 14px;
  }
  .core-ver { font-size: 12px; color: rgba(255, 255, 255, 0.9); }
  .core-ver b { color: #ffffff; font-family: ui-monospace, SFMono-Regular, monospace; font-weight: 700; }
  .hint-tag { color: var(--amber-star); font-weight: 600; margin-left: 4px; }
  .btn-pill-update {
    appearance: none;
    border: none;
    background: var(--royal-blue);
    color: #ffffff;
    font-size: 11.5px;
    font-weight: 600;
    padding: 6px 14px;
    border-radius: 999px;
    cursor: pointer;
    box-shadow: 0 3px 10px rgba(46, 111, 242, 0.35);
  }
  .btn-pill-update.ready-upgrade {
    background: var(--amber-star);
    color: #112854;
  }

  /* Compact Content Body for iPhone Air Single Screen */
  .content-body {
    padding: 10px 16px 12px;
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .section-heading {
    display: flex;
    justify-content: center;
    align-items: center;
    font-size: 14px;
    font-weight: 700;
    color: var(--text-dark);
    margin-bottom: 6px;
    text-align: center;
  }

  .grid { display: grid; gap: 7px; }
  .row-2 { display: grid; grid-template-columns: 2fr 1fr; gap: 8px; }
  .row-equal { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  label {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 10.5px;
    color: var(--text-muted);
    margin-bottom: 3px;
    font-weight: 600;
    padding: 0 2px;
  }
  .lock-tag {
    font-size: 8.5px;
    color: #64748b;
    background: #e2e8f0;
    padding: 1px 6px;
    border-radius: 999px;
    letter-spacing: 0.04em;
    display: none;
    font-weight: 700;
  }
  .lock-tag.visible { display: inline-block; }

  .proto-tabs {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 6px;
    background: var(--surface-gray);
    padding: 4px;
    border-radius: 13px;
  }
  .proto-tab {
    appearance: none;
    background: transparent;
    border: none;
    color: var(--text-muted);
    padding: 6px 0;
    font-size: 12px;
    font-weight: 700;
    border-radius: 10px;
    cursor: pointer;
    user-select: none;
  }
  .proto-tab.active {
    background: var(--royal-blue);
    color: #ffffff;
    box-shadow: 0 3px 10px rgba(46, 111, 242, 0.3);
  }

  .select-wrap {
    position: relative;
    width: 100%;
  }
  .select-wrap::after {
    content: "▾";
    position: absolute;
    right: 11px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 11px;
    color: #7b88a1;
    pointer-events: none;
  }

  input, select {
    -webkit-appearance: none;
    appearance: none;
    width: 100%;
    height: 35px;
    background: var(--surface-gray);
    border: 1.5px solid transparent;
    color: var(--text-dark);
    padding: 0 11px;
    border-radius: 11px;
    font-size: 12.5px;
    font-weight: 600;
    outline: none;
  }
  select {
    padding-right: 26px;
  }
  input:focus, select:focus {
    background: #ffffff;
    border-color: var(--royal-blue);
  }

  /* Identical Locked ("Cemented") Styling for both <input> and <select> */
  input:disabled, select:disabled {
    -webkit-appearance: none !important;
    appearance: none !important;
    opacity: 1 !important;
    -webkit-text-fill-color: #8b99af !important;
    color: #8b99af !important;
    background: repeating-linear-gradient(
      -45deg,
      #e2e8f2,
      #e2e8f2 6px,
      #d8e0ed 6px,
      #d8e0ed 12px
    ) !important;
    border: 1.5px solid #cfd8e6 !important;
    cursor: not-allowed;
  }

  /* 1. New Keys button width matches Port section (2fr 1fr grid) */
  .actions {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 8px;
    margin-top: 8px;
  }
  button.main-btn {
    cursor: pointer;
    border: none;
    border-radius: 999px;
    height: 37px;
    padding: 0 12px;
    font-size: 12.5px;
    font-weight: 700;
    width: 100%;
  }
  .btn-primary {
    background: var(--royal-blue);
    color: #ffffff;
    box-shadow: 0 4px 12px rgba(46, 111, 242, 0.28);
  }
  .btn-secondary {
    background: var(--surface-gray);
    color: var(--navy-header);
  }

  /* Compact Share Link Box */
  .link-card {
    margin-top: 8px;
    background: var(--surface-gray);
    border-radius: 16px;
    padding: 9px 11px;
  }
  .uri-field {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 10.5px;
    word-break: break-all;
    background: #ffffff;
    padding: 7px 9px;
    border-radius: 10px;
    color: var(--navy-header);
    margin: 4px 0 7px;
    height: 48px;
    overflow-y: auto;
    line-height: 1.35;
    border: 1px solid var(--surface-border);
  }
  /* 2. Copy Share Link button matches Core v26.10.10 capsule color */
  .btn-copy {
    width: 100%;
    height: 35px;
    background: var(--core-pill-bg);
    border: 1px solid var(--core-pill-border);
    color: #ffffff;
  }
  .status-msg {
    font-size: 10.5px;
    color: var(--royal-blue);
    margin-top: 4px;
    min-height: 13px;
    text-align: center;
    font-weight: 600;
  }

  /* Centered Login Screen */
  #loginView {
    flex: 1;
    height: 100dvh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 24px 22px;
  }
  .login-box {
    background: var(--surface-gray);
    border-radius: 22px;
    padding: 24px 18px 20px;
    text-align: center;
  }
  .login-title {
    font-size: 16px;
    font-weight: 700;
    color: var(--text-dark);
    margin-bottom: 5px;
  }
  .login-sub {
    font-size: 12px;
    color: var(--text-muted);
    margin-bottom: 16px;
    font-weight: 500;
  }
  #loginPass {
    background: #ffffff;
    text-align: center;
    margin-bottom: 10px;
    border: 1.5px solid var(--surface-border);
  }
  .login-err {
    font-size: 11.5px;
    color: var(--red-err);
    margin-top: 8px;
    min-height: 15px;
    font-weight: 600;
  }
  .hidden { display: none !important; }
</style>
</head>
<body>
  <div class="screen-inner">
    <!-- Centered Password Login Screen -->
    <div id="loginView">
      <div class="login-box">
        <div class="login-title">Panel Login</div>
        <div class="login-sub">Enter your panel password to unlock</div>
        <input id="loginPass" type="password" placeholder="Password" autocomplete="current-password">
        <button type="button" class="main-btn btn-primary" id="loginBtn">Unlock Panel</button>
        <div class="login-err" id="loginErr"></div>
      </div>
    </div>

    <!-- Top Honeycomb Banner with Cybernetic X Logo -->
    <div class="navy-banner hidden" id="topBanner">
      <div class="banner-top">
        <div class="x-logo-wrap" title="Xray Core">
          <svg class="x-logo-svg" viewBox="0 0 150 84" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="xMetal" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#ffffff"/>
                <stop offset="50%" stop-color="#d8e3ec"/>
                <stop offset="100%" stop-color="#94a8b8"/>
              </linearGradient>
            </defs>
            <g stroke="#7dd3fc" stroke-width="1" stroke-opacity="0.65">
              <line x1="12" y1="24" x2="138" y2="24"/>
              <line x1="6" y1="33" x2="144" y2="33"/>
              <line x1="16" y1="42" x2="134" y2="42"/>
              <line x1="8" y1="51" x2="142" y2="51"/>
              <line x1="18" y1="60" x2="132" y2="60"/>
            </g>
            <path d="M40 8 L58 8 L75 28 L92 8 L110 8 L83 39 L67 39 Z" fill="url(#xMetal)"/>
            <path d="M40 76 L58 76 L75 56 L92 76 L110 76 L83 45 L67 45 Z" fill="url(#xMetal)"/>
            <g fill="#38bdf8">
              <rect x="62" y="34" width="4" height="4"/>
              <rect x="70" y="38" width="5" height="5"/>
              <rect x="78" y="35" width="4" height="4"/>
              <rect x="85" y="40" width="4" height="4"/>
              <rect x="54" y="39" width="4" height="4"/>
              <rect x="66" y="44" width="4" height="4"/>
              <rect x="74" y="42" width="5" height="5" fill="#7dd3fc"/>
              <rect x="81" y="45" width="3.5" height="3.5"/>
              <rect x="46" y="30" width="3.5" height="3.5"/>
              <rect x="95" y="29" width="3.5" height="3.5"/>
              <rect x="33" y="40" width="3" height="3"/>
              <rect x="108" y="43" width="3.5" height="3.5"/>
              <rect x="50" y="49" width="3.5" height="3.5"/>
              <rect x="92" y="50" width="3.5" height="3.5"/>
            </g>
          </svg>
        </div>
        <div class="header-right">
          <div class="status-badge">
            <span class="status-dot" id="statusDot"></span>
            <span id="statusText">RAW Active</span>
          </div>
          <button type="button" class="btn-lock" id="logoutBtn">Lock</button>
        </div>
      </div>
      <div class="banner-controls" id="bannerControls">
        <div class="core-ver">
          Core: <b id="coreVersion">v26.10.10</b>
          <span class="hint-tag" id="latestHint"></span>
        </div>
        <button type="button" class="btn-pill-update" id="updateBtn">Check Update</button>
      </div>
    </div>

    <!-- Main Configuration Body -->
    <div class="content-body hidden" id="appView">
      <div>
        <div class="section-heading">
          <span>Node Configuration</span>
        </div>

        <div class="grid">
          <div>
            <label><span>Profile Name (Remark)</span></label>
            <input id="remark" type="text" value="Xray-RAW-Reality">
          </div>

          <div>
            <label><span>Transport Protocol</span></label>
            <div class="proto-tabs" id="protoTabs">
              <button type="button" class="proto-tab active" data-proto="raw">RAW (TCP)</button>
              <button type="button" class="proto-tab" data-proto="xhttp">XHTTP</button>
              <button type="button" class="proto-tab" data-proto="grpc">gRPC</button>
            </div>
          </div>

          <div class="row-2">
            <div>
              <label><span>Server IP or Domain</span></label>
              <input id="serverHost" type="text" value="194.87.219.231">
            </div>
            <div>
              <label><span>Port</span></label>
              <input id="port" type="number" value="443">
            </div>
          </div>

          <div class="row-equal">
            <div>
              <label><span>SNI (Masking Domain)</span></label>
              <input id="sni" type="text" value="www.microsoft.com">
            </div>
            <div>
              <label><span>Fingerprint (uTLS)</span></label>
              <div class="select-wrap">
                <select id="fingerprint">
                  <option value="chrome" selected>Chrome (default)</option>
                  <option value="safari">Safari</option>
                  <option value="ios">iOS</option>
                  <option value="firefox">Firefox</option>
                  <option value="edge">Edge</option>
                  <option value="android">Android</option>
                  <option value="random">Random</option>
                  <option value="randomized">Randomized</option>
                </select>
              </div>
            </div>
          </div>

          <div class="row-equal">
            <div>
              <label>
                <span>Flow Control</span>
                <span class="lock-tag" id="flowLock">LOCKED</span>
              </label>
              <div class="select-wrap">
                <select id="flow">
                  <option value="xtls-rprx-vision" selected>xtls-rprx-vision (default)</option>
                  <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
                </select>
              </div>
            </div>
            <div>
              <label>
                <span id="modeLabel">Transport Mode</span>
                <span class="lock-tag visible" id="modeLock">LOCKED</span>
              </label>
              <div class="select-wrap">
                <select id="transportMode" disabled>
                  <option value="">Locked for RAW</option>
                </select>
              </div>
            </div>
          </div>

          <div>
            <label>
              <span id="pathLabel">Path / ServiceName</span>
              <span class="lock-tag visible" id="pathLock">LOCKED</span>
            </label>
            <input id="transportPath" type="text" value="Locked for RAW" disabled>
          </div>
        </div>

        <div class="actions">
          <button type="button" class="main-btn btn-primary" id="applyBtn">Apply &amp; Get Link</button>
          <button type="button" class="main-btn btn-secondary" id="rekeyBtn">New Keys</button>
        </div>
      </div>

      <div class="link-card">
        <label><span>Generated VLESS Share Link</span></label>
        <div class="uri-field" id="shareLink">vless://da592fba-8c93-46b9-84b1-aa6db33b236d@194.87.219.231:443?encryption=none&amp;flow=xtls-rprx-vision&amp;fp=chrome&amp;pbk=mX9_kLp2vR8nQwZy4tH6jF1cB0gV5sA3dE7uI9oP2xM&amp;security=reality&amp;sid=a4f8c91e&amp;sni=www.microsoft.com&amp;type=tcp#Xray-RAW-Reality</div>
        <button type="button" class="main-btn btn-copy" id="copyBtn">Copy Share Link</button>
        <div class="status-msg" id="msg"></div>
      </div>
    </div>
  </div>

<script>
(function() {
  const queryParams = new URLSearchParams(window.location.search);
  let authToken = queryParams.get("token") || localStorage.getItem("xray_ui_token") || "";

  const PROTOCOL_PRESETS = {
    raw: {
      remark: "Xray-RAW-Reality",
      sni: "www.microsoft.com",
      flowLocked: false,
      flowOptions: [
        { value: "xtls-rprx-vision", label: "xtls-rprx-vision (default)" },
        { value: "xtls-rprx-vision-udp443", label: "xtls-rprx-vision-udp443" }
      ],
      modeLocked: true,
      modeLabel: "Transport Mode",
      modeOptions: [{ value: "", label: "Locked for RAW" }],
      pathLocked: true,
      pathLabel: "Path / ServiceName",
      pathDefault: "Locked for RAW"
    },
    xhttp: {
      remark: "Xray-XHTTP-Reality",
      sni: "www.microsoft.com",
      flowLocked: true,
      flowOptions: [{ value: "", label: "Locked for XHTTP" }],
      modeLocked: false,
      modeLabel: "XHTTP Mode",
      modeOptions: [
        { value: "auto", label: "auto (default)" },
        { value: "packet-up", label: "packet-up" },
        { value: "stream-up", label: "stream-up" },
        { value: "stream-one", label: "stream-one" }
      ],
      pathLocked: false,
      pathLabel: "XHTTP Path",
      pathDefault: "/xhttp"
    },
    grpc: {
      remark: "Xray-gRPC-Reality",
      sni: "www.microsoft.com",
      flowLocked: true,
      flowOptions: [{ value: "", label: "Locked for gRPC" }],
      modeLocked: false,
      modeLabel: "gRPC Mode",
      modeOptions: [
        { value: "gun", label: "gun (default)" },
        { value: "multi", label: "multi (multiplex)" }
      ],
      pathLocked: false,
      pathLabel: "gRPC ServiceName",
      pathDefault: "grpc_service"
    }
  };

  let currentProto = "raw";
  let updateStage = "check";
  let latestTag = "v26.10.10";
  let creds = {
    uuid: "da592fba-8c93-46b9-84b1-aa6db33b236d",
    pbk: "mX9_kLp2vR8nQwZy4tH6jF1cB0gV5sA3dE7uI9oP2xM",
    sid: "a4f8c91e"
  };

  const elTopBanner = document.getElementById("topBanner");
  const elLoginView = document.getElementById("loginView");
  const elAppView = document.getElementById("appView");
  const elLoginPass = document.getElementById("loginPass");
  const elLoginErr = document.getElementById("loginErr");
  const elLogoutBtn = document.getElementById("logoutBtn");

  const elRemark = document.getElementById("remark");
  const elHost = document.getElementById("serverHost");
  const elPort = document.getElementById("port");
  const elSni = document.getElementById("sni");
  const elFp = document.getElementById("fingerprint");
  const elFlow = document.getElementById("flow");
  const elMode = document.getElementById("transportMode");
  const elPath = document.getElementById("transportPath");
  const elLink = document.getElementById("shareLink");
  const elMsg = document.getElementById("msg");
  const elStatus = document.getElementById("statusText");

  function showUnlockedUI(stateData) {
    elLoginView.classList.add("hidden");
    elTopBanner.classList.remove("hidden");
    elAppView.classList.remove("hidden");
    if (stateData) {
      renderServerState(stateData);
    } else {
      setProtocol("raw", true);
    }
  }

  function showLockedUI(errMsg) {
    elTopBanner.classList.add("hidden");
    elAppView.classList.add("hidden");
    elLoginView.classList.remove("hidden");
    elLoginErr.textContent = errMsg || "";
  }

  async function tryUnlock(password, isAuto) {
    if (!password) {
      if (!isAuto) elLoginErr.textContent = "Please enter a password.";
      return;
    }
    elLoginErr.textContent = "";
    try {
      const loginRes = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: password })
      });
      if (loginRes.status === 401) {
        localStorage.removeItem("xray_ui_token");
        showLockedUI(isAuto ? "" : "Invalid password. Try again.");
        return;
      }
      if (loginRes.ok) {
        authToken = password;
        localStorage.setItem("xray_ui_token", password);
        if (window.location.search.indexOf("token=") !== -1 && window.history.replaceState) {
          window.history.replaceState({}, document.title, window.location.pathname);
        }
        const stRes = await fetch("/api/state", { headers: { "X-Auth-Token": authToken } });
        const stData = stRes.ok ? await stRes.json() : null;
        showUnlockedUI(stData);
        return;
      }
    } catch (_) {
      authToken = password;
      showUnlockedUI(null);
    }
  }

  document.getElementById("loginBtn").addEventListener("click", function() {
    tryUnlock(elLoginPass.value.trim(), false);
  });

  elLoginPass.addEventListener("keydown", function(e) {
    if (e.key === "Enter") {
      tryUnlock(elLoginPass.value.trim(), false);
    }
  });

  elLogoutBtn.addEventListener("click", function() {
    authToken = "";
    localStorage.removeItem("xray_ui_token");
    elLoginPass.value = "";
    showLockedUI("");
  });

  function populateSelect(selectEl, options, locked) {
    selectEl.innerHTML = "";
    options.forEach(function(opt) {
      const o = document.createElement("option");
      o.value = opt.value;
      o.textContent = opt.label;
      selectEl.appendChild(o);
    });
    selectEl.disabled = locked;
  }

  function setProtocol(proto, resetDefaults) {
    if (!PROTOCOL_PRESETS[proto]) proto = "raw";
    currentProto = proto;
    const preset = PROTOCOL_PRESETS[proto];

    const tabs = document.querySelectorAll(".proto-tab");
    for (let i = 0; i < tabs.length; i++) {
      if (tabs[i].getAttribute("data-proto") === proto) {
        tabs[i].classList.add("active");
      } else {
        tabs[i].classList.remove("active");
      }
    }

    populateSelect(elFlow, preset.flowOptions, preset.flowLocked);
    document.getElementById("flowLock").classList.toggle("visible", preset.flowLocked);

    document.getElementById("modeLabel").textContent = preset.modeLabel;
    populateSelect(elMode, preset.modeOptions, preset.modeLocked);
    document.getElementById("modeLock").classList.toggle("visible", preset.modeLocked);

    document.getElementById("pathLabel").textContent = preset.pathLabel;
    elPath.disabled = preset.pathLocked;
    document.getElementById("pathLock").classList.toggle("visible", preset.pathLocked);

    if (resetDefaults) {
      elRemark.value = preset.remark;
      elSni.value = preset.sni;
      elPort.value = "443";
      elPath.value = preset.pathDefault;
      showMsg("Switched to " + proto.toUpperCase() + " default preset.");
    }

    elStatus.textContent = proto.toUpperCase() + " Active";
    buildLocalLink();
  }

  function buildLocalLink() {
    const host = elHost.value.trim() || "127.0.0.1";
    const port = elPort.value.trim() || "443";
    const sni = elSni.value.trim() || "www.microsoft.com";
    const fp = elFp.value || "chrome";
    const remark = encodeURIComponent(elRemark.value.trim() || "Xray-Reality");

    const params = new URLSearchParams();
    params.set("encryption", "none");
    params.set("security", "reality");
    params.set("sni", sni);
    params.set("fp", fp);
    params.set("pbk", creds.pbk);
    params.set("sid", creds.sid);

    if (currentProto === "raw") {
      params.set("type", "tcp");
      params.set("flow", elFlow.value);
    } else if (currentProto === "xhttp") {
      params.set("type", "xhttp");
      params.set("path", elPath.value.trim());
      params.set("mode", elMode.value);
    } else if (currentProto === "grpc") {
      params.set("type", "grpc");
      params.set("serviceName", elPath.value.trim());
      params.set("mode", elMode.value);
    }

    elLink.textContent = "vless://" + creds.uuid + "@" + host + ":" + port + "?" + params.toString() + "#" + remark;
  }

  function showMsg(text) {
    elMsg.textContent = text;
  }

  function renderServerState(s) {
    if (s.uuid) creds.uuid = s.uuid;
    if (s.publicKey) creds.pbk = s.publicKey;
    if (s.shortId) creds.sid = s.shortId;

    setProtocol(s.protocol || "raw", false);
    elRemark.value = s.remark || PROTOCOL_PRESETS[currentProto].remark;
    elHost.value = s.serverHost || "127.0.0.1";
    elPort.value = s.port || 443;
    elSni.value = s.sni || "www.microsoft.com";
    elFp.value = s.fingerprint || "chrome";

    if (!PROTOCOL_PRESETS[currentProto].flowLocked && s.flow) {
      elFlow.value = s.flow;
    }
    if (!PROTOCOL_PRESETS[currentProto].modeLocked && s.transportMode) {
      elMode.value = s.transportMode;
    }
    if (!PROTOCOL_PRESETS[currentProto].pathLocked && s.transportPath) {
      elPath.value = s.transportPath;
    } else {
      elPath.value = PROTOCOL_PRESETS[currentProto].pathDefault;
    }

    if (s.coreVersion) {
      document.getElementById("coreVersion").textContent = "v" + s.coreVersion.replace(/^v/, "");
    }
    if (s.shareLink) {
      elLink.textContent = s.shareLink;
    } else {
      buildLocalLink();
    }
  }

  const tabButtons = document.querySelectorAll(".proto-tab");
  for (let i = 0; i < tabButtons.length; i++) {
    tabButtons[i].addEventListener("click", function() {
      setProtocol(this.getAttribute("data-proto"), true);
    });
  }

  const liveInputs = [elRemark, elHost, elPort, elSni, elFp, elFlow, elMode, elPath];
  for (let i = 0; i < liveInputs.length; i++) {
    liveInputs[i].addEventListener("input", buildLocalLink);
    liveInputs[i].addEventListener("change", buildLocalLink);
  }

  document.getElementById("applyBtn").addEventListener("click", async function() {
    buildLocalLink();
    try {
      const res = await fetch("/api/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Auth-Token": authToken },
        body: JSON.stringify({
          remark: elRemark.value.trim(),
          protocol: currentProto,
          serverHost: elHost.value.trim(),
          port: parseInt(elPort.value, 10) || 443,
          sni: elSni.value.trim(),
          fingerprint: elFp.value,
          flow: elFlow.value,
          transportMode: elMode.value,
          transportPath: elPath.value.trim()
        })
      });
      if (res.status === 401) {
        showLockedUI("Session expired. Please log in again.");
        return;
      }
      if (res.ok) {
        const s = await res.json();
        renderServerState(s);
        showMsg("Xray Core restarted with " + currentProto.toUpperCase() + " configuration.");
        return;
      }
    } catch (_) {}
    showMsg("Configuration applied (" + currentProto.toUpperCase() + "). Share link updated.");
  });

  document.getElementById("rekeyBtn").addEventListener("click", async function() {
    try {
      const res = await fetch("/api/rekey", {
        method: "POST",
        headers: { "X-Auth-Token": authToken }
      });
      if (res.status === 401) {
        showLockedUI("Session expired. Please log in again.");
        return;
      }
      if (res.ok) {
        const s = await res.json();
        renderServerState(s);
        showMsg("New Reality X25519 keys & UUID generated on server.");
        return;
      }
    } catch (_) {}
    creds.uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
    });
    creds.sid = Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, "0");
    buildLocalLink();
    showMsg("New Reality keys & UUID generated.");
  });

  function copyTextUniversal(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function(resolve, reject) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "0";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, text.length);
      let ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (e) {}
      document.body.removeChild(ta);
      if (ok) resolve();
      else reject(new Error("Copy failed"));
    });
  }

  document.getElementById("copyBtn").addEventListener("click", function() {
    const btn = this;
    const text = elLink.textContent.trim();
    copyTextUniversal(text).then(function() {
      btn.textContent = "Copied! ✓";
      showMsg("Share link copied to clipboard!");
      setTimeout(function() {
        btn.textContent = "Copy Share Link";
      }, 1800);
    }).catch(function() {
      showMsg("Long-press the link above to copy manually.");
    });
  });

  document.getElementById("updateBtn").addEventListener("click", async function() {
    const btn = this;
    const hint = document.getElementById("latestHint");

    if (updateStage === "check") {
      showMsg("Checking XTLS/Xray-core for updates...");
      try {
        const res = await fetch("/api/update/check", {
          headers: { "X-Auth-Token": authToken }
        });
        if (res.status === 401) {
          showLockedUI("Please unlock the panel first.");
          return;
        }
        if (res.ok) {
          const data = await res.json();
          latestTag = data.latest;
          if (data.hasUpdate) {
            hint.textContent = "→ " + data.latest;
            btn.textContent = "Update to " + data.latest;
            btn.classList.add("ready-upgrade");
            updateStage = "upgrade";
            showMsg("New version " + data.latest + " available! Click again to install.");
          } else {
            showMsg("You are running the latest version (" + data.current + ").");
          }
          return;
        }
      } catch (_) {}

      hint.textContent = "→ " + latestTag;
      btn.textContent = "Update to " + latestTag;
      btn.classList.add("ready-upgrade");
      updateStage = "upgrade";
      showMsg("New version " + latestTag + " found! Click button to update.");
    } else if (updateStage === "upgrade") {
      btn.textContent = "Updating...";
      showMsg("Fetching " + latestTag + " and rebuilding Xray Core...");
      try {
        const res = await fetch("/api/update/run", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Auth-Token": authToken },
          body: JSON.stringify({ tag: latestTag })
        });
        if (res.ok) {
          const data = await res.json();
          document.getElementById("coreVersion").textContent = latestTag;
          hint.textContent = "";
          btn.textContent = "Updated ✓";
          btn.classList.remove("ready-upgrade");
          updateStage = "done";
          showMsg(data.message);
          return;
        }
      } catch (_) {}
    }
  });

  if (authToken) {
    tryUnlock(authToken, true);
  } else {
    showLockedUI("");
  }
})();
</script>
</body>
</html>`
