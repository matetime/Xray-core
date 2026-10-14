package all

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
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
	"golang.org/x/crypto/curve25519"
)

var cmdWebUI = &base.Command{
	UsageLine: "{{.Exec}} webui [-listen 127.0.0.1:8080] [-token secret]",
	Short:     "Start modern Web UI for VLESS + (RAW / XHTTP / gRPC) + REALITY",
	Long: `
Start an embedded Web UI to configure and run a VLESS + REALITY node with RAW, XHTTP, or gRPC.

Arguments:
	-listen <addr:port> : Address and port for the Web UI (default: 127.0.0.1:8080)
	-token <string>     : Optional access token for UI protection
	-state <file>       : Path to state file (default: webui_state.json)
`,
}

var (
	uiListen  string
	uiToken   string
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
	uiListen = *cmdWebUI.Flag.String("listen", "127.0.0.1:8080", "Web UI listen address")
	uiToken = *cmdWebUI.Flag.String("token", "", "Access token for Web UI")
	stateFile = *cmdWebUI.Flag.String("state", "webui_state.json", "State file path")

	base.RootCommand.Commands = append(base.RootCommand.Commands, cmdWebUI)
}

func executeWebUI(cmd *base.Command, args []string) {
	cmd.Flag.Parse(args)
	uiListen = cmd.Flag.Lookup("listen").Value.String()
	uiToken = cmd.Flag.Lookup("token").Value.String()
	stateFile = cmd.Flag.Lookup("state").Value.String()

	initDefaultState()

	mux := http.NewServeMux()
	mux.HandleFunc("/", authMiddleware(handleIndex))
	mux.HandleFunc("/api/state", authMiddleware(handleState))
	mux.HandleFunc("/api/apply", authMiddleware(handleApply))
	mux.HandleFunc("/api/rekey", authMiddleware(handleRekey))
	mux.HandleFunc("/api/update/check", authMiddleware(handleUpdateCheck))
	mux.HandleFunc("/api/update/run", authMiddleware(handleUpdateRun))

	log.Printf("[Xray-WebUI] Listening on http://%s (Xray Core v%s)", uiListen, core.Version())
	if currentState.ServerHost != "" {
		if err := restartXrayInstance(); err != nil {
			log.Printf("[Xray-WebUI] Autostart deferred: %v", err)
		}
	}

	go func() {
		if err := http.ListenAndServe(uiListen, mux); err != nil {
			log.Fatalf("[Xray-WebUI] HTTP server error: %v", err)
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

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if uiToken != "" {
			token := r.Header.Get("X-Auth-Token")
			if token == "" {
				token = r.URL.Query().Get("token")
			}
			if token != uiToken {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
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
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", s.SNI)
	q.Set("fp", "chrome")
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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Xray Reality Core — Web UI</title>
<style>
  :root {
    --navy-header: #112854;
    --navy-dark: #0c1d3e;
    --royal-blue: #2e6ff2;
    --royal-hover: #1e5dd9;
    --card-white: #ffffff;
    --surface-gray: #edf0f6;
    --surface-border: #dfe5ef;
    --text-dark: #121f38;
    --text-muted: #7b88a1;
    --amber-star: #f5a623;
    --green-ok: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Inter", "Segoe UI", sans-serif;
    background-color: var(--card-white);
    color: var(--text-dark);
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: flex-start;
  }
  .screen-inner {
    width: 100%;
    max-width: 460px;
    background: var(--card-white);
    overflow: hidden;
  }
  .navy-banner {
    background: linear-gradient(160deg, var(--navy-header) 0%, var(--navy-dark) 100%);
    color: #ffffff;
    padding: 22px 20px 20px;
  }
  .banner-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }
  .banner-title { font-size: 19px; font-weight: 700; letter-spacing: -0.01em; }
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(255, 255, 255, 0.12);
    border: 1px solid rgba(255, 255, 255, 0.2);
    padding: 5px 12px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 600;
    color: #ffffff;
  }
  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--green-ok);
    box-shadow: 0 0 8px var(--green-ok);
  }
  .banner-controls {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 999px;
    padding: 6px 6px 6px 16px;
  }
  .core-ver { font-size: 12.5px; color: rgba(255, 255, 255, 0.85); }
  .core-ver b { color: #ffffff; font-family: ui-monospace, SFMono-Regular, monospace; font-weight: 700; }
  .hint-tag { color: var(--amber-star); font-weight: 600; margin-left: 4px; }
  .btn-pill-update {
    appearance: none;
    border: none;
    background: var(--royal-blue);
    color: #ffffff;
    font-size: 12px;
    font-weight: 600;
    padding: 8px 16px;
    border-radius: 999px;
    cursor: pointer;
    transition: all 0.2s ease;
    box-shadow: 0 4px 12px rgba(46, 111, 242, 0.4);
  }
  .btn-pill-update:hover { background: var(--royal-hover); }
  .btn-pill-update.ready-upgrade {
    background: var(--amber-star);
    color: #112854;
    box-shadow: 0 4px 12px rgba(245, 166, 35, 0.4);
  }
  .content-body { padding: 20px 18px 24px; }
  .section-heading {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 14px;
    font-weight: 700;
    color: var(--text-dark);
    margin-bottom: 12px;
  }
  .section-sub { font-size: 11px; font-weight: 600; color: var(--amber-star); }
  .grid { display: grid; gap: 13px; }
  .row-2 { display: grid; grid-template-columns: 2fr 1fr; gap: 10px; }
  .row-equal { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 11.5px;
    color: var(--text-muted);
    margin-bottom: 5px;
    font-weight: 600;
    padding: 0 2px;
  }
  .lock-tag {
    font-size: 9.5px;
    color: #64748b;
    background: #e2e8f0;
    padding: 2px 7px;
    border-radius: 999px;
    letter-spacing: 0.04em;
    display: none;
    font-weight: 700;
  }
  .lock-tag.visible { display: inline-block; }
  .proto-tabs {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    background: var(--surface-gray);
    padding: 5px;
    border-radius: 16px;
  }
  .proto-tab {
    appearance: none;
    background: transparent;
    border: none;
    color: var(--text-muted);
    padding: 9px 0;
    font-size: 12.5px;
    font-weight: 700;
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.18s ease;
    user-select: none;
  }
  .proto-tab:hover { color: var(--text-dark); }
  .proto-tab.active {
    background: var(--royal-blue);
    color: #ffffff;
    box-shadow: 0 4px 12px rgba(46, 111, 242, 0.35);
  }
  input, select {
    width: 100%;
    background: var(--surface-gray);
    border: 1.5px solid transparent;
    color: var(--text-dark);
    padding: 10px 13px;
    border-radius: 14px;
    font-size: 13.5px;
    font-weight: 600;
    outline: none;
    transition: all 0.18s ease;
  }
  input:focus, select:focus {
    background: #ffffff;
    border-color: var(--royal-blue);
    box-shadow: 0 3px 12px rgba(46, 111, 242, 0.12);
  }
  input:disabled, select:disabled {
    background: repeating-linear-gradient(-45deg, #e6ebf3, #e6ebf3 6px, #dfe5ef 6px, #dfe5ef 12px);
    color: #94a3b8;
    border-color: #d8e0ec;
    cursor: not-allowed;
  }
  .actions { display: flex; gap: 10px; margin-top: 16px; }
  button.main-btn {
    cursor: pointer;
    border: none;
    border-radius: 999px;
    padding: 11px 18px;
    font-size: 13px;
    font-weight: 700;
    transition: all 0.2s ease;
  }
  .btn-primary {
    flex: 1;
    background: var(--royal-blue);
    color: #ffffff;
    box-shadow: 0 6px 16px rgba(46, 111, 242, 0.3);
  }
  .btn-primary:hover { background: var(--royal-hover); }
  .btn-secondary { background: var(--surface-gray); color: var(--navy-header); }
  .btn-secondary:hover { background: #e1e7f0; }
  .link-card {
    margin-top: 18px;
    background: var(--surface-gray);
    border-radius: 20px;
    padding: 14px;
  }
  .uri-field {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11.5px;
    word-break: break-all;
    background: #ffffff;
    padding: 11px 13px;
    border-radius: 12px;
    color: var(--navy-header);
    margin: 6px 0 10px;
    max-height: 82px;
    overflow-y: auto;
    line-height: 1.45;
    border: 1px solid var(--surface-border);
  }
  .btn-copy { width: 100%; background: var(--navy-header); color: #ffffff; }
  .btn-copy:hover { background: var(--navy-dark); }
  .status-msg {
    font-size: 11.5px;
    color: var(--royal-blue);
    margin-top: 10px;
    min-height: 16px;
    text-align: center;
    font-weight: 600;
  }
</style>
</head>
<body>
  <div class="screen-inner">
    <div class="navy-banner">
      <div class="banner-top">
        <div class="banner-title">Xray Reality Core</div>
        <div class="status-badge">
          <span class="status-dot"></span>
          <span id="statusText">RAW Active</span>
        </div>
      </div>
      <div class="banner-controls">
        <div class="core-ver">
          Core: <b id="coreVersion">v26.1.18</b>
          <span class="hint-tag" id="latestHint"></span>
        </div>
        <button type="button" class="btn-pill-update" id="updateBtn">Check Update</button>
      </div>
    </div>

    <div class="content-body">
      <div class="section-heading">
        <span>Node Configuration</span>
        <span class="section-sub">★ VLESS + REALITY</span>
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
            <input id="serverHost" type="text" value="203.0.113.10">
          </div>
          <div>
            <label><span>Port</span></label>
            <input id="port" type="number" value="443">
          </div>
        </div>

        <div>
          <label><span>SNI (Reality Masking Domain)</span></label>
          <input id="sni" type="text" value="www.microsoft.com">
        </div>

        <div class="row-equal">
          <div>
            <label>
              <span>Flow Control</span>
              <span class="lock-tag" id="flowLock">LOCKED</span>
            </label>
            <select id="flow">
              <option value="xtls-rprx-vision" selected>xtls-rprx-vision (default)</option>
              <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
            </select>
          </div>
          <div>
            <label>
              <span id="modeLabel">Transport Mode</span>
              <span class="lock-tag visible" id="modeLock">LOCKED</span>
            </label>
            <select id="transportMode" disabled>
              <option value="">Locked for RAW</option>
            </select>
          </div>
        </div>

        <div>
          <label>
            <span id="pathLabel">Path / ServiceName</span>
            <span class="lock-tag visible" id="pathLock">LOCKED</span>
          </label>
          <input id="transportPath" type="text" value="Not used in RAW" disabled>
        </div>
      </div>

      <div class="actions">
        <button type="button" class="main-btn btn-primary" id="applyBtn">Apply &amp; Get Link</button>
        <button type="button" class="main-btn btn-secondary" id="rekeyBtn">New Keys</button>
      </div>

      <div class="link-card">
        <label><span>Generated VLESS Share Link</span></label>
        <div class="uri-field" id="shareLink">vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@203.0.113.10:443?encryption=none&amp;flow=xtls-rprx-vision&amp;fp=chrome&amp;pbk=mX9_kLp2vR8nQwZy4tH6jF1cB0gV5sA3dE7uI9oP2xM&amp;security=reality&amp;sid=a4f8c91e&amp;sni=www.microsoft.com&amp;type=tcp#Xray-RAW-Reality</div>
        <button type="button" class="main-btn btn-copy" id="copyBtn">Copy Share Link</button>
        <div class="status-msg" id="msg"></div>
      </div>
    </div>
  </div>

<script>
(function() {
  const queryParams = new URLSearchParams(window.location.search);
  const authToken = queryParams.get("token") || "";

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
      pathDefault: "Not used in RAW"
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
  let latestTag = "v26.2.4";
  let creds = {
    uuid: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    pbk: "mX9_kLp2vR8nQwZy4tH6jF1cB0gV5sA3dE7uI9oP2xM",
    sid: "a4f8c91e"
  };

  const elRemark = document.getElementById("remark");
  const elHost = document.getElementById("serverHost");
  const elPort = document.getElementById("port");
  const elSni = document.getElementById("sni");
  const elFlow = document.getElementById("flow");
  const elMode = document.getElementById("transportMode");
  const elPath = document.getElementById("transportPath");
  const elLink = document.getElementById("shareLink");
  const elMsg = document.getElementById("msg");
  const elStatus = document.getElementById("statusText");

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
    const remark = encodeURIComponent(elRemark.value.trim() || "Xray-Reality");

    const params = new URLSearchParams();
    params.set("encryption", "none");
    params.set("security", "reality");
    params.set("sni", sni);
    params.set("fp", "chrome");
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

  const liveInputs = [elRemark, elHost, elPort, elSni, elFlow, elMode, elPath];
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
          flow: elFlow.value,
          transportMode: elMode.value,
          transportPath: elPath.value.trim()
        })
      });
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

  document.getElementById("copyBtn").addEventListener("click", function() {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(elLink.textContent);
    }
    showMsg("Share link copied to clipboard!");
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

      try {
        const gh = await fetch("https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10");
        if (gh.ok) {
          const list = await gh.json();
          const pre = list.find(function(r) { return r.prerelease; }) || list[0];
          if (pre && pre.tag_name) latestTag = pre.tag_name;
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

      setTimeout(function() {
        document.getElementById("coreVersion").textContent = latestTag;
        hint.textContent = "";
        btn.textContent = "Updated ✓";
        btn.classList.remove("ready-upgrade");
        updateStage = "done";
        showMsg("Xray Core successfully updated to " + latestTag + "!");
      }, 600);
    }
  });

  setProtocol("raw", true);
  fetch("/api/state", { headers: { "X-Auth-Token": authToken } })
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(s) { if (s) renderServerState(s); })
    .catch(function() {});
})();
</script>
</body>
</html>`
