package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	veilapi "github.com/veil-protocol/veil-core/api"
	"github.com/veil-protocol/veil-core/morph"
)

//go:embed web/*
var webFiles embed.FS

type AppConfig struct {
	Server    string `json:"server"`
	Secret    string `json:"secret"`
	Transport string `json:"transport"`
	SNI       string `json:"sni"`
	Cipher    string `json:"cipher"`
	Morph     string `json:"morph"`
	Socks     string `json:"socks"`
	Insecure  bool   `json:"insecure"`
}

type VeilApp struct {
	mu          sync.RWMutex
	client      *veilapi.Client
	connected   bool
	config      AppConfig
	configPath  string
	wsClients   map[*websocket.Conn]bool
	wsMu        sync.Mutex
	totalBytes  int64
	activeConns int64
	socksLn     net.Listener
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func main() {
	vapp := &VeilApp{
		config: AppConfig{
			Transport: "raw", Cipher: "chacha20-poly1305",
			Morph: "http2_browsing", Socks: "127.0.0.1:1080",
		},
		wsClients: make(map[*websocket.Conn]bool),
	}

	home, _ := os.UserHomeDir()
	vapp.configPath = filepath.Join(home, ".config", "veil", "config.json")
	vapp.loadConfig()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, _ := webFiles.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})
	http.HandleFunc("/ws", vapp.handleWS)

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := fmt.Sprintf("http://%s", addr)

	fmt.Printf("\n  🛡️  Veil Protocol\n  %s\n\n", url)

	go vapp.statsLoop()
	go func() { time.Sleep(400 * time.Millisecond); openBrowser(url) }()

	http.ListenAndServe(addr, nil)
}

func (v *VeilApp) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	v.wsMu.Lock()
	v.wsClients[conn] = true
	v.wsMu.Unlock()
	defer func() {
		v.wsMu.Lock()
		delete(v.wsClients, conn)
		v.wsMu.Unlock()
	}()

	v.sendStatus(conn)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var action map[string]string
		json.Unmarshal(msg, &action)

		switch action["action"] {
		case "connect":
			go v.connect()
		case "disconnect":
			go v.disconnect()
		case "get_config":
			v.sendConfig(conn)
		case "save_config":
			v.config.Server = action["server"]
			v.config.Secret = action["secret"]
			v.config.Transport = action["transport"]
			v.config.Morph = action["morph"]
			v.config.Cipher = action["cipher"]
			v.config.SNI = action["sni"]
			v.config.Socks = action["socks"]
			v.saveConfig()
			v.broadcastLog("Настройки сохранены", "success")
			v.sendConfigToAll()
		case "import_link":
			v.importLink(action["link"])
		}
	}
}

func (v *VeilApp) importLink(link string) {
	cfg, err := veilapi.ParseLink(link)
	if err != nil {
		v.broadcast(map[string]string{"type": "import_err", "text": err.Error()})
		return
	}

	v.config.Server = cfg.ServerAddr
	v.config.Secret = cfg.Secret
	v.config.Transport = cfg.Transport
	v.config.Morph = cfg.MorphProfile
	v.config.Cipher = cfg.Cipher
	v.config.SNI = cfg.SNI
	v.saveConfig()

	v.sendConfigToAll()
	v.broadcast(map[string]string{"type": "import_ok",
		"server": v.config.Server, "secret": v.config.Secret,
		"transport": v.config.Transport, "morph": v.config.Morph,
		"cipher": v.config.Cipher, "sni": v.config.SNI,
		"socks": v.config.Socks,
	})
}

func (v *VeilApp) connect() {
	v.mu.Lock()
	if v.connected {
		v.mu.Unlock()
		return
	}
	v.mu.Unlock()

	if v.config.Server == "" || v.config.Secret == "" {
		v.broadcastLog("Укажи сервер и секрет — вставь ссылку или настрой вручную", "error")
		return
	}

	v.broadcastStatus("connecting", "Подключение...")
	v.broadcastLog(fmt.Sprintf("Подключение к %s...", v.config.Server), "")

	config := veilapi.ClientConfig{
		ServerAddr: v.config.Server, Secret: v.config.Secret,
		Transport: v.config.Transport, SNI: v.config.SNI,
		Cipher: v.config.Cipher, MorphProfile: v.config.Morph,
		InsecureSkipVerify: v.config.Insecure,
		OnDisconnect: func(err error) {
			v.mu.Lock()
			v.connected = false
			v.client = nil
			v.mu.Unlock()
			v.stopSocks()
			v.broadcastStatus("", "Отключен")
			v.broadcastLog(fmt.Sprintf("Отключен: %v", err), "error")
		},
	}

	client, err := veilapi.NewClient(config)
	if err != nil {
		v.broadcastLog(fmt.Sprintf("Ошибка: %v", err), "error")
		v.broadcastStatus("", "Отключен")
		return
	}

	client.Events().On(veilapi.EventStreamOpened, func(e veilapi.Event) {
		v.broadcastLog(fmt.Sprintf("→ %s", e.Message), "stream")
		atomic.AddInt64(&v.activeConns, 1)
	})
	client.Events().On(veilapi.EventStreamClosed, func(e veilapi.Event) {
		atomic.AddInt64(&v.activeConns, -1)
	})

	if err := client.Connect(); err != nil {
		v.broadcastLog(fmt.Sprintf("Не удалось: %v", err), "error")
		v.broadcastStatus("", "Отключен")
		return
	}

	v.mu.Lock()
	v.client = client
	v.connected = true
	v.mu.Unlock()

	go startSOCKS5(v.config.Socks, client, v)

	// Try auto-proxy
	if err := veilapi.SetSystemProxy(v.config.Socks); err == nil {
		v.broadcastLog("Системный прокси настроен автоматически", "success")
	}

	v.broadcastStatus("connected", "Подключен")
	v.broadcastLog("Подключен!", "success")
	v.broadcastLog(fmt.Sprintf("SOCKS5: %s", v.config.Socks), "success")
}

func (v *VeilApp) disconnect() {
	v.mu.Lock()
	if v.client != nil {
		v.client.Close()
		v.client = nil
	}
	v.connected = false
	v.mu.Unlock()

	v.stopSocks()
	veilapi.UnsetSystemProxy()

	v.broadcastStatus("", "Отключен")
	v.broadcastLog("Отключен", "")
}

func (v *VeilApp) stopSocks() {
	v.mu.Lock()
	if v.socksLn != nil {
		v.socksLn.Close()
		v.socksLn = nil
	}
	v.mu.Unlock()
}

func (v *VeilApp) broadcastStatus(state, text string) {
	v.broadcast(map[string]string{"type": "status", "state": state, "text": text})
}
func (v *VeilApp) broadcastLog(text, level string) {
	v.broadcast(map[string]string{"type": "log", "text": text, "level": level})
}
func (v *VeilApp) broadcast(msg interface{}) {
	data, _ := json.Marshal(msg)
	v.wsMu.Lock()
	defer v.wsMu.Unlock()
	for conn := range v.wsClients {
		conn.WriteMessage(websocket.TextMessage, data)
	}
}
func (v *VeilApp) sendStatus(conn *websocket.Conn) {
	v.mu.RLock()
	c := v.connected
	v.mu.RUnlock()
	s, t := "", "Отключен"
	if c {
		s, t = "connected", "Подключен"
	}
	data, _ := json.Marshal(map[string]string{"type": "status", "state": s, "text": t})
	conn.WriteMessage(websocket.TextMessage, data)
}
func (v *VeilApp) sendConfig(conn *websocket.Conn) {
	data, _ := json.Marshal(map[string]string{
		"type": "config", "server": v.config.Server, "secret": v.config.Secret,
		"transport": v.config.Transport, "morph": v.config.Morph,
		"cipher": v.config.Cipher, "sni": v.config.SNI, "socks": v.config.Socks,
	})
	conn.WriteMessage(websocket.TextMessage, data)
}
func (v *VeilApp) sendConfigToAll() {
	v.broadcast(map[string]string{
		"type": "config", "server": v.config.Server, "secret": v.config.Secret,
		"transport": v.config.Transport, "morph": v.config.Morph,
		"cipher": v.config.Cipher, "sni": v.config.SNI, "socks": v.config.Socks,
	})
}
func (v *VeilApp) sendProfiles(conn *websocket.Conn) {
        profiles := morph.ListBuiltinProfiles()
        type profileMsg struct {
                Type     string             `json:"type"`
                Profiles []morph.ProfileInfo `json:"profiles"`
        }
        data, _ := json.Marshal(profileMsg{Type: "profiles", Profiles: profiles})
        conn.WriteMessage(websocket.TextMessage, data)
}

func (v *VeilApp) statsLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		b := atomic.LoadInt64(&v.totalBytes)
		c := atomic.LoadInt64(&v.activeConns)
		v.broadcast(map[string]string{"type": "stats", "bytes": fmtB(b), "conns": fmt.Sprintf("%d", c)})
	}
}
func (v *VeilApp) saveConfig() {
	os.MkdirAll(filepath.Dir(v.configPath), 0700)
	data, _ := json.MarshalIndent(v.config, "", "  ")
	os.WriteFile(v.configPath, data, 0600)
}
func (v *VeilApp) loadConfig() {
	data, err := os.ReadFile(v.configPath)
	if err != nil {
		return
	}
	json.Unmarshal(data, &v.config)
}
func fmtB(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	} else if b < 1<<30 {
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
}
func openBrowser(url string) {
	switch runtime.GOOS {
	case "linux":
		exec.Command("xdg-open", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
}
