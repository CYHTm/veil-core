// Package api — decoy.go implements Protocol Completion.
//
// In decoy mode, the Veil server is a REAL HTTPS website.
// Normal browsers see a legitimate website.
// Veil clients activate the tunnel via steganographic trigger in HTTP headers.
//
// This defeats active probing: censors connect, see a real site,
// conclude it's not a proxy.
package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
	"github.com/veil-protocol/veil-core/morph"
	"github.com/veil-protocol/veil-core/protocol"
)

// DecoyServer runs a real HTTPS website with hidden Veil tunnel.
type DecoyServer struct {
	mu       sync.RWMutex
	config   ServerConfig
	events   *EventBus
	logger   *log.Logger
	trigger  *veilcrypto.StegTrigger
	sessions map[[16]byte]*protocol.Session

	httpServer *http.Server
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewDecoyServer creates a server that looks like a real website.
func NewDecoyServer(config ServerConfig) (*DecoyServer, error) {
	if config.ListenAddr == "" {
		return nil, fmt.Errorf("veil: listen_addr is required")
	}
	if config.Secret == "" {
		return nil, fmt.Errorf("veil: secret is required")
	}
	if config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("veil: cert_file and key_file are required for decoy mode")
	}

	defaults := DefaultServerConfig()
	if config.Cipher == "" {
		config.Cipher = defaults.Cipher
	}
	if config.MaxStreams == 0 {
		config.MaxStreams = defaults.MaxStreams
	}
	if len(config.MorphProfiles) == 0 {
		config.MorphProfiles = defaults.MorphProfiles
	}

	ctx, cancel := context.WithCancel(context.Background())

	ds := &DecoyServer{
		config:   config,
		events:   NewEventBus(256),
		logger:   log.New(os.Stdout, "[veil-decoy] ", log.LstdFlags),
		trigger:  veilcrypto.NewStegTrigger(config.Secret),
		sessions: make(map[[16]byte]*protocol.Session),
		ctx:      ctx,
		cancel:   cancel,
	}

	return ds, nil
}

// Events returns the event bus.
func (ds *DecoyServer) Events() *EventBus {
	return ds.events
}

// Start begins serving HTTPS with hidden Veil tunnel.
func (ds *DecoyServer) Start() error {
	mux := http.NewServeMux()

	// All requests go through the trigger checker
	mux.HandleFunc("/", ds.handleRequest)

	cert, err := tls.LoadX509KeyPair(ds.config.CertFile, ds.config.KeyFile)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	ds.httpServer = &http.Server{
		Addr:      ds.config.ListenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	ds.logger.Printf("decoy server starting on %s", ds.config.ListenAddr)
	ds.logger.Printf("normal visitors see a website, Veil clients get a tunnel")

	go ds.httpServer.ListenAndServeTLS("", "")

	return nil
}

// Stop shuts down the decoy server.
func (ds *DecoyServer) Stop() error {
	ds.cancel()

	ds.mu.Lock()
	for id, session := range ds.sessions {
		session.Close()
		delete(ds.sessions, id)
	}
	ds.mu.Unlock()

	if ds.httpServer != nil {
		ds.httpServer.Close()
	}

	ds.events.Close()
	ds.logger.Println("decoy server stopped")
	return nil
}

// ActiveSessions returns count of active Veil sessions.
func (ds *DecoyServer) ActiveSessions() int {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return len(ds.sessions)
}

// GenerateClientTrigger returns the cookie a Veil client should send.
func (ds *DecoyServer) GenerateClientTrigger() (cookieName, cookieValue, headerName, headerValue string) {
	cn, cv := ds.trigger.GenerateHTTPCookieTrigger()
	hn, hv := ds.trigger.GenerateHTTPHeaderTrigger()
	return cn, cv, hn, hv
}

func (ds *DecoyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Check for Veil trigger in Cookie
	if cookie, err := r.Cookie("_ga"); err == nil {
		if ds.trigger.ValidateHTTPCookieTrigger(cookie.Value) {
			ds.logger.Printf("trigger detected (cookie) from %s", r.RemoteAddr)
			ds.hijackAndTunnel(w, r)
			return
		}
	}

	// Check trigger in Accept-Language header
	if lang := r.Header.Get("Accept-Language"); lang != "" {
		if ds.trigger.ValidateHTTPHeaderTrigger(lang) {
			ds.logger.Printf("trigger detected (header) from %s", r.RemoteAddr)
			ds.hijackAndTunnel(w, r)
			return
		}
	}

	// No trigger — serve decoy website
	ds.serveDecoy(w, r)
}

func (ds *DecoyServer) hijackAndTunnel(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		ds.logger.Printf("hijack not supported for %s", r.RemoteAddr)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		ds.logger.Printf("hijack failed for %s: %v", r.RemoteAddr, err)
		return
	}

	// Send HTTP 101 Switching Protocols (looks like WebSocket upgrade)
	conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))

	// Now proceed with Veil handshake over this hijacked connection
	go ds.handleVeilConnection(conn, r.RemoteAddr)
}

func (ds *DecoyServer) handleVeilConnection(conn net.Conn, remoteAddr string) {
	defer conn.Close()

	ds.logger.Printf("veil tunnel activated for %s", remoteAddr)

	if ds.config.OnClientConnect != nil {
		ds.config.OnClientConnect(remoteAddr)
	}

	handshaker := protocol.NewHandshaker(
		protocol.RoleServer,
		ds.config.Secret,
		"wss", // decoy mode uses wss-like transport
		protocol.Capabilities{
			MaxStreams:    ds.config.MaxStreams,
			MorphProfiles: ds.config.MorphProfiles,
			Transports:    []string{"wss"},
		},
	)

	cipherType := veilcrypto.CipherChaCha20Poly1305
	if ds.config.Cipher == "aes-256-gcm" {
		cipherType = veilcrypto.CipherAES256GCM
	}
	handshaker.SetCipher(cipherType)

	// Read Veil ClientHello
	clientHelloBytes, err := readHandshake(conn, 4096)
	if err != nil {
		ds.logger.Printf("read client hello failed (%s): %v", remoteAddr, err)
		return
	}

	serverHelloBytes, hsResult, _, err := handshaker.ProcessClientHello(clientHelloBytes)
	if err != nil {
		ds.logger.Printf("handshake failed (%s): %v", remoteAddr, err)
		return
	}

	if err := writeHandshake(conn, serverHelloBytes); err != nil {
		ds.logger.Printf("send server hello failed (%s): %v", remoteAddr, err)
		return
	}

	ds.logger.Printf("handshake complete with %s (session: %x)", remoteAddr, hsResult.SessionID[:4])

	morphProfile := morph.BuiltinHTTP2Profile()

	// Wrap net.Conn as transport.Connection
	tConn := &decoyConnection{Conn: conn}

	var session *protocol.Session

	sessionCfg := protocol.SessionConfig{
		Role:            protocol.RoleServer,
		Connection:      tConn,
		HandshakeResult: hsResult,
		MorphProfile:    morphProfile,
		Logger:          ds.logger,
		OnStreamOpen: func(streamID uint16, targetAddr string) {
			ds.logger.Printf("[session:%x] stream %d -> %s",
				hsResult.SessionID[:4], streamID, targetAddr)
			if ds.config.OnStreamOpen != nil {
				ds.config.OnStreamOpen(remoteAddr, targetAddr)
			}
			go ds.proxyStream(session, streamID, targetAddr)
		},
		OnClose: func(err error) {
			ds.mu.Lock()
			delete(ds.sessions, hsResult.SessionID)
			ds.mu.Unlock()
			if ds.config.OnClientDisconnect != nil {
				ds.config.OnClientDisconnect(remoteAddr)
			}
		},
	}

	session, err = protocol.NewSession(sessionCfg)
	if err != nil {
		ds.logger.Printf("create session failed (%s): %v", remoteAddr, err)
		return
	}

	ds.mu.Lock()
	ds.sessions[hsResult.SessionID] = session
	ds.mu.Unlock()

	session.Start(ds.ctx)

	// Block until session closes
	<-ds.ctx.Done()
}

func (ds *DecoyServer) proxyStream(session *protocol.Session, streamID uint16, targetAddr string) {
	if session == nil {
		return
	}

	stream, ok := session.GetMux().GetStream(streamID)
	if !ok {
		return
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, protocol.HandshakeTimeout)
	if err != nil {
		ds.logger.Printf("proxy connect to %s failed: %v", targetAddr, err)
		stream.Close()
		return
	}
	defer targetConn.Close()
	defer stream.Close()

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if _, we := stream.Write(buf[:n]); we != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, we := targetConn.Write(buf[:n]); we != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
}

func (ds *DecoyServer) serveDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("X-Powered-By", "Express")

	switch r.URL.Path {
	case "/", "/index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		io.WriteString(w, decoyPageHTML)
	case "/favicon.ico":
		w.WriteHeader(204)
	case "/robots.txt":
		w.WriteHeader(200)
		io.WriteString(w, "User-agent: *\nAllow: /\n")
	case "/sitemap.xml":
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(200)
		io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://`+r.Host+`/</loc></url></urlset>`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, notFoundHTML)
	}
}

const decoyPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudMatrix — Enterprise Cloud Solutions</title>
<meta name="description" content="Enterprise-grade cloud infrastructure with 99.99% uptime SLA. Auto-scaling, global CDN, and SOC 2 compliance.">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#1f2937;line-height:1.6}
.nav{background:#fff;padding:14px 40px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e5e7eb;position:sticky;top:0;z-index:10}
.nav .logo{font-size:18px;font-weight:700;color:#2563eb;display:flex;align-items:center;gap:8px}
.nav .logo span{background:#2563eb;color:#fff;width:28px;height:28px;border-radius:6px;display:grid;place-items:center;font-size:14px}
.nav-links{display:flex;gap:24px}
.nav-links a{color:#6b7280;text-decoration:none;font-size:14px;font-weight:500;transition:color .2s}
.nav-links a:hover{color:#2563eb}
.hero{background:linear-gradient(135deg,#1e3a8a,#3b82f6);color:#fff;padding:80px 40px;text-align:center}
.hero h1{font-size:40px;font-weight:800;margin-bottom:16px;letter-spacing:-.5px}
.hero p{font-size:18px;opacity:.9;max-width:560px;margin:0 auto 32px}
.hero .cta{display:inline-flex;gap:12px}
.btn{padding:12px 28px;border-radius:8px;font-weight:600;text-decoration:none;font-size:14px;transition:all .2s}
.btn-primary{background:#fff;color:#2563eb}.btn-primary:hover{background:#f0f4ff}
.btn-secondary{background:rgba(255,255,255,.15);color:#fff;border:1px solid rgba(255,255,255,.3)}.btn-secondary:hover{background:rgba(255,255,255,.25)}
.features{padding:60px 40px;max-width:960px;margin:0 auto}
.features h2{text-align:center;font-size:28px;margin-bottom:40px;color:#111827}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:24px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px;transition:box-shadow .2s}
.card:hover{box-shadow:0 4px 12px rgba(0,0,0,.08)}
.card .icon{width:40px;height:40px;background:#eff6ff;border-radius:8px;display:grid;place-items:center;font-size:20px;margin-bottom:12px}
.card h3{font-size:16px;margin-bottom:6px;color:#111827}
.card p{font-size:13px;color:#6b7280;line-height:1.5}
.stats{background:#f9fafb;padding:48px 40px;display:flex;justify-content:center;gap:64px}
.stat{text-align:center}.stat b{display:block;font-size:32px;color:#2563eb;font-weight:800}.stat span{font-size:13px;color:#6b7280}
.footer{padding:24px 40px;text-align:center;color:#9ca3af;font-size:12px;border-top:1px solid #e5e7eb}
@media(max-width:768px){.grid{grid-template-columns:1fr}.stats{flex-direction:column;gap:24px}.nav-links{display:none}}
</style>
</head>
<body>
<nav class="nav"><div class="logo"><span>C</span>CloudMatrix</div><div class="nav-links"><a href="#">Products</a><a href="#">Pricing</a><a href="#">Documentation</a><a href="#">Blog</a><a href="#">Contact</a></div></nav>
<div class="hero"><h1>Infrastructure That Scales With You</h1><p>Enterprise-grade cloud platform with automatic scaling, global edge network, and built-in security compliance.</p><div class="cta"><a href="#" class="btn btn-primary">Start Free Trial</a><a href="#" class="btn btn-secondary">View Documentation</a></div></div>
<div class="stats"><div class="stat"><b>99.99%</b><span>Uptime SLA</span></div><div class="stat"><b>42</b><span>Edge Locations</span></div><div class="stat"><b>150ms</b><span>Avg Latency</span></div><div class="stat"><b>10K+</b><span>Companies</span></div></div>
<div class="features"><h2>Why Teams Choose CloudMatrix</h2><div class="grid">
<div class="card"><div class="icon">⚡</div><h3>Auto Scaling</h3><p>Automatically adjust compute resources based on real-time demand. Pay only for what you use.</p></div>
<div class="card"><div class="icon">🔒</div><h3>Security First</h3><p>SOC 2 Type II and ISO 27001 certified. End-to-end encryption with customer-managed keys.</p></div>
<div class="card"><div class="icon">🌍</div><h3>Global CDN</h3><p>Content delivery across 42 edge locations. Sub-100ms response times worldwide.</p></div>
<div class="card"><div class="icon">📊</div><h3>Observability</h3><p>Built-in monitoring, logging, and tracing. Real-time dashboards and smart alerts.</p></div>
<div class="card"><div class="icon">🔄</div><h3>CI/CD Native</h3><p>Integrated deployment pipelines with GitHub, GitLab, and Bitbucket. Zero-downtime deploys.</p></div>
<div class="card"><div class="icon">🤝</div><h3>24/7 Support</h3><p>Dedicated support engineers with 15-minute response time on critical issues.</p></div>
</div></div>
<footer class="footer">&copy; 2024 CloudMatrix, Inc. All rights reserved. &nbsp;|&nbsp; <a href="#" style="color:#9ca3af">Privacy Policy</a> &nbsp;|&nbsp; <a href="#" style="color:#9ca3af">Terms of Service</a></footer>
</body>
</html>`

const notFoundHTML = `<!DOCTYPE html>
<html><head><title>404 — Not Found</title>
<style>body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#6b7280}
.c{text-align:center}h1{font-size:72px;color:#e5e7eb;margin:0}p{margin-top:8px}</style>
</head><body><div class="c"><h1>404</h1><p>The page you're looking for doesn't exist.</p><a href="/" style="color:#2563eb">Go Home</a></div></body></html>`

// decoyConnection wraps net.Conn to implement transport.Connection.
type decoyConnection struct {
	net.Conn
}

func (c *decoyConnection) TransportID() string {
	return "decoy"
}
