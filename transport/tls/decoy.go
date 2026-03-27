// Package tls — decoy.go implements Protocol Completion.
//
// The Veil server runs as a REAL HTTPS website. When a normal browser
// visits it, they see a legitimate website. Only requests containing
// a steganographic trigger activate the Veil tunnel.
//
// This defeats active probing: censors connect to the server,
// see a real website, and conclude it's not a proxy.
package tls

import (
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
	"github.com/veil-protocol/veil-core/transport"
)

// DecoyServer wraps a real HTTPS server with Veil tunnel capability.
// From outside it looks like a normal website.
// Veil clients activate the tunnel via steganographic trigger.
type DecoyServer struct {
	trigger   *veilcrypto.StegTrigger
	veilConns chan transport.Connection
	httpMux   *http.ServeMux
	mu        sync.Mutex
}

// NewDecoyServer creates a server that acts as a real website
// but also accepts Veil tunnel connections via steganographic triggers.
func NewDecoyServer(secret string, decoyTarget string) (*DecoyServer, error) {
	ds := &DecoyServer{
		trigger:   veilcrypto.NewStegTrigger(secret),
		veilConns: make(chan transport.Connection, 64),
		httpMux:   http.NewServeMux(),
	}

	if decoyTarget != "" {
		// Reverse proxy to a real website (e.g., nginx default page)
		target, err := url.Parse(decoyTarget)
		if err != nil {
			return nil, err
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		ds.httpMux.Handle("/", proxy)
	} else {
		// Built-in decoy: looks like a corporate landing page
		ds.httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Check for Veil trigger in Cookie
			if cookie, err := r.Cookie("_ga"); err == nil {
				if ds.trigger.ValidateHTTPCookieTrigger(cookie.Value) {
					// This is a Veil client! Hijack the connection.
					ds.hijackConnection(w, r)
					return
				}
			}

			// Check trigger in Accept-Language header
			if lang := r.Header.Get("Accept-Language"); lang != "" {
				if ds.trigger.ValidateHTTPHeaderTrigger(lang) {
					ds.hijackConnection(w, r)
					return
				}
			}

			// Normal visitor — show decoy page
			serveDecoyPage(w, r)
		})
	}

	return ds, nil
}

// AcceptVeil waits for a Veil client connection (triggered via stego).
func (ds *DecoyServer) AcceptVeil() (transport.Connection, error) {
	conn, ok := <-ds.veilConns
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

// GetHTTPHandler returns the HTTP handler for use with http.Server.
func (ds *DecoyServer) GetHTTPHandler() http.Handler {
	return ds.httpMux
}

// GenerateTriggerCookie creates the cookie a Veil client should send.
func (ds *DecoyServer) GenerateTriggerCookie() (name, value string) {
	return ds.trigger.GenerateHTTPCookieTrigger()
}

// GenerateTriggerHeader creates the header a Veil client should send.
func (ds *DecoyServer) GenerateTriggerHeader() (name, value string) {
	return ds.trigger.GenerateHTTPHeaderTrigger()
}

func (ds *DecoyServer) hijackConnection(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Internal Server Error", 500)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}

	veilConn := &hijackedConnection{
		Conn:        conn,
		transportID: "tls-decoy",
	}

	select {
	case ds.veilConns <- veilConn:
	default:
		conn.Close()
	}
}

// serveDecoyPage renders a realistic-looking website.
func serveDecoyPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("X-Powered-By", "Express")

	switch r.URL.Path {
	case "/", "/index.html":
		w.WriteHeader(200)
		io.WriteString(w, decoyHTML)
	case "/favicon.ico":
		w.WriteHeader(204)
	case "/robots.txt":
		w.WriteHeader(200)
		io.WriteString(w, "User-agent: *\nAllow: /\n")
	default:
		w.WriteHeader(404)
		io.WriteString(w, "<!DOCTYPE html><html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
	}
}

const decoyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudMatrix — Enterprise Cloud Solutions</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#333;line-height:1.6}
.nav{background:#fff;padding:16px 40px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #eee}
.nav .logo{font-size:20px;font-weight:700;color:#2563eb}
.nav a{color:#666;text-decoration:none;margin-left:24px;font-size:14px}
.hero{background:linear-gradient(135deg,#1e40af,#3b82f6);color:#fff;padding:80px 40px;text-align:center}
.hero h1{font-size:42px;margin-bottom:16px}
.hero p{font-size:18px;opacity:.9;max-width:600px;margin:0 auto 32px}
.btn{display:inline-block;padding:12px 32px;background:#fff;color:#2563eb;border-radius:8px;font-weight:600;text-decoration:none}
.features{padding:60px 40px;display:grid;grid-template-columns:repeat(3,1fr);gap:32px;max-width:1000px;margin:0 auto}
.feature{text-align:center;padding:24px}
.feature h3{margin:12px 0 8px;font-size:18px}
.feature p{color:#666;font-size:14px}
.footer{background:#f8fafc;padding:24px;text-align:center;color:#999;font-size:13px}
</style>
</head>
<body>
<div class="nav"><div class="logo">CloudMatrix</div><div><a href="#">Products</a><a href="#">Pricing</a><a href="#">Docs</a><a href="#">Contact</a></div></div>
<div class="hero"><h1>Scale Your Infrastructure</h1><p>Enterprise-grade cloud solutions with 99.99% uptime. Deploy globally in seconds.</p><a href="#" class="btn">Get Started Free</a></div>
<div class="features">
<div class="feature"><div style="font-size:36px">🚀</div><h3>Auto Scaling</h3><p>Automatically scale resources based on demand.</p></div>
<div class="feature"><div style="font-size:36px">🔒</div><h3>Enterprise Security</h3><p>SOC 2 Type II certified with end-to-end encryption.</p></div>
<div class="feature"><div style="font-size:36px">🌍</div><h3>Global CDN</h3><p>40+ edge locations for low-latency content delivery.</p></div>
</div>
<div class="footer">&copy; 2024 CloudMatrix Inc. All rights reserved.</div>
</body>
</html>`

// hijackedConnection wraps a hijacked HTTP connection.
type hijackedConnection struct {
	net.Conn
	transportID string
}

func (c *hijackedConnection) TransportID() string {
	return c.transportID
}
