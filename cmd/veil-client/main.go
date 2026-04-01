// Command veil-client runs the Veil Protocol CLI client.
//
// It connects to a Veil server, establishes an encrypted tunnel,
// and exposes a local SOCKS5 proxy for browser traffic.
// Supports morph profile selection and config files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/veil-protocol/veil-core/api"
	"github.com/veil-protocol/veil-core/morph"
)

type ClientFileConfig struct {
	Server    string `json:"server"`
	Secret    string `json:"secret"`
	Transport string `json:"transport"`
	SNI       string `json:"sni"`
	Cipher    string `json:"cipher"`
	Morph     string `json:"morph"`
	Socks     string `json:"socks"`
	Insecure  bool   `json:"insecure"`
}

var (
	totalConnections int64
	activeStreams    int64
	totalBytes       int64
)

func main() {
	configFile := flag.String("config", "", "Path to config file (JSON)")
	serverAddr := flag.String("server", "", "Veil server address")
	secret := flag.String("secret", "", "Pre-shared secret")
	transportType := flag.String("transport", "raw", "Transport: raw, tls, wss, quic")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 address")
	sni := flag.String("sni", "", "TLS SNI override")
	cipher := flag.String("cipher", "chacha20-poly1305", "Cipher")
	morphProfile := flag.String("morph", "http2_browsing", "Morph profile")
	insecure := flag.Bool("insecure", false, "Skip TLS verify (testing)")
	dnsAddr := flag.String("dns", "", "Local DNS proxy address (e.g., 127.0.0.1:5353) — prevents DNS leaks")

	listProfiles := flag.Bool("list-profiles", false, "List available morph profiles")
	flag.Parse()

	if *listProfiles {
		fmt.Println("Available morph profiles:")
		fmt.Println()
		for _, p := range morph.ListBuiltinProfiles() {
			fmt.Printf("  %-22s  %s\n", p.Name, p.Description)
		}
		fmt.Println()
		fmt.Println("Use: veil-client -morph <profile-name>")
		fmt.Println("Or:  veil-client -morph /path/to/custom.json")
		os.Exit(0)
	}


	if *configFile != "" {
		fc, err := loadClientConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		if fc.Server != "" && *serverAddr == "" {
			*serverAddr = fc.Server
		}
		if fc.Secret != "" && *secret == "" {
			*secret = fc.Secret
		}
		if fc.Transport != "" && *transportType == "raw" {
			*transportType = fc.Transport
		}
		if fc.Socks != "" && *socksAddr == "127.0.0.1:1080" {
			*socksAddr = fc.Socks
		}
		if fc.SNI != "" && *sni == "" {
			*sni = fc.SNI
		}
		if fc.Cipher != "" && *cipher == "chacha20-poly1305" {
			*cipher = fc.Cipher
		}
		if fc.Morph != "" && *morphProfile == "http2_browsing" {
			*morphProfile = fc.Morph
		}
		if fc.Insecure {
			*insecure = true
		}
	}

	if *serverAddr == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "Error: server and secret are required")
		fmt.Fprintln(os.Stderr, "  veil-client -server IP:PORT -secret \"your-secret\"")
		fmt.Fprintln(os.Stderr, "  veil-client -config client.json")
		os.Exit(1)
	}

	config := api.ClientConfig{
		ServerAddr:         *serverAddr,
		Secret:             *secret,
		Transport:          *transportType,
		SNI:                *sni,
		Cipher:             *cipher,
		MorphProfile:       *morphProfile,
		InsecureSkipVerify: *insecure,
		DNSListenAddr:     *dnsAddr,
		OnConnect: func() {
			log.Println("✅ Connected to Veil server")
		},
		OnDisconnect: func(err error) {
			log.Printf("🔌 Disconnected: %v", err)
		},
	}

	client, err := api.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	client.Events().On(api.EventHandshakeOK, func(e api.Event) {
		log.Printf("🤝 Handshake complete (session: %x)", e.SessionID[:4])
	})

	log.Printf("🔄 Connecting to %s via %s...", *serverAddr, *transportType)
	if err := client.Connect(); err != nil {
		log.Fatalf("❌ Connection failed: %v", err)
	}

	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════╗")
	fmt.Println("  ║           🛡️  Veil Protocol Client            ║")
	fmt.Println("  ╠══════════════════════════════════════════════╣")
	fmt.Printf("  ║  Server:    %-32s ║\n", *serverAddr)
	fmt.Printf("  ║  Transport: %-32s ║\n", *transportType)
	fmt.Printf("  ║  Cipher:    %-32s ║\n", *cipher)
	fmt.Printf("  ║  Morph:     %-32s ║\n", *morphProfile)
	fmt.Printf("  ║  SOCKS5:    %-32s ║\n", *socksAddr)
	if *dnsAddr != "" {
		fmt.Printf("  ║  DNS Proxy: %-32s ║\n", *dnsAddr)
	}
	fmt.Println("  ╠══════════════════════════════════════════════╣")
	fmt.Println("  ║  Status: ✅  CONNECTED                       ║")
	fmt.Println("  ║                                              ║")
	fmt.Println("  ║  Настрой браузер на SOCKS5 прокси:           ║")
	fmt.Printf("  ║    -> %-38s ║\n", *socksAddr)
	fmt.Println("  ║                                              ║")
	fmt.Println("  ║  Press Ctrl+C to disconnect                  ║")
	fmt.Println("  ╚══════════════════════════════════════════════╝")
	fmt.Println()

	go startSOCKS5Proxy(*socksAddr, client)

	if *dnsAddr != "" {
		dnsOpener := func(target string) (io.ReadWriteCloser, error) {
			return client.OpenStream(target)
		}
		dnsProxy := api.NewDNSProxy(*dnsAddr, "", dnsOpener, nil)
		if err := dnsProxy.Start(); err != nil {
			log.Fatalf("❌ DNS proxy failed: %v", err)
		}
		defer dnsProxy.Close()
		log.Printf("🛡  DNS leak protection active on %s", *dnsAddr)
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			tc := atomic.LoadInt64(&totalConnections)
			as := atomic.LoadInt64(&activeStreams)
			tb := atomic.LoadInt64(&totalBytes)
			log.Printf("📊 Connections: %d | Active: %d | Transferred: %s",
				tc, as, formatBytes(tb))
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n⏳ Disconnecting...")
	client.Close()

	tc := atomic.LoadInt64(&totalConnections)
	tb := atomic.LoadInt64(&totalBytes)
	fmt.Printf("📊 Total: %d connections, %s transferred\n", tc, formatBytes(tb))
	fmt.Println("✅ Client stopped.")
}

func loadClientConfig(path string) (*ClientFileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ClientFileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	} else if b < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
}

func startSOCKS5Proxy(addr string, client *api.Client) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("SOCKS5 listen failed: %v", err)
	}
	defer ln.Close()
	log.Printf("🧦 SOCKS5 proxy listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSOCKS5(conn, client)
	}
}

func handleSOCKS5(conn net.Conn, client *api.Client) {
	defer conn.Close()

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00})

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetAddr string
	switch header[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		targetAddr = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		targetAddr = string(domainBuf)
	case 0x04:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		targetAddr = net.IP(ipBuf).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	target := fmt.Sprintf("%s:%d", targetAddr, port)

	atomic.AddInt64(&totalConnections, 1)
	atomic.AddInt64(&activeStreams, 1)
	defer atomic.AddInt64(&activeStreams, -1)

	log.Printf("🔗 %s", target)

	stream, err := client.OpenStream(target)
	if err != nil {
		log.Printf("❌ Stream failed: %v", err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		b := make([]byte, 32*1024)
		for {
			n, err := stream.Read(b)
			if n > 0 {
				atomic.AddInt64(&totalBytes, int64(n))
				if _, we := conn.Write(b[:n]); we != nil {
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
		b := make([]byte, 32*1024)
		for {
			n, err := conn.Read(b)
			if n > 0 {
				atomic.AddInt64(&totalBytes, int64(n))
				if _, we := stream.Write(b[:n]); we != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	stream.Close()
}
