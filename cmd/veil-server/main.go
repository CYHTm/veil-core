package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/veil-protocol/veil-core/api"
)

type ServerFileConfig struct {
	Listen        string   `json:"listen"`
	Secret        string   `json:"secret"`
	Transport     string   `json:"transport"`
	CertFile      string   `json:"cert_file"`
	KeyFile       string   `json:"key_file"`
	Cipher        string   `json:"cipher"`
	MaxStreams     int      `json:"max_streams"`
	MorphProfiles []string `json:"morph_profiles"`
}

func main() {
	configFile := flag.String("config", "", "Path to config file (JSON)")
	listenAddr := flag.String("listen", ":8443", "Listen address")
	secret := flag.String("secret", "", "Pre-shared secret")
	transportType := flag.String("transport", "raw", "Transport: raw, tls, wss")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS private key file")
	cipher := flag.String("cipher", "chacha20-poly1305", "Cipher")
	maxStreams := flag.Int("max-streams", 256, "Max concurrent streams")

	flag.Parse()

	if *configFile != "" {
		fc, err := loadServerConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		if fc.Listen != "" && *listenAddr == ":8443" {
			*listenAddr = fc.Listen
		}
		if fc.Secret != "" && *secret == "" {
			*secret = fc.Secret
		}
		if fc.Transport != "" && *transportType == "raw" {
			*transportType = fc.Transport
		}
		if fc.CertFile != "" && *certFile == "" {
			*certFile = fc.CertFile
		}
		if fc.KeyFile != "" && *keyFile == "" {
			*keyFile = fc.KeyFile
		}
		if fc.Cipher != "" && *cipher == "chacha20-poly1305" {
			*cipher = fc.Cipher
		}
		if fc.MaxStreams > 0 && *maxStreams == 256 {
			*maxStreams = fc.MaxStreams
		}
	}

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "Error: secret is required (-secret or in config file)")
		fmt.Fprintln(os.Stderr, "  veil-server -secret \"your-secret\"")
		fmt.Fprintln(os.Stderr, "  veil-server -config server.json")
		os.Exit(1)
	}

	config := api.ServerConfig{
		ListenAddr: *listenAddr,
		Secret:     *secret,
		Transport:  *transportType,
		CertFile:   *certFile,
		KeyFile:    *keyFile,
		Cipher:     *cipher,
		MaxStreams:  uint16(*maxStreams),
		OnClientConnect: func(addr string) {
			log.Printf("📡 Client connected: %s", addr)
		},
		OnClientDisconnect: func(addr string) {
			log.Printf("🔌 Client disconnected: %s", addr)
		},
		OnStreamOpen: func(clientAddr, target string) {
			log.Printf("🔗 Stream: %s -> %s", clientAddr, target)
		},
	}

	server, err := api.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	server.Events().On(api.EventHandshakeOK, func(e api.Event) {
		log.Printf("🤝 Handshake OK (session: %x)", e.SessionID[:4])
	})
	server.Events().On(api.EventError, func(e api.Event) {
		log.Printf("❌ Error: %v", e.Error)
	})

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════╗")
	fmt.Println("  ║           🛡️  Veil Protocol Server            ║")
	fmt.Println("  ╠══════════════════════════════════════════════╣")
	fmt.Printf("  ║  Listen:      %-30s ║\n", *listenAddr)
	fmt.Printf("  ║  Transport:   %-30s ║\n", *transportType)
	fmt.Printf("  ║  Cipher:      %-30s ║\n", *cipher)
	fmt.Printf("  ║  Max Streams: %-30d ║\n", *maxStreams)
	fmt.Println("  ╠══════════════════════════════════════════════╣")
	fmt.Println("  ║  Status: ✅  RUNNING                         ║")
	fmt.Println("  ║  Press Ctrl+C to stop                        ║")
	fmt.Println("  ╚══════════════════════════════════════════════╝")
	fmt.Println()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("📊 Active sessions: %d", server.ActiveSessions())
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n⏳ Shutting down...")
	server.Stop()
	fmt.Println("✅ Server stopped.")
}

func loadServerConfig(path string) (*ServerFileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ServerFileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
