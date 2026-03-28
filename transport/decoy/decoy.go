package decoy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
	"github.com/veil-protocol/veil-core/transport"

	utls "github.com/refraction-networking/utls"
)

type Transport struct{}

func New() *Transport {
	return &Transport{}
}

func (t *Transport) ID() string {
	return "decoy"
}

func (t *Transport) Dial(ctx context.Context, addr string, config *transport.Config) (transport.Connection, error) {
	timeout := 15 * time.Second
	if config != nil && config.ConnectTimeout > 0 {
		timeout = config.ConnectTimeout
	}

	sni := ""
	if config != nil && config.SNI != "" {
		sni = config.SNI
	} else {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		sni = host
	}

	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: config != nil && config.InsecureSkipVerify,
	}

	tlsConn := utls.UClient(tcpConn, tlsConfig, utls.HelloChrome_Auto)
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	secret := ""
	if config != nil {
		if s, ok := config.Headers["secret"]; ok {
			secret = s
		}
	}

	trigger := veilcrypto.NewStegTrigger(secret)
	cookieName, cookieValue := trigger.GenerateHTTPCookieTrigger()
	headerName, headerValue := trigger.GenerateHTTPHeaderTrigger()

	path := "/"
	if config != nil && config.Path != "" {
		path = config.Path
	}

	reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"+
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
		"%s: %s\r\n"+
		"Cookie: %s=%s\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+
		"\r\n",
		path, sni, headerName, headerValue, cookieName, cookieValue)

	if _, err := tlsConn.Write([]byte(reqStr)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("send trigger: %w", err)
	}

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 101 {
		tlsConn.Close()
		return nil, fmt.Errorf("trigger rejected (status %d)", resp.StatusCode)
	}

	return &decoyConnection{Conn: tlsConn, reader: reader}, nil
}

func (t *Transport) Listen(ctx context.Context, addr string, config *transport.Config) (transport.Listener, error) {
	return nil, fmt.Errorf("decoy transport: use DecoyServer for listening")
}

type decoyConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (c *decoyConnection) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *decoyConnection) TransportID() string {
	return "decoy"
}
