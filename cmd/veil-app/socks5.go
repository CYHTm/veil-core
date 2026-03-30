// Command veil-app — SOCKS5 proxy handler.
//
// This file implements the SOCKS5 proxy server that runs
// alongside the GUI, forwarding local browser traffic through
// the Veil tunnel.
package main

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"

	veilapi "github.com/veil-protocol/veil-core/api"
)

func startSOCKS5(addr string, client *veilapi.Client, vapp *VeilApp) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		vapp.broadcastLog(fmt.Sprintf("SOCKS5 ошибка: %v", err), "error")
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		vapp.mu.RLock()
		ok := vapp.connected
		vapp.mu.RUnlock()
		if !ok {
			conn.Close()
			return
		}
		go handleSOCKS5Conn(conn, client, vapp)
	}
}

func handleSOCKS5Conn(conn net.Conn, client *veilapi.Client, vapp *VeilApp) {
	defer conn.Close()

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	if buf[0] != 0x05 { return }

	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil { return }
	conn.Write([]byte{0x05, 0x00})

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil { return }
	if header[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetAddr string
	switch header[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil { return }
		targetAddr = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil { return }
		d := make([]byte, l[0])
		if _, err := io.ReadFull(conn, d); err != nil { return }
		targetAddr = string(d)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil { return }
		targetAddr = net.IP(b).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil { return }
	port := int(portBuf[0])<<8 | int(portBuf[1])
	target := fmt.Sprintf("%s:%d", targetAddr, port)

	stream, err := client.OpenStream(target)
	if err != nil {
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
				atomic.AddInt64(&vapp.totalBytes, int64(n))
				if _, we := conn.Write(b[:n]); we != nil { return }
			}
			if err != nil { return }
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		b := make([]byte, 32*1024)
		for {
			n, err := conn.Read(b)
			if n > 0 {
				atomic.AddInt64(&vapp.totalBytes, int64(n))
				if _, we := stream.Write(b[:n]); we != nil { return }
			}
			if err != nil { return }
		}
	}()

	<-done
	stream.Close()
}
