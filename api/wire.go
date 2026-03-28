package api

import (
	"fmt"
	"io"

	"github.com/veil-protocol/veil-core/protocol"
)

// writeHandshake writes raw handshake bytes (already length-prefixed internally).
func writeHandshake(w io.Writer, data []byte) error {
	_, err := w.Write(data)
	return err
}

// readHandshake reads a variable-length handshake message.
// Reads up to maxSize bytes. The handshake self-describes its length.
func readHandshake(r io.Reader, maxSize int) ([]byte, error) {
	buf := make([]byte, maxSize)
	// Read as much as available (handshake is one TCP segment typically)
	n, err := r.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	if n < protocol.ClientHelloCoreSize+protocol.MinHelloPadding+2 {
		return nil, fmt.Errorf("handshake too short: %d bytes", n)
	}
	return buf[:n], nil
}

// writeLengthPrefixed writes [4-byte length][data] for post-handshake messages.
func writeLengthPrefixed(w io.Writer, data []byte) error {
	header := []byte{
		byte(len(data) >> 24), byte(len(data) >> 16),
		byte(len(data) >> 8), byte(len(data)),
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// readLengthPrefixed reads [4-byte length][data].
func readLengthPrefixed(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length <= 0 || length > protocol.MaxPayloadSize {
		return nil, fmt.Errorf("invalid length: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}
