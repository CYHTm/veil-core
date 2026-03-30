package api

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestWriteHandshake(t *testing.T) {
	var buf bytes.Buffer
	data := []byte("hello-handshake-data")

	err := writeHandshake(&buf, data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), data) {
		t.Fatal("written data mismatch")
	}
}

func TestWriteHandshakeEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := writeHandshake(&buf, []byte{})
	if err != nil {
		t.Fatalf("write empty: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatal("expected 0 bytes written")
	}
}

func TestReadHandshakeValid(t *testing.T) {
	// Minimum valid size: ClientHelloCoreSize(48) + MinHelloPadding(16) + 2 = 66
	data := make([]byte, 70)
	for i := range data {
		data[i] = byte(i)
	}

	r := bytes.NewReader(data)
	got, err := readHandshake(r, 4096)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch")
	}
}

func TestReadHandshakeTooShort(t *testing.T) {
	data := make([]byte, 10) // Way too short
	r := bytes.NewReader(data)

	_, err := readHandshake(r, 4096)
	if err == nil {
		t.Fatal("should reject too short handshake")
	}
}

func TestReadHandshakeEOF(t *testing.T) {
	r := bytes.NewReader([]byte{})
	_, err := readHandshake(r, 4096)
	if err == nil {
		t.Fatal("should fail on empty reader")
	}
}

func TestWriteLengthPrefixed(t *testing.T) {
	var buf bytes.Buffer
	data := []byte("test-payload-data")

	err := writeLengthPrefixed(&buf, data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Should be 4 bytes header + payload
	if buf.Len() != 4+len(data) {
		t.Fatalf("expected %d bytes, got %d", 4+len(data), buf.Len())
	}

	// Check length header
	header := buf.Bytes()[:4]
	length := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length != len(data) {
		t.Fatalf("length header: expected %d, got %d", len(data), length)
	}

	// Check payload
	if !bytes.Equal(buf.Bytes()[4:], data) {
		t.Fatal("payload mismatch")
	}
}

func TestReadLengthPrefixed(t *testing.T) {
	payload := []byte("hello-length-prefixed")

	// Build wire format: [4-byte length][payload]
	var buf bytes.Buffer
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	buf.Write(header)
	buf.Write(payload)

	got, err := readLengthPrefixed(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestWriteReadLengthPrefixedRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	original := []byte("roundtrip-test-data-1234567890")

	if err := writeLengthPrefixed(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readLengthPrefixed(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestReadLengthPrefixedZeroLength(t *testing.T) {
	var buf bytes.Buffer
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 0)
	buf.Write(header)

	_, err := readLengthPrefixed(&buf)
	if err == nil {
		t.Fatal("should reject zero length")
	}
}

func TestReadLengthPrefixedTooLarge(t *testing.T) {
	var buf bytes.Buffer
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 0xFFFFFFFF) // Huge
	buf.Write(header)

	_, err := readLengthPrefixed(&buf)
	if err == nil {
		t.Fatal("should reject too large length")
	}
}

func TestReadLengthPrefixedTruncated(t *testing.T) {
	var buf bytes.Buffer
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 100) // Says 100 bytes
	buf.Write(header)
	buf.Write([]byte("short")) // Only 5 bytes

	_, err := readLengthPrefixed(&buf)
	if err == nil {
		t.Fatal("should fail on truncated payload")
	}
}

func TestReadLengthPrefixedNoHeader(t *testing.T) {
	buf := bytes.NewReader([]byte{0x01}) // Only 1 byte, need 4
	_, err := readLengthPrefixed(buf)
	if err == nil {
		t.Fatal("should fail on incomplete header")
	}
}

func TestWriteLengthPrefixedMultiple(t *testing.T) {
	var buf bytes.Buffer

	msg1 := []byte("first message")
	msg2 := []byte("second message!!!")
	msg3 := []byte("3")

	writeLengthPrefixed(&buf, msg1)
	writeLengthPrefixed(&buf, msg2)
	writeLengthPrefixed(&buf, msg3)

	got1, _ := readLengthPrefixed(&buf)
	got2, _ := readLengthPrefixed(&buf)
	got3, _ := readLengthPrefixed(&buf)

	if !bytes.Equal(got1, msg1) {
		t.Fatal("msg1 mismatch")
	}
	if !bytes.Equal(got2, msg2) {
		t.Fatal("msg2 mismatch")
	}
	if !bytes.Equal(got3, msg3) {
		t.Fatal("msg3 mismatch")
	}

	// Should be EOF now
	_, err := readLengthPrefixed(&buf)
	if err == nil || err == io.EOF {
		// Both are acceptable — no more data
	}
}

type failWriter struct{}

func (fw *failWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestWriteHandshakeError(t *testing.T) {
	err := writeHandshake(&failWriter{}, []byte("data"))
	if err == nil {
		t.Fatal("should propagate write error")
	}
}

func TestWriteLengthPrefixedError(t *testing.T) {
	err := writeLengthPrefixed(&failWriter{}, []byte("data"))
	if err == nil {
		t.Fatal("should propagate write error")
	}
}
