package crypto

import (
	"testing"
)

func TestZeroize(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	Zeroize(data)

	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: 0x%02x", i, b)
		}
	}
}

func TestZeroizeEmpty(t *testing.T) {
	data := []byte{}
	Zeroize(data) // should not panic
}

func TestSecureBufferCreate(t *testing.T) {
	sb := NewSecureBuffer(32)
	if len(sb.Bytes()) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(sb.Bytes()))
	}
}

func TestSecureBufferCopy(t *testing.T) {
	sb := NewSecureBuffer(4)
	sb.Copy([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	b := sb.Bytes()
	if b[0] != 0xDE || b[1] != 0xAD || b[2] != 0xBE || b[3] != 0xEF {
		t.Fatal("copy did not work")
	}
}

func TestSecureBufferDestroy(t *testing.T) {
	sb := NewSecureBuffer(4)
	sb.Copy([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	sb.Destroy()

	for i, b := range sb.Bytes() {
		if b != 0 {
			t.Fatalf("byte %d not zeroed after Destroy: 0x%02x", i, b)
		}
	}
}

func TestSecureBufferDestroyTwice(t *testing.T) {
	sb := NewSecureBuffer(16)
	sb.Destroy()
	sb.Destroy() // should not panic
}

func TestZeroizeLargeBuffer(t *testing.T) {
	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = 0xFF
	}
	Zeroize(data)

	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed in large buffer", i)
		}
	}
}
