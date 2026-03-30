// Package protocol implements the Veil wire protocol.
//
// This file defines frame types, encoding, and decoding for the
// binary protocol used between Veil client and server.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrFrameTooLarge  = errors.New("veil: frame payload exceeds maximum size")
	ErrInvalidFrame   = errors.New("veil: invalid frame format")
	ErrInvalidVersion = errors.New("veil: unsupported protocol version")
	ErrAuthFailed     = errors.New("veil: AEAD authentication failed")
	ErrStreamNotFound = errors.New("veil: stream not found")
	ErrSessionClosed  = errors.New("veil: session is closed")
)

// Frame represents a single Veil protocol frame.
type Frame struct {
	Version  uint8
	Type     FrameType
	StreamID uint16
	Flags    FrameFlags
	SeqNum   uint32
	Payload  []byte
	MorphPad []byte // Padding added by the morph engine (wire only)
}

// MarshalBinary serializes the frame into wire format.
//
// When FlagMorphPadded is set, the wire payload is structured as:
//   [real_payload_len (3 bytes)][real_payload][morph_padding]
// This allows the receiver to strip padding and recover the real payload.
func (f *Frame) MarshalBinary() ([]byte, error) {
	realLen := len(f.Payload)
	padLen := len(f.MorphPad)

	// Calculate total payload on wire
	prefixLen := 0
	if padLen > 0 {
		prefixLen = 3 // 3 bytes to store real payload length
	}
	totalPayload := prefixLen + realLen + padLen

	if totalPayload > MaxPayloadSize {
		return nil, ErrFrameTooLarge
	}

	buf := make([]byte, FrameHeaderSize+totalPayload)

	// Header
	buf[0] = f.Version
	buf[1] = byte(f.Type)
	binary.BigEndian.PutUint16(buf[2:4], f.StreamID)

	// PayloadLength: 3 bytes big-endian (total including prefix and padding)
	buf[4] = byte(totalPayload >> 16)
	buf[5] = byte(totalPayload >> 8)
	buf[6] = byte(totalPayload)

	buf[7] = byte(f.Flags)
	binary.BigEndian.PutUint32(buf[8:12], f.SeqNum)

	// Payload area
	offset := FrameHeaderSize

	if padLen > 0 {
		// Write real payload length prefix so receiver can strip padding
		buf[offset] = byte(realLen >> 16)
		buf[offset+1] = byte(realLen >> 8)
		buf[offset+2] = byte(realLen)
		offset += 3
	}

	copy(buf[offset:], f.Payload)
	offset += realLen

	if padLen > 0 {
		copy(buf[offset:], f.MorphPad)
	}

	return buf, nil
}

// UnmarshalBinary deserializes a frame from wire format.
// If FlagMorphPadded is set, strips padding and recovers real payload.
func (f *Frame) UnmarshalBinary(data []byte) error {
	if len(data) < FrameHeaderSize {
		return ErrInvalidFrame
	}

	f.Version = data[0]
	if f.Version != ProtocolVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrInvalidVersion, f.Version, ProtocolVersion)
	}

	f.Type = FrameType(data[1])
	f.StreamID = binary.BigEndian.Uint16(data[2:4])

	totalPayload := int(data[4])<<16 | int(data[5])<<8 | int(data[6])
	if totalPayload > MaxPayloadSize {
		return ErrFrameTooLarge
	}

	f.Flags = FrameFlags(data[7])
	f.SeqNum = binary.BigEndian.Uint32(data[8:12])

	if len(data) < FrameHeaderSize+totalPayload {
		return ErrInvalidFrame
	}

	// Extract payload — strip morph padding if present
	if f.Flags&FlagMorphPadded != 0 && totalPayload >= 3 {
		// First 3 bytes = real payload length
		realLen := int(data[FrameHeaderSize])<<16 | int(data[FrameHeaderSize+1])<<8 | int(data[FrameHeaderSize+2])

		if realLen > totalPayload-3 {
			return ErrInvalidFrame
		}

		// Only extract real payload, discard padding
		f.Payload = make([]byte, realLen)
		copy(f.Payload, data[FrameHeaderSize+3:FrameHeaderSize+3+realLen])
	} else {
		// No padding — payload is everything
		f.Payload = make([]byte, totalPayload)
		copy(f.Payload, data[FrameHeaderSize:FrameHeaderSize+totalPayload])
	}

	return nil
}

// NewDataFrame creates a new data frame for a given stream.
func NewDataFrame(streamID uint16, seqNum uint32, payload []byte) *Frame {
	return &Frame{
		Version:  ProtocolVersion,
		Type:     FrameStreamData,
		StreamID: streamID,
		SeqNum:   seqNum,
		Payload:  payload,
	}
}

// NewStreamOpenFrame creates a frame to open a new stream.
func NewStreamOpenFrame(streamID uint16, targetAddr string) *Frame {
	return &Frame{
		Version:  ProtocolVersion,
		Type:     FrameStreamOpen,
		StreamID: streamID,
		SeqNum:   0,
		Payload:  []byte(targetAddr),
	}
}

// NewKeepaliveFrame creates a keepalive frame.
func NewKeepaliveFrame() *Frame {
	return &Frame{
		Version: ProtocolVersion,
		Type:    FrameKeepalive,
	}
}

// NewSessionCloseFrame creates a session close frame.
func NewSessionCloseFrame() *Frame {
	return &Frame{
		Version: ProtocolVersion,
		Type:    FrameSessionClose,
		Flags:   FlagFinal,
	}
}

// FrameReader reads frames from an io.Reader.
type FrameReader struct {
	reader io.Reader
}

func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{reader: r}
}

func (fr *FrameReader) ReadFrame() (*Frame, error) {
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(fr.reader, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	payloadLen := int(header[4])<<16 | int(header[5])<<8 | int(header[6])
	if payloadLen > MaxPayloadSize {
		return nil, ErrFrameTooLarge
	}

	fullFrame := make([]byte, FrameHeaderSize+payloadLen)
	copy(fullFrame, header)

	if payloadLen > 0 {
		if _, err := io.ReadFull(fr.reader, fullFrame[FrameHeaderSize:]); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	frame := &Frame{}
	if err := frame.UnmarshalBinary(fullFrame); err != nil {
		return nil, err
	}

	return frame, nil
}

// FrameWriter writes frames to an io.Writer.
type FrameWriter struct {
	writer io.Writer
}

func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{writer: w}
}

func (fw *FrameWriter) WriteFrame(f *Frame) error {
	data, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = fw.writer.Write(data)
	return err
}
