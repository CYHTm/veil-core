package protocol

import "testing"

func BenchmarkFrameMarshal(b *testing.B) {
	frame := NewDataFrame(1, 1, make([]byte, 1400))

	b.SetBytes(int64(len(frame.Payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame.MarshalBinary()
	}
}

func BenchmarkFrameUnmarshal(b *testing.B) {
	frame := NewDataFrame(1, 1, make([]byte, 1400))
	data, _ := frame.MarshalBinary()

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := &Frame{}
		f.UnmarshalBinary(data)
	}
}

func BenchmarkFrameWithMorphPadding(b *testing.B) {
	frame := &Frame{
		Version:  ProtocolVersion,
		Type:     FrameStreamData,
		StreamID: 1,
		Flags:    FlagMorphPadded,
		SeqNum:   1,
		Payload:  make([]byte, 1000),
		MorphPad: make([]byte, 400),
	}

	b.SetBytes(int64(len(frame.Payload) + len(frame.MorphPad)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := frame.MarshalBinary()
		f := &Frame{}
		f.UnmarshalBinary(data)
	}
}
