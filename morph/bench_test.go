package morph

import "testing"

func BenchmarkCalculatePadding(b *testing.B) {
	engine := NewEngine(BuiltinHTTP2Profile())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.CalculatePadding(1000)
	}
}

func BenchmarkCalculateDelay(b *testing.B) {
	engine := NewEngine(BuiltinHTTP2Profile())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.CalculateDelay()
	}
}

func BenchmarkGeneratePadding(b *testing.B) {
	engine := NewEngine(BuiltinHTTP2Profile())

	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.GeneratePadding(1400)
	}
}

func BenchmarkTimingEngine(b *testing.B) {
	te := NewTimingEngine(&BuiltinHTTP2Profile().Timing)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		te.NextDelay()
	}
}
