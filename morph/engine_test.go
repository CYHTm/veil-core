package morph

import (
	"testing"
)

func TestMorphPadding(t *testing.T) {
	engine := NewEngine(BuiltinHTTP2Profile())

	// Паддинг должен быть >= 0
	for i := 0; i < 100; i++ {
		pad := engine.CalculatePadding(500)
		if pad < 0 {
			t.Errorf("padding is negative: %d", pad)
		}
	}
}

func TestMorphPaddingDistribution(t *testing.T) {
	engine := NewEngine(BuiltinHTTP2Profile())

	// Проверяем что размеры после паддинга разнообразны
	sizes := make(map[int]bool)
	for i := 0; i < 100; i++ {
		pad := engine.CalculatePadding(200)
		total := 200 + pad
		sizes[total] = true
	}

	// Должно быть больше 1 уникального размера
	if len(sizes) < 3 {
		t.Errorf("padding not diverse enough: only %d unique sizes", len(sizes))
	}
}

func TestMorphDelay(t *testing.T) {
	engine := NewEngine(BuiltinHTTP2Profile())

	hasNonZero := false
	for i := 0; i < 50; i++ {
		delay := engine.CalculateDelay()
		if delay < 0 {
			t.Error("delay is negative")
		}
		if delay > 0 {
			hasNonZero = true
		}
	}

	if !hasNonZero {
		t.Error("all delays are zero — jitter not working")
	}
}

func TestMorphGeneratePadding(t *testing.T) {
	engine := NewEngine(BuiltinHTTP2Profile())

	pad := engine.GeneratePadding(1000)
	if len(pad) != 1000 {
		t.Errorf("padding length: got %d, want 1000", len(pad))
	}

	// Проверяем что не все байты одинаковые
	allSame := true
	for i := 1; i < len(pad); i++ {
		if pad[i] != pad[0] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("padding bytes are all the same")
	}
}

func TestNilProfile(t *testing.T) {
	engine := NewEngine(nil)

	// Не должно паниковать
	pad := engine.CalculatePadding(100)
	if pad != 0 {
		t.Error("nil profile should produce zero padding")
	}

	delay := engine.CalculateDelay()
	if delay != 0 {
		t.Error("nil profile should produce zero delay")
	}
}

func TestVideoProfile(t *testing.T) {
	profile := BuiltinVideoProfile()
	if profile.Name != "video_streaming" {
		t.Errorf("name: got %q, want 'video_streaming'", profile.Name)
	}

	engine := NewEngine(profile)

	// Видео-профиль должен давать размеры ближе к MTU
	bigCount := 0
	for i := 0; i < 100; i++ {
		pad := engine.CalculatePadding(1000)
		total := 1000 + pad
		if total >= 1200 {
			bigCount++
		}
	}

	if bigCount < 30 {
		t.Errorf("video profile should prefer large packets, got %d/100 >= 1200", bigCount)
	}
}
