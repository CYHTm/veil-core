package api

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger("test:", LogDebug)
	l.SetOutput(&buf)

	l.Debug("debug msg")
	l.Info("info msg")
	l.Warn("warn msg")
	l.Error("error msg")

	output := buf.String()
	if !strings.Contains(output, "[DBG]") {
		t.Fatal("missing debug output")
	}
	if !strings.Contains(output, "[INF]") {
		t.Fatal("missing info output")
	}
	if !strings.Contains(output, "[WRN]") {
		t.Fatal("missing warn output")
	}
	if !strings.Contains(output, "[ERR]") {
		t.Fatal("missing error output")
	}
}

func TestLoggerLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger("test:", LogWarn)
	l.SetOutput(&buf)

	l.Debug("should not appear")
	l.Info("should not appear")
	l.Warn("should appear")
	l.Error("should appear")

	output := buf.String()
	if strings.Contains(output, "[DBG]") {
		t.Fatal("debug should be filtered")
	}
	if strings.Contains(output, "[INF]") {
		t.Fatal("info should be filtered")
	}
	if !strings.Contains(output, "[WRN]") {
		t.Fatal("warn should appear")
	}
	if !strings.Contains(output, "[ERR]") {
		t.Fatal("error should appear")
	}
}

func TestLoggerSilent(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger("test:", LogSilent)
	l.SetOutput(&buf)

	l.Debug("no")
	l.Info("no")
	l.Warn("no")
	l.Error("no")

	if buf.Len() != 0 {
		t.Fatalf("silent logger should produce no output, got: %s", buf.String())
	}
}

func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger("test:", LogSilent)
	l.SetOutput(&buf)

	l.Info("invisible")
	if buf.Len() != 0 {
		t.Fatal("should be silent")
	}

	l.SetLevel(LogInfo)
	l.Info("visible")
	if !strings.Contains(buf.String(), "visible") {
		t.Fatal("should be visible after SetLevel")
	}
}

func TestLoggerPrefix(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger("veil:", LogDebug)
	l.SetOutput(&buf)

	l.Info("hello")
	if !strings.Contains(buf.String(), "veil:") {
		t.Fatal("output should contain prefix")
	}
}

func TestLoggerPrintf(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger("test:", LogInfo)
	l.SetOutput(&buf)

	l.Printf("formatted %d", 42)
	if !strings.Contains(buf.String(), "formatted 42") {
		t.Fatal("Printf should work like Info")
	}
}

func TestLoggerFormatArgs(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger("", LogDebug)
	l.SetOutput(&buf)

	l.Error("code=%d msg=%s", 404, "not found")
	if !strings.Contains(buf.String(), "code=404 msg=not found") {
		t.Fatalf("format args not applied: %s", buf.String())
	}
}
