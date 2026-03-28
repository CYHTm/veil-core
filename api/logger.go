package api

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// LogLevel controls verbosity.
type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
	LogSilent
)

// Logger provides leveled logging.
type Logger struct {
	mu     sync.Mutex
	level  LogLevel
	writer io.Writer
	prefix string
}

// NewLogger creates a logger with given level.
func NewLogger(prefix string, level LogLevel) *Logger {
	return &Logger{
		level:  level,
		writer: os.Stdout,
		prefix: prefix,
	}
}

// SetLevel changes the log level.
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput changes the output writer.
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer = w
}

func (l *Logger) log(level LogLevel, tag string, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.writer, "%s %s[%s] %s\n", ts, l.prefix, tag, msg)
}

// Debug logs at debug level.
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LogDebug, "DBG", format, args...)
}

// Info logs at info level.
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LogInfo, "INF", format, args...)
}

// Warn logs at warning level.
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LogWarn, "WRN", format, args...)
}

// Error logs at error level.
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LogError, "ERR", format, args...)
}

// Printf implements the standard logger interface (for compatibility).
func (l *Logger) Printf(format string, args ...interface{}) {
	l.Info(format, args...)
}
