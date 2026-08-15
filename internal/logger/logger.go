// Package logger configures the process logger.
package logger

import (
	"log/slog"
	"os"
	"strings"
)

// Configure builds the base logger and installs it as the slog default.
func Configure(level, format string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: l}
	var h slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if strings.ToLower(format) == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	}

	lg := slog.New(h)
	slog.SetDefault(lg)
	return lg
}
