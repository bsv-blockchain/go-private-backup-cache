// Package logger configures the process logger.
package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel/trace"
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

	lg := slog.New(WithTraceContext(h))
	slog.SetDefault(lg)
	return lg
}

// WithTraceContext stamps trace_id and span_id onto every record logged inside a traced
// request, so log lines can be joined to their trace in the backend. Untraced contexts
// pass through untouched.
func WithTraceContext(h slog.Handler) slog.Handler {
	return traceHandler{Handler: h}
}

type traceHandler struct{ slog.Handler }

func (t traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return t.Handler.Handle(ctx, r)
}

func (t traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceHandler{Handler: t.Handler.WithAttrs(attrs)}
}

func (t traceHandler) WithGroup(name string) slog.Handler {
	return traceHandler{Handler: t.Handler.WithGroup(name)}
}
