package logger_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/logger"
)

func TestTraceCorrelationAddsTraceAndSpanIDs(t *testing.T) {
	// Every log line written inside a traced request must carry the trace ID, or logs and
	// traces cannot be joined in the backend.
	var buf bytes.Buffer
	h := logger.WithTraceContext(slog.NewJSONHandler(&buf, nil))
	log := slog.New(h)

	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	defer span.End()

	log.InfoContext(ctx, "hello")

	var line map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &line))
	require.Equal(t, span.SpanContext().TraceID().String(), line["trace_id"])
	require.Equal(t, span.SpanContext().SpanID().String(), line["span_id"])
}

func TestTraceCorrelationSkipsUntracedContext(t *testing.T) {
	var buf bytes.Buffer
	h := logger.WithTraceContext(slog.NewJSONHandler(&buf, nil))
	slog.New(h).InfoContext(context.Background(), "hello")

	var line map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &line))
	require.NotContains(t, line, "trace_id")
	require.NotContains(t, line, "span_id")
}
