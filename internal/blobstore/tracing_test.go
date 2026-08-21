package blobstore_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
)

func withSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	return rec
}

func TestWithTracingSpansAppend(t *testing.T) {
	rec := withSpanRecorder(t)
	store := blobstore.WithTracing(blobstore.NewMemoryStore())

	k := blobstore.BlobKey{Pseudonym: "pseud", DeviceID: "dev", Generation: 1, Seq: 1}
	_, n, err := store.Append(context.Background(), k, "", strings.NewReader("payload"))
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), n)

	spans := rec.Ended()
	require.Len(t, spans, 1)
	require.Equal(t, "blobstore.Append", spans[0].Name())

	// The blob size is worth having on the span; the pseudonym must NOT be — telemetry
	// backends are outside this service's zero-knowledge boundary.
	attrs := attribute.NewSet(spans[0].Attributes()...)
	size, ok := attrs.Value("blob.bytes")
	require.True(t, ok)
	require.EqualValues(t, len("payload"), size.AsInt64())
	for _, kv := range spans[0].Attributes() {
		require.NotContains(t, kv.Value.Emit(), "pseud")
	}
}

func TestWithTracingMarksErrors(t *testing.T) {
	rec := withSpanRecorder(t)
	store := blobstore.WithTracing(blobstore.NewMemoryStore())

	// Sequence 5 on an empty store violates append-only ordering and must fail.
	k := blobstore.BlobKey{Pseudonym: "p", DeviceID: "d", Generation: 1, Seq: 5}
	_, _, err := store.Append(context.Background(), k, "", strings.NewReader("x"))
	require.Error(t, err)

	spans := rec.Ended()
	require.Len(t, spans, 1)
	require.Equal(t, otelcodes.Error, spans[0].Status().Code)
}

func TestWithTracingSpansGet(t *testing.T) {
	rec := withSpanRecorder(t)
	store := blobstore.WithTracing(blobstore.NewMemoryStore())

	k := blobstore.BlobKey{Pseudonym: "p", DeviceID: "d", Generation: 1, Seq: 1}
	_, _, err := store.Append(context.Background(), k, "", strings.NewReader("payload"))
	require.NoError(t, err)

	rc, _, err := store.Get(context.Background(), k)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	names := make([]string, 0, 2)
	for _, s := range rec.Ended() {
		names = append(names, s.Name())
	}
	require.Contains(t, names, "blobstore.Get")
}
