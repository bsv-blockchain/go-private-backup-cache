package otel_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	sdkotel "go.opentelemetry.io/otel"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/otel"
)

func TestSetupWithoutEndpointIsInert(t *testing.T) {
	// No collector configured must mean no telemetry export and no failure — the service
	// runs exactly as before.
	shutdown, err := otel.Setup(context.Background(), "", "test-service")
	require.NoError(t, err)

	_, span := sdkotel.Tracer("test").Start(context.Background(), "op")
	require.False(t, span.IsRecording())
	span.End()

	require.NoError(t, shutdown(context.Background()))
}

func TestSetupWithEndpointExportsSpans(t *testing.T) {
	var traceRequests atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real collectors serve traces at this exact path; posting anywhere else would
		// export into the void.
		if r.Method == http.MethodPost && r.URL.Path == "/v1/traces" {
			traceRequests.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	shutdown, err := otel.Setup(context.Background(), collector.URL, "test-service")
	require.NoError(t, err)

	_, span := sdkotel.Tracer("test").Start(context.Background(), "op")
	require.True(t, span.IsRecording())
	span.End()

	// Shutdown flushes pending spans; the fake collector must have seen them.
	require.NoError(t, shutdown(context.Background()))
	require.Positive(t, traceRequests.Load())
}
