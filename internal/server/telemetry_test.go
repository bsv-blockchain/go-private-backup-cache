package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server"
)

// telemetryHarness routes one request through the telemetry middleware with recording
// providers installed, and returns what was captured.
type telemetryHarness struct {
	spans  *tracetest.SpanRecorder
	reader *sdkmetric.ManualReader
	logs   *bytes.Buffer
	router chi.Router
}

func newTelemetryHarness(t *testing.T) *telemetryHarness {
	t.Helper()
	h := &telemetryHarness{
		spans:  tracetest.NewSpanRecorder(),
		reader: sdkmetric.NewManualReader(),
		logs:   &bytes.Buffer{},
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(h.spans))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(h.reader))
	prevTP, prevMP := otel.GetTracerProvider(), otel.GetMeterProvider()
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetMeterProvider(prevMP)
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
	})

	log := slog.New(slog.NewJSONHandler(h.logs, nil))
	r := chi.NewRouter()
	r.Use(server.Telemetry(log))
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/v1/log/{deviceId}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	})
	r.Get("/boom", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	h.router = r
	return h
}

func (h *telemetryHarness) do(method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestTelemetrySpanUsesRoutePattern(t *testing.T) {
	// Span names must use the route pattern, not the raw path: raw paths explode
	// cardinality and leak device IDs into the telemetry backend.
	h := newTelemetryHarness(t)
	h.do(http.MethodGet, "/v1/log/abc123")

	spans := h.spans.Ended()
	require.Len(t, spans, 1)
	require.Equal(t, "GET /v1/log/{deviceId}", spans[0].Name())

	attrs := attribute.NewSet(spans[0].Attributes()...)
	route, _ := attrs.Value("http.route")
	require.Equal(t, "/v1/log/{deviceId}", route.AsString())
	status, _ := attrs.Value("http.response.status_code")
	require.Equal(t, int64(http.StatusOK), status.AsInt64())
}

func TestTelemetrySkipsHealth(t *testing.T) {
	// Health probes fire every few seconds; tracing them drowns real traffic.
	h := newTelemetryHarness(t)
	h.do(http.MethodGet, "/health")
	require.Empty(t, h.spans.Ended())
	require.Empty(t, h.logs.String())
}

func TestTelemetryRecordsDurationHistogram(t *testing.T) {
	h := newTelemetryHarness(t)
	h.do(http.MethodGet, "/v1/log/abc123")

	var rm metricdata.ResourceMetrics
	require.NoError(t, h.reader.Collect(context.Background(), &rm))

	hist := findHistogram(t, rm, "http.server.request.duration")
	require.Len(t, hist.DataPoints, 1)
	dp := hist.DataPoints[0]
	require.EqualValues(t, 1, dp.Count)
	route, ok := dp.Attributes.Value("http.route")
	require.True(t, ok)
	require.Equal(t, "/v1/log/{deviceId}", route.AsString())
}

func TestTelemetryEmitsRequestSummaryLog(t *testing.T) {
	h := newTelemetryHarness(t)
	h.do(http.MethodGet, "/v1/log/abc123")

	var line map[string]any
	require.NoError(t, json.Unmarshal(h.logs.Bytes(), &line), "log output: %s", h.logs.String())
	require.Equal(t, "request", line["msg"])
	require.Equal(t, "GET", line["method"])
	require.Equal(t, "/v1/log/{deviceId}", line["route"])
	require.EqualValues(t, http.StatusOK, line["status"])
	require.Contains(t, line, "duration_ms")
	require.EqualValues(t, len("payload"), line["bytes_out"])
	require.Equal(t, "INFO", line["level"])
}

func TestTelemetryLogsServerErrorsAtWarn(t *testing.T) {
	// A 5xx is the "something is going wrong" signal; it must stand out from routine
	// traffic at the log level, not just in the status field.
	h := newTelemetryHarness(t)
	h.do(http.MethodGet, "/boom")

	var line map[string]any
	require.NoError(t, json.Unmarshal(h.logs.Bytes(), &line))
	require.Equal(t, "WARN", line["level"])
	require.EqualValues(t, http.StatusInternalServerError, line["status"])
}

func TestTelemetryCountsServerErrors(t *testing.T) {
	h := newTelemetryHarness(t)
	h.do(http.MethodGet, "/boom")
	h.do(http.MethodGet, "/v1/log/abc123")

	var rm metricdata.ResourceMetrics
	require.NoError(t, h.reader.Collect(context.Background(), &rm))

	sum := findSum(t, rm, "http.server.errors")
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	require.EqualValues(t, 1, total)
}

func TestTelemetryLabelsUnmatchedRoutes(t *testing.T) {
	// A request that matches no route has no chi pattern; an empty label would make
	// unmatched traffic invisible in metrics, so it gets a fixed name. All such requests
	// share one label on purpose — per-path labels would let scanners mint metric series.
	h := newTelemetryHarness(t)
	h.do(http.MethodGet, "/no/such/route")

	var line map[string]any
	require.NoError(t, json.Unmarshal(h.logs.Bytes(), &line))
	require.Equal(t, "unmatched", line["route"])

	spans := h.spans.Ended()
	require.Len(t, spans, 1)
	require.Equal(t, "GET unmatched", spans[0].Name())
}

func TestRouterWiresTelemetry(t *testing.T) {
	// The middleware only observes traffic it is actually mounted in front of; this pins
	// the wiring in NewRouter, not just the middleware in isolation.
	h := newTelemetryHarness(t)

	serverPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverWallet, err := sdkwallet.NewCompletedProtoWallet(serverPriv)
	require.NoError(t, err)

	router, err := server.NewRouter(server.Deps{
		Wallet:       serverWallet,
		Store:        blobstore.NewMemoryStore(),
		Nonces:       nonce.NewMemoryStore(),
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		MaxBlobBytes: 1 << 20,
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/limits", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	spans := h.spans.Ended()
	require.Len(t, spans, 1)
	require.Equal(t, "GET /v1/limits", spans[0].Name())
}

func findHistogram(t *testing.T, rm metricdata.ResourceMetrics, name string) metricdata.Histogram[float64] {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				h, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok, "metric %s is %T, not a float64 histogram", name, m.Data)
				return h
			}
		}
	}
	t.Fatalf("metric %q not found; have: %s", name, metricNames(rm))
	return metricdata.Histogram[float64]{}
}

func findSum(t *testing.T, rm metricdata.ResourceMetrics, name string) metricdata.Sum[int64] {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				s, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok, "metric %s is %T, not an int64 sum", name, m.Data)
				return s
			}
		}
	}
	t.Fatalf("metric %q not found; have: %s", name, metricNames(rm))
	return metricdata.Sum[int64]{}
}

func metricNames(rm metricdata.ResourceMetrics) string {
	var names []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names = append(names, m.Name)
		}
	}
	return strings.Join(names, ", ")
}
