package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const instrumentationName = "github.com/bsv-blockchain/go-private-backup-cache/internal/server"

// Telemetry traces, measures and logs every request except health probes.
//
// One span per request, named by the chi route pattern rather than the raw path — raw
// paths would explode metric cardinality and leak device IDs into the telemetry backend.
// One summary log line per request carries the same fields, at WARN for 5xx so trouble
// stands out without a dashboard.
func Telemetry(log *slog.Logger) func(http.Handler) http.Handler {
	tracer := otel.Tracer(instrumentationName)
	meter := otel.Meter(instrumentationName)

	duration, err := meter.Float64Histogram("http.server.request.duration",
		metric.WithUnit("s"),
		metric.WithDescription("HTTP request duration"))
	if err != nil {
		panic(fmt.Sprintf("build request duration histogram: %v", err))
	}
	errorsTotal, err := meter.Int64Counter("http.server.errors",
		metric.WithDescription("HTTP responses with a 5xx status"))
	if err != nil {
		panic(fmt.Sprintf("build error counter: %v", err))
	}

	propagator := otel.GetTextMapPropagator()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Health probes fire every few seconds; tracing them drowns real traffic.
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			ctx, span := tracer.Start(ctx, r.Method,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(attribute.String("http.request.method", r.Method)))

			rec := &statusRecorder{ResponseWriter: w}
			start := time.Now()
			next.ServeHTTP(rec, r.WithContext(ctx))
			elapsed := time.Since(start)

			// The route pattern is only known after routing; the span was started before,
			// so it is renamed here.
			route := chi.RouteContext(r.Context()).RoutePattern()
			if route == "" {
				// No route matched. One shared label for all such requests — labeling by
				// path would let scanners mint unbounded metric series.
				route = "unmatched"
			}
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}

			span.SetName(fmt.Sprintf("%s %s", r.Method, route))
			span.SetAttributes(
				attribute.String("http.route", route),
				attribute.Int("http.response.status_code", status),
			)
			if status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(status))
			}
			span.End()

			attrs := metric.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("http.route", route),
				attribute.Int("http.response.status_code", status),
			)
			duration.Record(ctx, elapsed.Seconds(), attrs)
			if status >= 500 {
				errorsTotal.Add(ctx, 1, attrs)
			}

			level := slog.LevelInfo
			if status >= 500 {
				level = slog.LevelWarn
			}
			log.Log(ctx, level, "request",
				"method", r.Method,
				"route", route,
				"status", status,
				"duration_ms", elapsed.Milliseconds(),
				"bytes_out", rec.written,
			)
		})
	}
}

// statusRecorder captures what the handler answered, for the span, metrics and log line.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.written += int64(n)
	return n, err
}
