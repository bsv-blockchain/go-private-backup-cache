// Package otel wires OpenTelemetry tracing and metrics for the process.
//
// Export is OTLP over HTTP, aimed at whatever OTEL_EXPORTER_OTLP_ENDPOINT names — a local
// collector, Grafana Cloud, Honeycomb, anything that speaks OTLP. With no endpoint the
// global providers stay as the SDK's no-ops: zero overhead, no background connections, and
// every instrumentation call site still works.
package otel

import (
	"context"
	"errors"
	"runtime/debug"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// Setup installs the global tracer and meter providers.
//
// The returned shutdown flushes pending telemetry; call it on process exit. An empty
// endpoint installs nothing and returns a no-op shutdown.
func Setup(ctx context.Context, endpoint, serviceName string) (func(context.Context) error, error) {
	// W3C traceparent propagation is set even without an exporter, so incoming trace
	// headers still thread through to logs.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(serviceVersion()),
	))
	if err != nil {
		return nil, err
	}

	// The endpoint is the collector's base URL; each signal has its own well-known path,
	// which WithEndpointURL takes verbatim rather than appending.
	traceExp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint+"/v1/traces"))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	metricExp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(endpoint+"/v1/metrics"))
	if err != nil {
		// The tracer provider is already installed; tear it down rather than run half-configured.
		_ = tp.Shutdown(ctx)
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	return func(ctx context.Context) error {
		return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx))
	}, nil
}

// serviceVersion reports the module version stamped into the binary, or "dev" when built
// from a working tree.
func serviceVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
