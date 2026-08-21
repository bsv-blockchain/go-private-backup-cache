package blobstore

import (
	"context"
	"io"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// WithTracing wraps a store so every operation runs inside a child span of the request.
//
// Attributes carry sizes and counts only. Pseudonyms and device IDs are deliberately kept
// off the spans: the telemetry backend sits outside this service's zero-knowledge
// boundary, and the span timing alone is enough to debug a slow store.
func WithTracing(next BlobStore) BlobStore {
	return &tracingStore{
		next:   next,
		tracer: otel.Tracer("github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"),
	}
}

type tracingStore struct {
	next   BlobStore
	tracer trace.Tracer
}

func (t *tracingStore) Append(ctx context.Context, k BlobKey, prev string, body io.Reader) (string, int64, error) {
	ctx, span := t.tracer.Start(ctx, "blobstore.Append")
	defer span.End()
	sha, n, err := t.next.Append(ctx, k, prev, body)
	span.SetAttributes(attribute.Int64("blob.bytes", n))
	recordErr(span, err)
	return sha, n, err
}

func (t *tracingStore) Get(ctx context.Context, k BlobKey) (io.ReadCloser, int64, error) {
	// The span covers the lookup, not the caller's streaming of the body — holding it
	// open across a 200 MiB download would report transfer time as store latency.
	ctx, span := t.tracer.Start(ctx, "blobstore.Get")
	defer span.End()
	rc, n, err := t.next.Get(ctx, k)
	span.SetAttributes(attribute.Int64("blob.bytes", n))
	recordErr(span, err)
	return rc, n, err
}

func (t *tracingStore) Index(ctx context.Context, pseudonym, deviceID string, generation, from, limit int) ([]Entry, error) {
	ctx, span := t.tracer.Start(ctx, "blobstore.Index")
	defer span.End()
	entries, err := t.next.Index(ctx, pseudonym, deviceID, generation, from, limit)
	span.SetAttributes(attribute.Int("entries", len(entries)))
	recordErr(span, err)
	return entries, err
}

func (t *tracingStore) Manifest(ctx context.Context, pseudonym string) ([]DeviceSummary, error) {
	ctx, span := t.tracer.Start(ctx, "blobstore.Manifest")
	defer span.End()
	devices, err := t.next.Manifest(ctx, pseudonym)
	span.SetAttributes(attribute.Int("devices", len(devices)))
	recordErr(span, err)
	return devices, err
}

func (t *tracingStore) DeleteGeneration(ctx context.Context, pseudonym, deviceID string, generation int) (int64, error) {
	ctx, span := t.tracer.Start(ctx, "blobstore.DeleteGeneration")
	defer span.End()
	n, err := t.next.DeleteGeneration(ctx, pseudonym, deviceID, generation)
	span.SetAttributes(attribute.Int64("rows", n))
	recordErr(span, err)
	return n, err
}

func (t *tracingStore) DeleteAccount(ctx context.Context, pseudonym string) (int64, error) {
	ctx, span := t.tracer.Start(ctx, "blobstore.DeleteAccount")
	defer span.End()
	n, err := t.next.DeleteAccount(ctx, pseudonym)
	span.SetAttributes(attribute.Int64("rows", n))
	recordErr(span, err)
	return n, err
}

func (t *tracingStore) Ping() error { return t.next.Ping() }

func recordErr(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}
