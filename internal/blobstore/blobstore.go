// Package blobstore persists opaque encrypted blobs.
//
// Nothing in this package interprets blob contents. The bytes arrive encrypted under a key
// derived from the client's wallet seed with counterparty "self", so the server is
// structurally incapable of reading them — there is no decrypt path here, and there must
// never be one.
package blobstore

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrSeqConflict means the requested sequence number is not the next one in the log.
	// Appends must be contiguous: a gap would leave a silent hole in a restore, and an
	// overwrite would destroy a backup entry.
	ErrSeqConflict = errors.New("sequence conflict")

	// ErrNotFound covers both "does not exist" and "belongs to another pseudonym".
	// Callers must not be able to distinguish the two.
	ErrNotFound = errors.New("not found")

	// ErrRetentionGuard means the caller tried to delete a generation that must be kept.
	ErrRetentionGuard = errors.New("generation is within the retained window")
)

// RetainedGenerations is how many generations survive pruning: the current one and the
// previous one.
//
// Two rather than one, so that a compaction which fails partway never leaves a user with
// zero recoverable backups.
const RetainedGenerations = 2

// BlobKey addresses a single blob.
//
// Pseudonym is ALWAYS the authenticated caller's identity key in compressed DER hex. It is
// never read from a request body, query parameter, path segment or header. A sibling
// project shipped a cross-tenant auth bypass by trusting a client-supplied identity here.
type BlobKey struct {
	Pseudonym  string
	DeviceID   string
	Generation int
	Seq        int
}

// Entry is one log entry's metadata, without the ciphertext.
type Entry struct {
	Seq        int       `json:"seq"`
	Sha256     string    `json:"sha256"`
	PrevSha256 string    `json:"prevSha256,omitempty"`
	Size       int       `json:"size"`
	CreatedAt  time.Time `json:"createdAt"`
}

// DeviceSummary describes one device's log head, as returned by the manifest.
type DeviceSummary struct {
	DeviceID   string    `json:"deviceId"`
	Generation int       `json:"generation"`
	HeadSeq    int       `json:"headSeq"`
	HeadSha256 string    `json:"headSha256"`
	TotalBytes int64     `json:"totalBytes"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// BlobStore is the persistence seam.
//
// Blobs are opaque, append-only and at most a megabyte, so a Postgres bytea column is a
// comfortable fit; this interface exists so an object store can be substituted later
// without touching the handlers.
type BlobStore interface {
	// Append stores data at k, which must be exactly one past the current head sequence
	// for that (pseudonym, device, generation). Returns the sha256 hex of the stored bytes.
	Append(ctx context.Context, k BlobKey, prevSha256 string, data []byte) (string, error)

	// Get returns the ciphertext at k, or ErrNotFound.
	Get(ctx context.Context, k BlobKey) ([]byte, error)

	// Index lists entry metadata for one generation, starting at sequence from.
	Index(ctx context.Context, pseudonym, deviceID string, generation, from, limit int) ([]Entry, error)

	// Manifest summarises every device and generation belonging to one pseudonym.
	Manifest(ctx context.Context, pseudonym string) ([]DeviceSummary, error)

	// DeleteGeneration removes a whole generation, refusing any within the retained
	// window. Returns the number of rows removed.
	DeleteGeneration(ctx context.Context, pseudonym, deviceID string, generation int) (int64, error)

	// DeleteAccount removes every blob belonging to one pseudonym, across all devices and
	// all generations. Returns the number of rows removed.
	//
	// The retention guard does NOT apply: this serves an erasure request from the only
	// party who can make one (the holder of the key the pseudonym derives from), and
	// leaving the two newest generations behind would defeat the entire point. Idempotent
	// — erasing an account that holds nothing removes nothing and is not an error, because
	// a client cannot tell a lost response from a refused request.
	DeleteAccount(ctx context.Context, pseudonym string) (int64, error)

	// Ping reports backing-store reachability for the health endpoint.
	Ping() error
}
