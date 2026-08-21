package blobstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
)

const device = "d1"

// alice and bob carry fresh per-process randomness because the postgres-backed tests may
// point at a persistent database: rows committed by a previous `go test` run would
// otherwise collide with this run's appends on identical (pseudonym, device, generation,
// seq) keys. One roll per process keeps everything deterministic within a run while making
// runs disjoint. Device ids need no mixing — every store operation scopes by pseudonym
// first.
var (
	alice = "02aa" + runSuffix()
	bob   = "02bb" + runSuffix()
)

func runSuffix() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// stores returns every BlobStore implementation available in this environment. The Postgres
// implementation only participates when TEST_DATABASE_URL is set, so the suite still runs
// meaningfully without a database while enforcing identical invariants when one is present.
func stores(t *testing.T) map[string]blobstore.BlobStore {
	t.Helper()
	out := map[string]blobstore.BlobStore{"memory": blobstore.NewMemoryStore()}

	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		pg, err := blobstore.NewPostgresStore(dsn)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, pg.Close()) })
		out["postgres"] = pg
	}
	return out
}

func eachStore(t *testing.T, name string, fn func(t *testing.T, s blobstore.BlobStore)) {
	t.Helper()
	for impl, s := range stores(t) {
		t.Run(impl+"/"+name, func(t *testing.T) { fn(t, s) })
	}
}

// mustGet drains and closes the stream so tests exercise the full read path — a store that
// returns the right bytes but breaks mid-stream or misreports the size must fail here.
func mustGet(t *testing.T, s blobstore.BlobStore, k blobstore.BlobKey) ([]byte, int64) {
	t.Helper()
	rc, size, err := s.Get(context.Background(), k)
	require.NoError(t, err)
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	return data, size
}

// failingReader stands in for an upload whose connection drops after some bytes arrived:
// it yields n bytes and then errors instead of reaching EOF.
type failingReader struct {
	remaining int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, errors.New("connection lost")
	}
	n := min(len(p), r.remaining)
	for i := range n {
		p[i] = 'x'
	}
	r.remaining -= n
	return n, nil
}

func TestAppendRequiresContiguousSequences(t *testing.T) {
	eachStore(t, "contiguous", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		k := blobstore.BlobKey{Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1}

		_, _, err := s.Append(ctx, k, "", bytes.NewReader([]byte("one")))
		require.NoError(t, err)

		// Re-appending the same sequence must conflict rather than overwrite: overwriting
		// would silently destroy a backup entry.
		_, _, err = s.Append(ctx, k, "", bytes.NewReader([]byte("different")))
		require.ErrorIs(t, err, blobstore.ErrSeqConflict)

		// Skipping a sequence must be refused, or a restore hits a silent hole.
		k.Seq = 3
		_, _, err = s.Append(ctx, k, "", bytes.NewReader([]byte("three")))
		require.ErrorIs(t, err, blobstore.ErrSeqConflict)
	})
}

func TestAppendReturnsSha256OfStoredBytes(t *testing.T) {
	eachStore(t, "sha", func(t *testing.T, s blobstore.BlobStore) {
		sha, _, err := s.Append(context.Background(), blobstore.BlobKey{
			Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1,
		}, "", bytes.NewReader([]byte("hello")))
		require.NoError(t, err)

		sum := sha256.Sum256([]byte("hello"))
		require.Equal(t, hex.EncodeToString(sum[:]), sha)
	})
}

func TestAppendRefusesAnEmptyBody(t *testing.T) {
	eachStore(t, "empty", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		k := blobstore.BlobKey{Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1}

		// A zero-byte entry would consume a sequence number while backing up nothing,
		// leaving a hole a restore cannot distinguish from data loss.
		_, _, err := s.Append(ctx, k, "", bytes.NewReader(nil))
		require.ErrorIs(t, err, blobstore.ErrEmptyBlob)

		_, _, err = s.Get(ctx, k)
		require.ErrorIs(t, err, blobstore.ErrNotFound)

		entries, err := s.Index(ctx, k.Pseudonym, device, 1, 1, 100)
		require.NoError(t, err)
		require.Empty(t, entries, "a refused append must store nothing")
	})
}

func TestAppendLeavesNothingBehindWhenTheBodyFailsMidStream(t *testing.T) {
	eachStore(t, "mid-stream-failure", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		k := blobstore.BlobKey{Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1}

		// The body streams straight into storage, so a dropped connection reaches the
		// store as a read error after real bytes were consumed. A half-written entry
		// would occupy the sequence number and poison the hash chain, so the append
		// must roll back completely.
		_, _, err := s.Append(ctx, k, "", &failingReader{remaining: 64})
		require.Error(t, err)
		require.NotErrorIs(t, err, blobstore.ErrSeqConflict)

		_, _, err = s.Get(ctx, k)
		require.ErrorIs(t, err, blobstore.ErrNotFound)

		entries, err := s.Index(ctx, k.Pseudonym, device, 1, 1, 100)
		require.NoError(t, err)
		require.Empty(t, entries, "an aborted append must store nothing")
	})
}

func TestAppendReportsTheStoredSizeConsistently(t *testing.T) {
	eachStore(t, "size", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		p := alice + t.Name()
		payload := bytes.Repeat([]byte("abc"), 100)

		// The size travels three routes to the client — the upload response, the index,
		// and the manifest — and a restore budget trusts all of them. They must agree
		// with the actual byte count.
		_, size, err := s.Append(ctx, blobstore.BlobKey{
			Pseudonym: p, DeviceID: device, Generation: 1, Seq: 1,
		}, "", bytes.NewReader(payload))
		require.NoError(t, err)
		require.Equal(t, int64(len(payload)), size)

		entries, err := s.Index(ctx, p, device, 1, 1, 100)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, len(payload), entries[0].Size)

		devices, err := s.Manifest(ctx, p)
		require.NoError(t, err)
		require.Len(t, devices, 1)
		require.Equal(t, int64(len(payload)), devices[0].TotalBytes)
	})
}

func TestGetIsScopedToPseudonym(t *testing.T) {
	eachStore(t, "scoping", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		mine := alice + t.Name()
		theirs := bob + t.Name()

		_, _, err := s.Append(ctx, blobstore.BlobKey{
			Pseudonym: mine, DeviceID: device, Generation: 1, Seq: 1,
		}, "", bytes.NewReader([]byte("secret")))
		require.NoError(t, err)

		// Every other coordinate identical; only the pseudonym differs.
		_, _, err = s.Get(ctx, blobstore.BlobKey{
			Pseudonym: theirs, DeviceID: device, Generation: 1, Seq: 1,
		})
		require.ErrorIs(t, err, blobstore.ErrNotFound)
	})
}

func TestBlobRoundTripsBinaryExactly(t *testing.T) {
	eachStore(t, "binary", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		payload := make([]byte, 256)
		for i := range payload {
			payload[i] = byte(i)
		}

		k := blobstore.BlobKey{Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1}
		_, _, err := s.Append(ctx, k, "", bytes.NewReader(payload))
		require.NoError(t, err)

		got, size := mustGet(t, s, k)
		require.Equal(t, payload, got, "ciphertext must survive storage byte for byte")
		require.Equal(t, int64(len(payload)), size)
	})
}

func TestDeleteGenerationRefusesTheRetainedWindow(t *testing.T) {
	eachStore(t, "retention", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		p := alice + t.Name()
		for gen := 1; gen <= 3; gen++ {
			_, _, err := s.Append(ctx, blobstore.BlobKey{
				Pseudonym: p, DeviceID: device, Generation: gen, Seq: 1,
			}, "", bytes.NewReader([]byte("x")))
			require.NoError(t, err)
		}

		// Generation 3 is current and 2 is its predecessor; both must survive so that a
		// compaction failing partway never leaves zero recoverable backups.
		_, err := s.DeleteGeneration(ctx, p, device, 3)
		require.ErrorIs(t, err, blobstore.ErrRetentionGuard)
		_, err = s.DeleteGeneration(ctx, p, device, 2)
		require.ErrorIs(t, err, blobstore.ErrRetentionGuard)

		n, err := s.DeleteGeneration(ctx, p, device, 1)
		require.NoError(t, err)
		require.Equal(t, int64(1), n)
	})
}

func TestDeleteGenerationIsScopedToPseudonym(t *testing.T) {
	eachStore(t, "delete-scoping", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		mine := alice + t.Name()
		theirs := bob + t.Name()

		for gen := 1; gen <= 3; gen++ {
			_, _, err := s.Append(ctx, blobstore.BlobKey{
				Pseudonym: mine, DeviceID: device, Generation: gen, Seq: 1,
			}, "", bytes.NewReader([]byte("x")))
			require.NoError(t, err)
		}

		n, err := s.DeleteGeneration(ctx, theirs, device, 1)
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "must not delete another pseudonym's data")

		got, _ := mustGet(t, s, blobstore.BlobKey{
			Pseudonym: mine, DeviceID: device, Generation: 1, Seq: 1,
		})
		require.Equal(t, []byte("x"), got)
	})
}

func TestDeleteAccountErasesEverythingIncludingTheRetainedWindow(t *testing.T) {
	eachStore(t, "erase", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		p := alice + t.Name()

		// Two devices, three generations each: the newest two per device are exactly what
		// DeleteGeneration refuses, and are exactly what an erasure request must remove.
		for _, dev := range []string{"d1", "d2"} {
			for gen := 1; gen <= 3; gen++ {
				_, _, err := s.Append(ctx, blobstore.BlobKey{
					Pseudonym: p, DeviceID: dev, Generation: gen, Seq: 1,
				}, "", bytes.NewReader([]byte("x")))
				require.NoError(t, err)
			}
		}

		n, err := s.DeleteAccount(ctx, p)
		require.NoError(t, err)
		require.Equal(t, int64(6), n)

		devices, err := s.Manifest(ctx, p)
		require.NoError(t, err)
		require.Empty(t, devices, "erasure must leave nothing behind for this pseudonym")

		_, _, err = s.Get(ctx, blobstore.BlobKey{Pseudonym: p, DeviceID: "d1", Generation: 3, Seq: 1})
		require.ErrorIs(t, err, blobstore.ErrNotFound)
	})
}

func TestDeleteAccountIsScopedToPseudonym(t *testing.T) {
	eachStore(t, "erase-scoping", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		mine := alice + t.Name()
		theirs := bob + t.Name()

		for _, p := range []string{mine, theirs} {
			_, _, err := s.Append(ctx, blobstore.BlobKey{
				Pseudonym: p, DeviceID: device, Generation: 1, Seq: 1,
			}, "", bytes.NewReader([]byte("x")))
			require.NoError(t, err)
		}

		n, err := s.DeleteAccount(ctx, mine)
		require.NoError(t, err)
		require.Equal(t, int64(1), n)

		// The neighbouring account is untouched. Erasure is the most destructive operation
		// in the service, so its scoping matters more than any other method's.
		got, _ := mustGet(t, s, blobstore.BlobKey{
			Pseudonym: theirs, DeviceID: device, Generation: 1, Seq: 1,
		})
		require.Equal(t, []byte("x"), got)
	})
}

func TestDeleteAccountIsIdempotent(t *testing.T) {
	eachStore(t, "erase-idempotent", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		p := alice + t.Name()
		_, _, err := s.Append(ctx, blobstore.BlobKey{
			Pseudonym: p, DeviceID: device, Generation: 1, Seq: 1,
		}, "", bytes.NewReader([]byte("x")))
		require.NoError(t, err)

		_, err = s.DeleteAccount(ctx, p)
		require.NoError(t, err)

		// A retried erasure request must succeed with nothing to do rather than error: the
		// caller cannot tell whether the first attempt's response was lost in transit.
		n, err := s.DeleteAccount(ctx, p)
		require.NoError(t, err)
		require.Equal(t, int64(0), n)
	})
}

func TestIndexAndManifestReportTheLog(t *testing.T) {
	eachStore(t, "index-manifest", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		p := alice + t.Name()

		var prev string
		for seq := 1; seq <= 3; seq++ {
			sha, _, err := s.Append(ctx, blobstore.BlobKey{
				Pseudonym: p, DeviceID: device, Generation: 1, Seq: seq,
			}, prev, bytes.NewReader([]byte{byte(seq)}))
			require.NoError(t, err)
			prev = sha
		}

		entries, err := s.Index(ctx, p, device, 1, 1, 100)
		require.NoError(t, err)
		require.Len(t, entries, 3)
		require.Equal(t, 1, entries[0].Seq)
		require.Equal(t, 3, entries[2].Seq)
		// The chain lets a client detect a gap or fork before trusting a restore.
		require.Equal(t, entries[1].Sha256, entries[2].PrevSha256)

		devices, err := s.Manifest(ctx, p)
		require.NoError(t, err)
		require.Len(t, devices, 1)
		require.Equal(t, 3, devices[0].HeadSeq)
		require.Equal(t, int64(3), devices[0].TotalBytes)
	})
}
