package blobstore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
)

const (
	alice  = "02aa"
	bob    = "02bb"
	device = "d1"
)

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

func TestAppendRequiresContiguousSequences(t *testing.T) {
	eachStore(t, "contiguous", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		k := blobstore.BlobKey{Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1}

		_, err := s.Append(ctx, k, "", []byte("one"))
		require.NoError(t, err)

		// Re-appending the same sequence must conflict rather than overwrite: overwriting
		// would silently destroy a backup entry.
		_, err = s.Append(ctx, k, "", []byte("different"))
		require.ErrorIs(t, err, blobstore.ErrSeqConflict)

		// Skipping a sequence must be refused, or a restore hits a silent hole.
		k.Seq = 3
		_, err = s.Append(ctx, k, "", []byte("three"))
		require.ErrorIs(t, err, blobstore.ErrSeqConflict)
	})
}

func TestAppendReturnsSha256OfStoredBytes(t *testing.T) {
	eachStore(t, "sha", func(t *testing.T, s blobstore.BlobStore) {
		sha, err := s.Append(context.Background(), blobstore.BlobKey{
			Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1,
		}, "", []byte("hello"))
		require.NoError(t, err)

		sum := sha256.Sum256([]byte("hello"))
		require.Equal(t, hex.EncodeToString(sum[:]), sha)
	})
}

func TestGetIsScopedToPseudonym(t *testing.T) {
	eachStore(t, "scoping", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		mine := alice + t.Name()
		theirs := bob + t.Name()

		_, err := s.Append(ctx, blobstore.BlobKey{
			Pseudonym: mine, DeviceID: device, Generation: 1, Seq: 1,
		}, "", []byte("secret"))
		require.NoError(t, err)

		// Every other coordinate identical; only the pseudonym differs.
		_, err = s.Get(ctx, blobstore.BlobKey{
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
		_, err := s.Append(ctx, k, "", payload)
		require.NoError(t, err)

		got, err := s.Get(ctx, k)
		require.NoError(t, err)
		require.Equal(t, payload, got, "ciphertext must survive storage byte for byte")
	})
}

func TestDeleteGenerationRefusesTheRetainedWindow(t *testing.T) {
	eachStore(t, "retention", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		p := alice + t.Name()
		for gen := 1; gen <= 3; gen++ {
			_, err := s.Append(ctx, blobstore.BlobKey{
				Pseudonym: p, DeviceID: device, Generation: gen, Seq: 1,
			}, "", []byte("x"))
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
			_, err := s.Append(ctx, blobstore.BlobKey{
				Pseudonym: mine, DeviceID: device, Generation: gen, Seq: 1,
			}, "", []byte("x"))
			require.NoError(t, err)
		}

		n, err := s.DeleteGeneration(ctx, theirs, device, 1)
		require.NoError(t, err)
		require.Equal(t, int64(0), n, "must not delete another pseudonym's data")

		_, err = s.Get(ctx, blobstore.BlobKey{
			Pseudonym: mine, DeviceID: device, Generation: 1, Seq: 1,
		})
		require.NoError(t, err)
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
				_, err := s.Append(ctx, blobstore.BlobKey{
					Pseudonym: p, DeviceID: dev, Generation: gen, Seq: 1,
				}, "", []byte("x"))
				require.NoError(t, err)
			}
		}

		n, err := s.DeleteAccount(ctx, p)
		require.NoError(t, err)
		require.Equal(t, int64(6), n)

		devices, err := s.Manifest(ctx, p)
		require.NoError(t, err)
		require.Empty(t, devices, "erasure must leave nothing behind for this pseudonym")

		_, err = s.Get(ctx, blobstore.BlobKey{Pseudonym: p, DeviceID: "d1", Generation: 3, Seq: 1})
		require.ErrorIs(t, err, blobstore.ErrNotFound)
	})
}

func TestDeleteAccountIsScopedToPseudonym(t *testing.T) {
	eachStore(t, "erase-scoping", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		mine := alice + t.Name()
		theirs := bob + t.Name()

		for _, p := range []string{mine, theirs} {
			_, err := s.Append(ctx, blobstore.BlobKey{
				Pseudonym: p, DeviceID: device, Generation: 1, Seq: 1,
			}, "", []byte("x"))
			require.NoError(t, err)
		}

		n, err := s.DeleteAccount(ctx, mine)
		require.NoError(t, err)
		require.Equal(t, int64(1), n)

		// The neighbouring account is untouched. Erasure is the most destructive operation
		// in the service, so its scoping matters more than any other method's.
		_, err = s.Get(ctx, blobstore.BlobKey{
			Pseudonym: theirs, DeviceID: device, Generation: 1, Seq: 1,
		})
		require.NoError(t, err)
	})
}

func TestDeleteAccountIsIdempotent(t *testing.T) {
	eachStore(t, "erase-idempotent", func(t *testing.T, s blobstore.BlobStore) {
		ctx := context.Background()
		p := alice + t.Name()
		_, err := s.Append(ctx, blobstore.BlobKey{
			Pseudonym: p, DeviceID: device, Generation: 1, Seq: 1,
		}, "", []byte("x"))
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
			sha, err := s.Append(ctx, blobstore.BlobKey{
				Pseudonym: p, DeviceID: device, Generation: 1, Seq: seq,
			}, prev, []byte{byte(seq)})
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
