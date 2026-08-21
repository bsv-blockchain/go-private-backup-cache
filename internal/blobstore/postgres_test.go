package blobstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
)

// pgStore gates a test on a real database, mirroring stores(): the behaviours below —
// transaction races, physical chunk rows, boot migrations — only exist in postgres, so
// there is no memory-store variant to fall back to.
func pgStore(t *testing.T) *blobstore.PostgresStore {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; this test needs a real postgres")
	}
	pg, err := blobstore.NewPostgresStore(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pg.Close()) })
	return pg
}

// randomBody returns n bytes of fresh randomness plus their sha256 hex. Random rather than
// patterned bytes, so a store that reorders or duplicates chunks cannot round-trip by luck.
func randomBody(t *testing.T, n int) ([]byte, string) {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:])
}

func TestConcurrentAppendsToOneSequenceHaveExactlyOneWinner(t *testing.T) {
	pg := pgStore(t)
	ctx := context.Background()
	k := blobstore.BlobKey{Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1}

	// Multi-megabyte bodies keep every transaction mid-stream while the others collide, so
	// the conflict lands on in-flight chunk inserts rather than neatly serialized
	// statements — the shape a real double-upload takes.
	const racers = 6
	const bodyBytes = 3 << 20
	bodies := make([][]byte, racers)
	shas := make([]string, racers)
	for i := range racers {
		bodies[i], shas[i] = randomBody(t, bodyBytes)
	}

	start := make(chan struct{})
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, errs[i] = pg.Append(ctx, k, "", bytes.NewReader(bodies[i]))
		}()
	}
	close(start)
	wg.Wait()

	// The READ COMMITTED head check waves every racer through; the primary key must stop
	// all but one, and each loser must hear the protocol answer (ErrSeqConflict) a stale
	// client gets — never a raw driver error, which the handler would surface as a 500.
	winner := -1
	for i, err := range errs {
		if err == nil {
			require.Equal(t, -1, winner, "appends %d and %d both claimed the sequence", winner, i)
			winner = i
			continue
		}
		require.ErrorIs(t, err, blobstore.ErrSeqConflict, "loser %d", i)
		var pqErr *pq.Error
		require.False(t, errors.As(err, &pqErr), "loser %d leaked a raw pq error: %v", i, err)
	}
	require.NotEqual(t, -1, winner, "no append won the race")

	// The stored blob must be the winner's, intact: losers rolled back without leaving a
	// single chunk of theirs interleaved into the winner's rows.
	got, size := mustGet(t, pg, k)
	require.Equal(t, int64(bodyBytes), size)
	sum := sha256.Sum256(got)
	require.Equal(t, shas[winner], hex.EncodeToString(sum[:]))
}

func TestMultiChunkBlobsRoundTripByteExactly(t *testing.T) {
	pg := pgStore(t)

	// Sizes bracket the chunking boundaries — exactly one buffer, one byte either side of
	// it, exactly two, and a partial trailing chunk — because an off-by-one here is a
	// corrupted restore, not a test failure someone notices.
	sizes := map[string]int{
		"one chunk exactly":      blobstore.ChunkBytes,
		"one byte under a chunk": blobstore.ChunkBytes - 1,
		"one byte over a chunk":  blobstore.ChunkBytes + 1,
		"two chunks exactly":     2 * blobstore.ChunkBytes,
		"two and a half chunks":  5 * blobstore.ChunkBytes / 2,
	}
	for name, n := range sizes {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			k := blobstore.BlobKey{Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1}
			body, wantSha := randomBody(t, n)

			sha, size, err := pg.Append(ctx, k, "", bytes.NewReader(body))
			require.NoError(t, err)
			require.Equal(t, wantSha, sha)
			require.Equal(t, int64(n), size)

			// Drain through the real chunk reader and hash what actually comes out:
			// comparing digests catches reordered, duplicated and truncated chunks alike.
			rc, gotSize, err := pg.Get(ctx, k)
			require.NoError(t, err)
			hasher := sha256.New()
			drained, err := io.Copy(hasher, rc)
			require.NoError(t, err)
			require.NoError(t, rc.Close())
			require.Equal(t, int64(n), gotSize)
			require.Equal(t, int64(n), drained)
			require.Equal(t, wantSha, hex.EncodeToString(hasher.Sum(nil)))

			// The index is what a restore budgets from, so its size must be the same truth.
			entries, err := pg.Index(ctx, k.Pseudonym, device, 1, 1, 10)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Equal(t, n, entries[0].Size)
		})
	}
}

func TestMidStreamFailureLeavesNoRowsInEitherTable(t *testing.T) {
	pg := pgStore(t)
	ctx := context.Background()
	k := blobstore.BlobKey{Pseudonym: alice + t.Name(), DeviceID: device, Generation: 1, Seq: 1}

	// The reader dies after ~1.5 MiB — past the first chunk's insert, midway through the
	// second — so real chunk rows exist inside the transaction when the failure hits.
	_, _, err := pg.Append(ctx, k, "", &failingReader{remaining: 3 * blobstore.ChunkBytes / 2})
	require.Error(t, err)
	require.NotErrorIs(t, err, blobstore.ErrSeqConflict)

	// Count the physical rows directly rather than through Get/Index: the rollback must
	// leave nothing on disk, not merely rows the read paths happen to skip. Orphaned
	// blob_chunks rows would be invisible storage leaked on every dropped upload.
	var logRows, chunkRows int
	require.NoError(t, pg.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM blob_log WHERE pseudonym=$1`, k.Pseudonym).Scan(&logRows))
	require.NoError(t, pg.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM blob_chunks WHERE pseudonym=$1`, k.Pseudonym).Scan(&chunkRows))
	require.Zero(t, logRows, "aborted append left blob_log rows behind")
	require.Zero(t, chunkRows, "aborted append left blob_chunks rows behind")
}

// preStreamingMigrations is origin/main's schema verbatim — the single ciphertext bytea
// column of the 1 MiB-cap design — which is exactly what a production database looks like
// the moment the streaming release first boots against it.
var preStreamingMigrations = []string{
	`CREATE TABLE IF NOT EXISTS blob_log (
		pseudonym    TEXT        NOT NULL,
		device_id    TEXT        NOT NULL,
		generation   INTEGER     NOT NULL,
		seq          INTEGER     NOT NULL,
		sha256       TEXT        NOT NULL,
		prev_sha256  TEXT,
		ciphertext   BYTEA       NOT NULL,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
		PRIMARY KEY (pseudonym, device_id, generation, seq)
	)`,
	`CREATE INDEX IF NOT EXISTS blob_log_head
		ON blob_log (pseudonym, device_id, generation, seq DESC)`,
}

func TestBootMigratesAPreStreamingDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; this test needs a real postgres")
	}

	// A dedicated database, because the migration under test DROPs blob_log: pointing it at
	// the shared test database would erase every other postgres-gated test's rows mid-run.
	// The TEST_DATABASE_URL connection itself serves as the admin connection — CREATE and
	// DROP DATABASE are server-level statements, and that database is the only one the env
	// var guarantees exists.
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	nameBytes := make([]byte, 6)
	_, err = rand.Read(nameBytes)
	require.NoError(t, err)
	name := "migration_" + hex.EncodeToString(nameBytes)
	_, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name))
	require.NoError(t, err)
	t.Cleanup(func() {
		// FORCE, so a lingering pool connection cannot strand the throwaway database.
		_, err := admin.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)")
		require.NoError(t, err)
		require.NoError(t, admin.Close())
	})

	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/" + name
	target := u.String()

	// Seed the old world: schema plus one stored blob, so the migration demonstrably
	// destroys data rather than happening to run against an empty table.
	seed, err := sql.Open("postgres", target)
	require.NoError(t, err)
	for _, m := range preStreamingMigrations {
		_, err := seed.Exec(m)
		require.NoError(t, err)
	}
	_, err = seed.Exec(
		`INSERT INTO blob_log (pseudonym, device_id, generation, seq, sha256, ciphertext)
		 VALUES ('02aa', 'd1', 1, 1, 'feed', '\x6f6c64'::bytea)`)
	require.NoError(t, err)
	require.NoError(t, seed.Close())

	// Boot against the old schema. Destructive on purpose, per the standing
	// no-compatibility decision: success means the old table is gone, not converted.
	pg, err := blobstore.NewPostgresStore(target)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pg.Close()) })

	var ciphertextCols int
	require.NoError(t, pg.DB().QueryRow(
		`SELECT COUNT(*) FROM information_schema.columns
		  WHERE table_name = 'blob_log' AND column_name = 'ciphertext'`).Scan(&ciphertextCols))
	require.Zero(t, ciphertextCols, "the pre-streaming ciphertext column survived the migration")

	var chunkTables int
	require.NoError(t, pg.DB().QueryRow(
		`SELECT COUNT(*) FROM information_schema.tables
		  WHERE table_name = 'blob_chunks'`).Scan(&chunkTables))
	require.Equal(t, 1, chunkTables, "blob_chunks missing after the migration")

	// The migrated database must be fully usable, with seq restarting at 1 because the
	// seeded row went down with the old table.
	ctx := context.Background()
	k := blobstore.BlobKey{Pseudonym: "02aa", DeviceID: device, Generation: 1, Seq: 1}
	body, wantSha := randomBody(t, blobstore.ChunkBytes+1)
	sha, size, err := pg.Append(ctx, k, "", bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, wantSha, sha)
	require.Equal(t, int64(len(body)), size)

	got, gotSize := mustGet(t, pg, k)
	require.Equal(t, int64(len(body)), gotSize)
	require.Equal(t, body, got, "round trip through the migrated database must be byte-exact")
}
