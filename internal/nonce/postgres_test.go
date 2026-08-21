package nonce_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq" // postgres driver, plus QuoteIdentifier
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
)

// pgNonceStore gates a test on a real database. The pool is handed back too, because the
// sweep inside Consume fires on a 1-in-64 roll: asserting anything about expired rows
// deterministically means running the sweep's statement by hand.
func pgNonceStore(t *testing.T) (*nonce.PostgresStore, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; this test needs a real postgres")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	s, err := nonce.NewPostgresStore(db)
	require.NoError(t, err)
	return s, db
}

// freshNonce mixes fresh randomness into every nonce so these tests can run repeatedly
// against one persistent database: a nonce consumed by a previous `go test` run must never
// masquerade as this run's replay.
func freshNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return t.Name() + "-" + hex.EncodeToString(b)
}

func TestPostgresConsumeIsSingleUse(t *testing.T) {
	s, _ := pgNonceStore(t)
	ctx := context.Background()
	exp := time.Now().Add(2 * time.Minute)
	n1, n2 := freshNonce(t), freshNonce(t)

	ok, err := s.Consume(ctx, n1, exp)
	require.NoError(t, err)
	require.True(t, ok, "first use must win")

	// A replay must come back false-without-error: it is a routine 401 for one caller, not
	// a store failure.
	ok, err = s.Consume(ctx, n1, exp)
	require.NoError(t, err)
	require.False(t, ok, "replay accepted")

	ok, err = s.Consume(ctx, n2, exp)
	require.NoError(t, err)
	require.True(t, ok, "distinct nonce refused")
}

func TestPostgresConsumeIsSingleUseUnderConcurrency(t *testing.T) {
	s, _ := pgNonceStore(t)
	exp := time.Now().Add(2 * time.Minute)
	contested := freshNonce(t)

	// Every racer dispatches behind one barrier so the inserts genuinely overlap: the
	// primary key is the only thing between a replayed proof and double acceptance, and
	// this is the store whose job is to hold that line across replicas.
	const racers = 32
	start := make(chan struct{})
	oks := make([]bool, racers)
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			oks[i], errs[i] = s.Consume(context.Background(), contested, exp)
		}()
	}
	close(start)
	wg.Wait()

	won := 0
	for i := range racers {
		require.NoError(t, errs[i], "racer %d", i)
		if oks[i] {
			won++
		}
	}
	require.Equal(t, 1, won, "exactly one racer must win")
}

func TestPostgresExpiredRowsDoNotBlockANonceAfterTheSweep(t *testing.T) {
	s, db := pgNonceStore(t)
	ctx := context.Background()
	n := freshNonce(t)

	// Record the nonce with an expiry already in the past — the state a row from an old
	// validity window is in by the time the sweep finds it.
	ok, err := s.Consume(ctx, n, time.Now().Add(-time.Minute))
	require.NoError(t, err)
	require.True(t, ok)

	// The in-store sweep fires on a random roll, which no assertion can wait on without
	// flaking, so run its exact statement directly. What matters is the property the sweep
	// exists for: an expired record must not block a nonce string forever, because the
	// proof it belonged to is already refused on freshness alone.
	_, err = db.ExecContext(ctx, `DELETE FROM auth_nonces WHERE expires_at < now()`)
	require.NoError(t, err)

	ok, err = s.Consume(ctx, n, time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok, "expired record still blocks the nonce after the sweep")
}

func TestPostgresConsumeReportsAStoreFailureAsAnError(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; this test needs a real postgres")
	}

	// A dedicated database, because this test breaks its store's schema on purpose:
	// dropping auth_nonces in the shared test database would race any other package's
	// tests using the same DSN in a parallel test binary.
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	nameBytes := make([]byte, 6)
	_, err = rand.Read(nameBytes)
	require.NoError(t, err)
	name := "nonce_" + hex.EncodeToString(nameBytes)
	_, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := admin.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)")
		require.NoError(t, err)
		require.NoError(t, admin.Close())
	})

	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	s, err := nonce.NewPostgresStore(db)
	require.NoError(t, err)
	_, err = db.Exec(`DROP TABLE auth_nonces`)
	require.NoError(t, err)

	// A broken store must surface as an error, never as ok=false: false means "replay,
	// refuse the proof", and an outage misread as a replay would silently lock every
	// caller out while reporting nothing wrong.
	ok, err := s.Consume(context.Background(), freshNonce(t), time.Now().Add(time.Minute))
	require.Error(t, err)
	require.False(t, ok)
}
