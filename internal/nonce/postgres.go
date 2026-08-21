package nonce

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"time"
)

// Migrations are idempotent and run at boot, matching the blobstore's pattern.
var Migrations = []string{
	`CREATE TABLE IF NOT EXISTS auth_nonces (
		nonce      TEXT        PRIMARY KEY,
		expires_at TIMESTAMPTZ NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS auth_nonces_expiry ON auth_nonces (expires_at)`,
}

// PostgresStore enforces single-use across every replica: the primary key makes the
// insert a serialization point, so two replicas seeing the same nonce cannot both win.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore runs migrations on an already-open pool (shared with the blobstore).
func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	for i, m := range Migrations {
		if _, err := db.Exec(m); err != nil {
			return nil, fmt.Errorf("nonce migration %d: %w", i, err)
		}
	}
	return &PostgresStore{db: db}, nil
}

// Consume implements Store. ON CONFLICT DO NOTHING reports a replay as zero rows
// inserted, with no error and no race.
func (s *PostgresStore) Consume(ctx context.Context, nonce string, expiresAt time.Time) (bool, error) {
	// Expired rows are useless — the proofs they belong to are refused on expiry before
	// the nonce is ever looked at. Sweep opportunistically rather than per-request: the
	// table only ever holds one validity window's worth of rows, so a 1-in-64 sweep keeps
	// it bounded without a background job or a scheduler.
	if rand.IntN(64) == 0 {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM auth_nonces WHERE expires_at < now()`); err != nil {
			return false, fmt.Errorf("sweep nonces: %w", err)
		}
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_nonces (nonce, expires_at) VALUES ($1, $2) ON CONFLICT (nonce) DO NOTHING`,
		nonce, expiresAt)
	if err != nil {
		return false, fmt.Errorf("consume nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
