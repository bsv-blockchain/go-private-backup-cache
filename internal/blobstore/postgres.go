package blobstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/lib/pq" // postgres driver
)

// Migrations are idempotent and run at boot, matching the house pattern of hand-written
// CREATE TABLE IF NOT EXISTS statements rather than a migration tool.
var Migrations = []string{
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

// PostgresStore stores blobs in a bytea column.
//
// Blobs are opaque, append-only and capped at a megabyte, so bytea is a comfortable fit and
// TOAST handles them without special treatment. Postgres also gives transactional
// generation swaps, which the retention rule needs.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore opens the database and runs migrations.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	for i, m := range Migrations {
		if _, err := db.Exec(m); err != nil {
			return nil, fmt.Errorf("migration %d: %w", i, err)
		}
	}
	return &PostgresStore{db: db}, nil
}

// Ping implements BlobStore.
func (s *PostgresStore) Ping() error { return s.db.Ping() }

// Close releases the pool.
func (s *PostgresStore) Close() error { return s.db.Close() }

// Append implements BlobStore.
//
// One transaction: read the head sequence, insert only if the new sequence is exactly
// head+1. Contiguity matters because a gap becomes a silent hole in a restore, and an
// overwrite would destroy a backup entry.
func (s *PostgresStore) Append(ctx context.Context, k BlobKey, prev string, data []byte) (string, error) {
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Error("rollback failed", "error", rbErr)
		}
	}()

	var head sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT MAX(seq) FROM blob_log WHERE pseudonym=$1 AND device_id=$2 AND generation=$3`,
		k.Pseudonym, k.DeviceID, k.Generation).Scan(&head)
	if err != nil {
		return "", err
	}

	want := 1
	if head.Valid {
		want = int(head.Int64) + 1
	}
	if k.Seq != want {
		return "", fmt.Errorf("%w: expected seq %d, got %d", ErrSeqConflict, want, k.Seq)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO blob_log (pseudonym, device_id, generation, seq, sha256, prev_sha256, ciphertext)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		k.Pseudonym, k.DeviceID, k.Generation, k.Seq, sha, nullable(prev), data)
	if err != nil {
		return "", err
	}
	return sha, tx.Commit()
}

// Get implements BlobStore.
func (s *PostgresStore) Get(ctx context.Context, k BlobKey) ([]byte, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT ciphertext FROM blob_log
		 WHERE pseudonym=$1 AND device_id=$2 AND generation=$3 AND seq=$4`,
		k.Pseudonym, k.DeviceID, k.Generation, k.Seq).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Index implements BlobStore.
func (s *PostgresStore) Index(ctx context.Context, pseudonym, deviceID string, generation, from, limit int) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, sha256, COALESCE(prev_sha256,''), octet_length(ciphertext), created_at
		   FROM blob_log
		  WHERE pseudonym=$1 AND device_id=$2 AND generation=$3 AND seq >= $4
		  ORDER BY seq ASC
		  LIMIT $5`,
		pseudonym, deviceID, generation, from, limit)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)

	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Seq, &e.Sha256, &e.PrevSha256, &e.Size, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Manifest implements BlobStore.
func (s *PostgresStore) Manifest(ctx context.Context, pseudonym string) ([]DeviceSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT b.device_id,
		        b.generation,
		        MAX(b.seq)                     AS head_seq,
		        SUM(octet_length(b.ciphertext)) AS total_bytes,
		        MAX(b.created_at)              AS updated_at
		   FROM blob_log b
		  WHERE b.pseudonym = $1
		  GROUP BY b.device_id, b.generation
		  ORDER BY b.device_id, b.generation`,
		pseudonym)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)

	out := []DeviceSummary{}
	for rows.Next() {
		var d DeviceSummary
		if err := rows.Scan(&d.DeviceID, &d.Generation, &d.HeadSeq, &d.TotalBytes, &d.UpdatedAt); err != nil {
			return nil, err
		}
		if err := s.db.QueryRowContext(ctx,
			`SELECT sha256 FROM blob_log
			  WHERE pseudonym=$1 AND device_id=$2 AND generation=$3 AND seq=$4`,
			pseudonym, d.DeviceID, d.Generation, d.HeadSeq).Scan(&d.HeadSha256); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteGeneration implements BlobStore.
func (s *PostgresStore) DeleteGeneration(ctx context.Context, pseudonym, deviceID string, generation int) (int64, error) {
	var newest sql.NullInt64
	if err := s.db.QueryRowContext(ctx,
		`SELECT MAX(generation) FROM blob_log WHERE pseudonym=$1 AND device_id=$2`,
		pseudonym, deviceID).Scan(&newest); err != nil {
		return 0, err
	}
	// Keep the current and previous generation, so a compaction that fails partway never
	// leaves the user with nothing to restore from.
	if newest.Valid && generation > int(newest.Int64)-RetainedGenerations {
		return 0, fmt.Errorf("%w: generation %d, newest %d", ErrRetentionGuard, generation, newest.Int64)
	}

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM blob_log WHERE pseudonym=$1 AND device_id=$2 AND generation=$3`,
		pseudonym, deviceID, generation)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func closeRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		slog.Error("failed to close rows", "error", err)
	}
}
