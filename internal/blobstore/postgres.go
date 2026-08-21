package blobstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/lib/pq" // postgres driver
)

// ChunkBytes is how much of a blob one blob_chunks row holds. One megabyte keeps any
// single allocation modest while an upload streams through, and a 200 MiB blob is only
// 200 rows.
const ChunkBytes = 1 << 20

// Migrations are idempotent and run at boot, matching the house pattern of hand-written
// CREATE TABLE IF NOT EXISTS statements rather than a migration tool.
//
// The first statement drops the pre-streaming table (single bytea column, 1 MiB cap) if
// it is what's there. Destructive on purpose, per the standing no-compatibility decision:
// nothing carries — not the wire format, the store schema, or existing rows.
var Migrations = []string{
	`DO $$ BEGIN
		IF EXISTS (SELECT 1 FROM information_schema.columns
		            WHERE table_name = 'blob_log' AND column_name = 'ciphertext') THEN
			DROP TABLE blob_log;
		END IF;
	END $$`,
	`CREATE TABLE IF NOT EXISTS blob_log (
		pseudonym    TEXT        NOT NULL,
		device_id    TEXT        NOT NULL,
		generation   INTEGER     NOT NULL,
		seq          INTEGER     NOT NULL,
		sha256       TEXT        NOT NULL,
		prev_sha256  TEXT,
		size         BIGINT      NOT NULL,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
		PRIMARY KEY (pseudonym, device_id, generation, seq)
	)`,
	`CREATE INDEX IF NOT EXISTS blob_log_head
		ON blob_log (pseudonym, device_id, generation, seq DESC)`,
	`CREATE TABLE IF NOT EXISTS blob_chunks (
		pseudonym    TEXT    NOT NULL,
		device_id    TEXT    NOT NULL,
		generation   INTEGER NOT NULL,
		seq          INTEGER NOT NULL,
		idx          INTEGER NOT NULL,
		chunk        BYTEA   NOT NULL,
		PRIMARY KEY (pseudonym, device_id, generation, seq, idx)
	)`,
}

// PostgresStore stores blob metadata in blob_log and the ciphertext in 1 MiB blob_chunks
// rows, so a blob of any permitted size streams through a bounded buffer in both
// directions. Postgres also gives transactional appends, which the contiguity rule needs.
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

// DB exposes the pool so collaborators sharing the database (the nonce store) reuse one
// set of connections instead of opening their own.
func (s *PostgresStore) DB() *sql.DB { return s.db }

// Append implements BlobStore.
//
// One transaction: read the head sequence, insert chunks as the body streams through a
// ChunkBytes buffer, then the metadata row, then commit. Contiguity matters because a gap
// becomes a silent hole in a restore, and an overwrite would destroy a backup entry. Any
// body read error — including a digest mismatch detected by the reader wrapper upstream —
// rolls the whole thing back, so a failed upload leaves no trace.
func (s *PostgresStore) Append(ctx context.Context, k BlobKey, prev string, body io.Reader) (string, int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err
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
		return "", 0, err
	}

	want := 1
	if head.Valid {
		want = int(head.Int64) + 1
	}
	if k.Seq != want {
		return "", 0, fmt.Errorf("%w: expected seq %d, got %d", ErrSeqConflict, want, k.Seq)
	}

	hasher := sha256.New()
	buf := make([]byte, ChunkBytes)
	var size int64
	for idx := 0; ; idx++ {
		n, readErr := io.ReadFull(body, buf)
		if n > 0 {
			hasher.Write(buf[:n])
			size += int64(n)
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO blob_chunks (pseudonym, device_id, generation, seq, idx, chunk)
				 VALUES ($1,$2,$3,$4,$5,$6)`,
				k.Pseudonym, k.DeviceID, k.Generation, k.Seq, idx, buf[:n]); err != nil {
				return "", 0, asSeqConflict(err)
			}
		}
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
		if readErr != nil {
			return "", 0, fmt.Errorf("read body: %w", readErr)
		}
	}
	if size == 0 {
		return "", 0, ErrEmptyBlob
	}
	sha := hex.EncodeToString(hasher.Sum(nil))

	_, err = tx.ExecContext(ctx,
		`INSERT INTO blob_log (pseudonym, device_id, generation, seq, sha256, prev_sha256, size)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		k.Pseudonym, k.DeviceID, k.Generation, k.Seq, sha, nullable(prev), size)
	if err != nil {
		return "", 0, asSeqConflict(err)
	}
	return sha, size, asNilOrSeqConflict(tx.Commit())
}

// asSeqConflict maps a unique-key violation onto ErrSeqConflict.
//
// The MAX(seq) head check runs under READ COMMITTED, so two appends racing for the same
// sequence both pass it; the primary key then stops the loser. That is the same protocol
// situation the head check refuses — somebody else already holds this sequence — and the
// caller must see the same answer (409), not an internal error. The memory store's
// under-lock re-check returns ErrSeqConflict for the identical race; this keeps the two
// implementations telling one story.
func asSeqConflict(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return fmt.Errorf("%w: another append holds this sequence", ErrSeqConflict)
	}
	return err
}

func asNilOrSeqConflict(err error) error {
	if err == nil {
		return nil
	}
	return asSeqConflict(err)
}

// Get implements BlobStore.
//
// The metadata row supplies the size up front (for Content-Length); the chunks then
// stream out one row at a time as the caller reads. lib/pq delivers rows lazily, so the
// full blob is never resident. Both queries run inside one REPEATABLE READ transaction —
// one snapshot — so a concurrent prune or erasure cannot make the promised Content-Length
// and the streamed bytes disagree. The transaction stays open until the caller closes the
// reader.
func (s *PostgresStore) Get(ctx context.Context, k BlobKey) (io.ReadCloser, int64, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}

	var size int64
	err = tx.QueryRowContext(ctx,
		`SELECT size FROM blob_log
		 WHERE pseudonym=$1 AND device_id=$2 AND generation=$3 AND seq=$4`,
		k.Pseudonym, k.DeviceID, k.Generation, k.Seq).Scan(&size)
	if err != nil {
		rollback(tx)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT chunk FROM blob_chunks
		 WHERE pseudonym=$1 AND device_id=$2 AND generation=$3 AND seq=$4
		 ORDER BY idx ASC`,
		k.Pseudonym, k.DeviceID, k.Generation, k.Seq)
	if err != nil {
		rollback(tx)
		return nil, 0, err
	}
	return &chunkReader{rows: rows, tx: tx}, size, nil
}

// chunkReader adapts a blob_chunks result set to io.ReadCloser. It owns the read
// transaction whose snapshot the rows come from; Close releases both.
type chunkReader struct {
	rows *sql.Rows
	tx   *sql.Tx
	buf  []byte
	err  error
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if !r.rows.Next() {
			if err := r.rows.Err(); err != nil {
				r.err = err
			} else {
				r.err = io.EOF
			}
			return 0, r.err
		}
		if err := r.rows.Scan(&r.buf); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *chunkReader) Close() error {
	err := r.rows.Close()
	rollback(r.tx)
	return err
}

// rollback ends a transaction whose work is done, logging only real failures.
func rollback(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		slog.Error("rollback failed", "error", err)
	}
}

// Index implements BlobStore.
func (s *PostgresStore) Index(ctx context.Context, pseudonym, deviceID string, generation, from, limit int) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, sha256, COALESCE(prev_sha256,''), size, created_at
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
//
// One statement, deliberately. The obvious shape — aggregate rows, then a per-row lookup
// for the head sha — needs a second pooled connection while the first is still streaming
// the outer result set; under load that is a textbook pool deadlock (25 manifests each
// holding one connection, all waiting for a 26th). DISTINCT ON gives the head row of each
// (device, generation) directly, and the window functions aggregate over the same pass.
func (s *PostgresStore) Manifest(ctx context.Context, pseudonym string) ([]DeviceSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT ON (device_id, generation)
		        device_id,
		        generation,
		        seq                                                    AS head_seq,
		        sha256                                                 AS head_sha256,
		        SUM(size)       OVER (PARTITION BY device_id, generation) AS total_bytes,
		        MAX(created_at) OVER (PARTITION BY device_id, generation) AS updated_at
		   FROM blob_log
		  WHERE pseudonym = $1
		  ORDER BY device_id, generation, seq DESC`,
		pseudonym)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)

	out := []DeviceSummary{}
	for rows.Next() {
		var d DeviceSummary
		if err := rows.Scan(&d.DeviceID, &d.Generation, &d.HeadSeq, &d.HeadSha256, &d.TotalBytes, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteGeneration implements BlobStore. The returned count is log entries, not chunks.
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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Error("rollback failed", "error", rbErr)
		}
	}()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM blob_chunks WHERE pseudonym=$1 AND device_id=$2 AND generation=$3`,
		pseudonym, deviceID, generation); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx,
		`DELETE FROM blob_log WHERE pseudonym=$1 AND device_id=$2 AND generation=$3`,
		pseudonym, deviceID, generation)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// DeleteAccount implements BlobStore.
//
// One transaction, no generation bookkeeping and no retention check: an erasure request
// is all-or-nothing, and a partial erasure that reported success would be worse than an
// error. The returned count is log entries, not chunks.
func (s *PostgresStore) DeleteAccount(ctx context.Context, pseudonym string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Error("rollback failed", "error", rbErr)
		}
	}()

	if _, err := tx.ExecContext(ctx, `DELETE FROM blob_chunks WHERE pseudonym=$1`, pseudonym); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM blob_log WHERE pseudonym=$1`, pseudonym)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
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
