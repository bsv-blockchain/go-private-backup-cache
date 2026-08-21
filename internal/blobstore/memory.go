package blobstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// MemoryStore is an in-memory BlobStore.
//
// It exists so the handler and security suites run in CI without a database. It enforces
// the same invariants as the Postgres implementation — contiguous sequences, pseudonym
// scoping, and the retention floor — so a test passing here means the same thing.
type MemoryStore struct {
	mu   sync.RWMutex
	rows map[string]*row
	now  func() time.Time
}

type row struct {
	key        BlobKey
	sha256     string
	prevSha256 string
	data       []byte
	createdAt  time.Time
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{rows: map[string]*row{}, now: time.Now}
}

func rowKey(k BlobKey) string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%d", k.Pseudonym, k.DeviceID, k.Generation, k.Seq)
}

// Append implements BlobStore. The body is drained before the lock is taken, so a slow
// upload does not block readers; the sequence check runs twice — advisory before the
// drain, authoritative under the lock — mirroring how the Postgres store's transaction
// settles conflicts at commit time.
func (m *MemoryStore) Append(_ context.Context, k BlobKey, prev string, body io.Reader) (string, int64, error) {
	m.mu.RLock()
	want := m.headSeqLocked(k.Pseudonym, k.DeviceID, k.Generation) + 1
	m.mu.RUnlock()
	if k.Seq != want {
		return "", 0, fmt.Errorf("%w: expected seq %d, got %d", ErrSeqConflict, want, k.Seq)
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return "", 0, fmt.Errorf("read body: %w", err)
	}
	if len(data) == 0 {
		return "", 0, ErrEmptyBlob
	}

	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	m.mu.Lock()
	defer m.mu.Unlock()
	if want := m.headSeqLocked(k.Pseudonym, k.DeviceID, k.Generation) + 1; k.Seq != want {
		return "", 0, fmt.Errorf("%w: expected seq %d, got %d", ErrSeqConflict, want, k.Seq)
	}
	m.rows[rowKey(k)] = &row{key: k, sha256: sha, prevSha256: prev, data: data, createdAt: m.now()}
	return sha, int64(len(data)), nil
}

// Get implements BlobStore.
func (m *MemoryStore) Get(_ context.Context, k BlobKey) (io.ReadCloser, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	r, ok := m.rows[rowKey(k)]
	if !ok {
		return nil, 0, ErrNotFound
	}
	out := make([]byte, len(r.data))
	copy(out, r.data)
	return io.NopCloser(bytes.NewReader(out)), int64(len(out)), nil
}

// Index implements BlobStore.
func (m *MemoryStore) Index(_ context.Context, pseudonym, deviceID string, generation, from, limit int) ([]Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := []Entry{}
	for _, r := range m.rows {
		if r.key.Pseudonym != pseudonym || r.key.DeviceID != deviceID || r.key.Generation != generation {
			continue
		}
		if r.key.Seq < from {
			continue
		}
		out = append(out, Entry{
			Seq: r.key.Seq, Sha256: r.sha256, PrevSha256: r.prevSha256,
			Size: len(r.data), CreatedAt: r.createdAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Manifest implements BlobStore.
func (m *MemoryStore) Manifest(_ context.Context, pseudonym string) ([]DeviceSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	type agg struct {
		head      *row
		total     int64
		updatedAt time.Time
	}
	byDevGen := map[string]*agg{}

	for _, r := range m.rows {
		if r.key.Pseudonym != pseudonym {
			continue
		}
		id := fmt.Sprintf("%s\x00%d", r.key.DeviceID, r.key.Generation)
		a, ok := byDevGen[id]
		if !ok {
			a = &agg{}
			byDevGen[id] = a
		}
		a.total += int64(len(r.data))
		if a.head == nil || r.key.Seq > a.head.key.Seq {
			a.head = r
		}
		if r.createdAt.After(a.updatedAt) {
			a.updatedAt = r.createdAt
		}
	}

	out := []DeviceSummary{}
	for _, a := range byDevGen {
		out = append(out, DeviceSummary{
			DeviceID:   a.head.key.DeviceID,
			Generation: a.head.key.Generation,
			HeadSeq:    a.head.key.Seq,
			HeadSha256: a.head.sha256,
			TotalBytes: a.total,
			UpdatedAt:  a.updatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceID != out[j].DeviceID {
			return out[i].DeviceID < out[j].DeviceID
		}
		return out[i].Generation < out[j].Generation
	})
	return out, nil
}

// DeleteGeneration implements BlobStore.
func (m *MemoryStore) DeleteGeneration(_ context.Context, pseudonym, deviceID string, generation int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	newest := 0
	found := false
	for _, r := range m.rows {
		if r.key.Pseudonym == pseudonym && r.key.DeviceID == deviceID {
			found = true
			if r.key.Generation > newest {
				newest = r.key.Generation
			}
		}
	}
	if found && generation > newest-RetainedGenerations {
		return 0, fmt.Errorf("%w: generation %d, newest %d", ErrRetentionGuard, generation, newest)
	}

	var n int64
	for id, r := range m.rows {
		if r.key.Pseudonym == pseudonym && r.key.DeviceID == deviceID && r.key.Generation == generation {
			delete(m.rows, id)
			n++
		}
	}
	return n, nil
}

// DeleteAccount implements BlobStore.
func (m *MemoryStore) DeleteAccount(_ context.Context, pseudonym string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// No retention guard, deliberately — see the interface doc.
	var n int64
	for id, r := range m.rows {
		if r.key.Pseudonym == pseudonym {
			delete(m.rows, id)
			n++
		}
	}
	return n, nil
}

// Ping implements BlobStore.
func (m *MemoryStore) Ping() error { return nil }

func (m *MemoryStore) headSeqLocked(pseudonym, deviceID string, generation int) int {
	head := 0
	for _, r := range m.rows {
		if r.key.Pseudonym == pseudonym && r.key.DeviceID == deviceID && r.key.Generation == generation {
			if r.key.Seq > head {
				head = r.key.Seq
			}
		}
	}
	return head
}
