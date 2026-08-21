// Package nonce enforces single-use of auth-proof nonces.
//
// A proof is replayable for its whole validity window unless the nonce is consumed on
// first sight. Consumption must be atomic across replicas, which is why the production
// implementation is a Postgres insert rather than anything in-process.
package nonce

import (
	"context"
	"sync"
	"time"
)

// Store records nonces. Consume returns true exactly once per nonce: the first caller
// wins, every later caller (a replay) gets false. expiresAt bounds how long the record
// must be kept — after that the proof it belongs to is refused on expiry alone.
type Store interface {
	Consume(ctx context.Context, nonce string, expiresAt time.Time) (bool, error)
}

// MemoryStore is a single-process Store for tests and DATABASE_URL-less runs.
type MemoryStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryStore builds an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{seen: map[string]time.Time{}, now: time.Now}
}

// Consume implements Store. Expired records are swept inline — the map stays bounded by
// the number of proofs minted within one validity window.
func (m *MemoryStore) Consume(_ context.Context, nonce string, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	for n, exp := range m.seen {
		if now.After(exp) {
			delete(m.seen, n)
		}
	}
	if _, used := m.seen[nonce]; used {
		return false, nil
	}
	m.seen[nonce] = expiresAt
	return true, nil
}
