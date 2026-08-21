package nonce_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
)

func TestConsumeIsSingleUse(t *testing.T) {
	s := nonce.NewMemoryStore()
	exp := time.Now().Add(2 * time.Minute)

	ok, err := s.Consume(context.Background(), "n1", exp)
	if err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v", ok, err)
	}
	ok, err = s.Consume(context.Background(), "n1", exp)
	if err != nil || ok {
		t.Fatalf("replay accepted: ok=%v err=%v", ok, err)
	}
	ok, err = s.Consume(context.Background(), "n2", exp)
	if err != nil || !ok {
		t.Fatalf("distinct nonce refused: ok=%v err=%v", ok, err)
	}
}

func TestConsumeIsSingleUseUnderConcurrency(t *testing.T) {
	s := nonce.NewMemoryStore()
	exp := time.Now().Add(2 * time.Minute)

	const racers = 32
	wins := make(chan bool, racers)
	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.Consume(context.Background(), "contested", exp)
			if err != nil {
				t.Error(err)
			}
			wins <- ok
		}()
	}
	wg.Wait()
	close(wins)

	won := 0
	for ok := range wins {
		if ok {
			won++
		}
	}
	if won != 1 {
		t.Errorf("expected exactly one winner, got %d", won)
	}
}

func TestExpiredNoncesAreForgotten(t *testing.T) {
	s := nonce.NewMemoryStore()

	// Already-expired record: a replay of it after expiry is refused by the proof's
	// freshness check, not by the store, so the store may forget it and accept the
	// nonce string again.
	past := time.Now().Add(-time.Minute)
	if ok, _ := s.Consume(context.Background(), "old", past); !ok {
		t.Fatal("first use refused")
	}
	if ok, _ := s.Consume(context.Background(), "old", time.Now().Add(time.Minute)); !ok {
		t.Error("expired record still blocks the nonce")
	}
}
