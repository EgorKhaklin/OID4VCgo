package storage

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DPoPReplayChecker is an in-memory issuer.DPoPReplayChecker: it
// remembers every "jti" UseOnce has seen and rejects a repeat, per
// RFC 9449 §11.1's own "MUST reject any DPoP proof in which the jti
// has been seen before". Each jti is kept until its expiresAt — past
// it the proof is refused for its age anyway — and expired ones are
// dropped as the map grows. In-memory and non-durable: see the package
// doc comment for why that's development/testing only.
type DPoPReplayChecker struct {
	mu    sync.Mutex
	seen  map[string]time.Time // until when each jti is remembered
	prune pruner
}

// NewDPoPReplayChecker builds an empty DPoPReplayChecker.
func NewDPoPReplayChecker() *DPoPReplayChecker {
	return &DPoPReplayChecker{seen: make(map[string]time.Time)}
}

// UseOnce implements issuer.DPoPReplayChecker.
func (s *DPoPReplayChecker) UseOnce(_ context.Context, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.seen[jti]; seen {
		return fmt.Errorf("storage: dpop proof jti %q already used", jti)
	}
	// A proof past expiresAt is refused for its age, so its jti needn't
	// be remembered beyond it.
	if now, ok := s.prune.due(len(s.seen)); ok {
		pruneMap(s.seen, now, func(until time.Time) time.Time { return until })
		s.prune.pruned(len(s.seen))
	}
	s.seen[jti] = expiresAt
	return nil
}
