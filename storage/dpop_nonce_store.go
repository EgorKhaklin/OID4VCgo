package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// DPoPNonceStore is an in-memory issuer.DPoPNonceStore. See the
// package doc comment for why this is development/testing only.
type DPoPNonceStore struct {
	mu     sync.Mutex
	issued map[string]issuer.DPoPNonceRecord
	prune  pruner
}

// NewDPoPNonceStore builds an empty DPoPNonceStore.
func NewDPoPNonceStore() *DPoPNonceStore {
	return &DPoPNonceStore{issued: make(map[string]issuer.DPoPNonceRecord)}
}

// Issue implements issuer.DPoPNonceStore.
func (s *DPoPNonceStore) Issue(_ context.Context, issuance issuer.DPoPNonceIssuance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now, ok := s.prune.due(len(s.issued)); ok {
		pruneMap(s.issued, now, func(r issuer.DPoPNonceRecord) time.Time { return r.ExpiresAt })
		s.prune.pruned(len(s.issued))
	}
	s.issued[issuance.Nonce] = issuer.DPoPNonceRecord{ExpiresAt: issuance.ExpiresAt}
	return nil
}

// Lookup implements issuer.DPoPNonceStore. It leaves the record in
// place, so every Lookup of an issued nonce succeeds until Issue's
// pruning drops it after its ExpiresAt (RFC 9449 §8: a nonce is valid
// for a time window, not for one use). An unknown nonce is
// issuer.ErrDPoPNonceUnknown; this store always answers.
func (s *DPoPNonceStore) Lookup(_ context.Context, lookup issuer.DPoPNonceLookup) (issuer.DPoPNonceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[lookup.Nonce]
	if !ok {
		return issuer.DPoPNonceRecord{}, fmt.Errorf("storage: %w", issuer.ErrDPoPNonceUnknown)
	}
	return record, nil
}
