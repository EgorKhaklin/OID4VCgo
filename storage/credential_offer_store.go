package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// CredentialOfferStore is an in-memory issuer.CredentialOfferStore. See
// the package doc comment for why this is development/testing only.
// Offers past their ExpiresAt are dropped as the store grows.
type CredentialOfferStore struct {
	mu      sync.Mutex
	records map[string]issuer.CredentialOfferRecord
	prune   pruner
}

// NewCredentialOfferStore builds an empty CredentialOfferStore.
func NewCredentialOfferStore() *CredentialOfferStore {
	return &CredentialOfferStore{records: make(map[string]issuer.CredentialOfferRecord)}
}

// Store implements issuer.CredentialOfferStore.
func (s *CredentialOfferStore) Store(_ context.Context, record issuer.CredentialOfferRecord) error {
	record.Offer = cloneCredentialOffer(record.Offer)
	s.mu.Lock()
	defer s.mu.Unlock()
	if now, ok := s.prune.due(len(s.records)); ok {
		pruneMap(s.records, now, func(r issuer.CredentialOfferRecord) time.Time { return r.ExpiresAt })
		s.prune.pruned(len(s.records))
	}
	s.records[record.Reference] = record
	return nil
}

// Get implements issuer.CredentialOfferStore.
func (s *CredentialOfferStore) Get(_ context.Context, reference string) (issuer.CredentialOfferRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[reference]
	if !ok {
		return issuer.CredentialOfferRecord{}, fmt.Errorf("storage: unknown credential offer reference")
	}
	record.Offer = cloneCredentialOffer(record.Offer)
	return record, nil
}
