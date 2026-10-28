package storage_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

func TestDPoPNonceStore_IssueThenLookup(t *testing.T) {
	s := storage.NewDPoPNonceStore()
	ctx := context.Background()
	expires := time.Now().Add(time.Minute)

	if err := s.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "nonce-1", ExpiresAt: expires}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	record, err := s.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: "nonce-1"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !record.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", record.ExpiresAt, expires)
	}
}

// TestDPoPNonceStore_LookupLeavesTheNonce: a nonce is valid for a time
// window (RFC 9449 §8), so repeated and concurrent Lookups all succeed.
func TestDPoPNonceStore_LookupLeavesTheNonce(t *testing.T) {
	s := storage.NewDPoPNonceStore()
	ctx := context.Background()
	if err := s.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "nonce-1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Go(func() {
			_, err := s.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: "nonce-1"})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Lookup: %v", err)
		}
	}
	if _, err := s.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: "nonce-1"}); err != nil {
		t.Fatalf("Lookup after the concurrent ones: %v", err)
	}
}

func TestDPoPNonceStore_LookupRejectsUnknownNonce(t *testing.T) {
	s := storage.NewDPoPNonceStore()
	_, err := s.Lookup(context.Background(), issuer.DPoPNonceLookup{Nonce: "never-issued"})
	if !errors.Is(err, issuer.ErrDPoPNonceUnknown) {
		t.Fatalf("Lookup = %v, want issuer.ErrDPoPNonceUnknown", err)
	}
}

// TestDPoPNonceStore_LookupReturnsAnExpiredRecord: the store doesn't
// judge expiry; the caller compares ExpiresAt with its own clock.
func TestDPoPNonceStore_LookupReturnsAnExpiredRecord(t *testing.T) {
	s := storage.NewDPoPNonceStore()
	ctx := context.Background()
	expired := time.Now().Add(-time.Minute)
	if err := s.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "old", ExpiresAt: expired}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	record, err := s.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: "old"})
	if err != nil || !record.ExpiresAt.Equal(expired) {
		t.Fatalf("Lookup = %+v, %v; want the expired record", record, err)
	}
}
