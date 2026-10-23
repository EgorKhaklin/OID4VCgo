package storage

import (
	"context"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// Invalidate runs once the Credentials are on their way to the Wallet,
// so the store stops holding them.
func TestDeferredTransactionStoreInvalidateDropsCredentials(t *testing.T) {
	s := NewDeferredTransactionStore()
	ctx := context.Background()
	if err := s.Create(ctx, "txn-1", issuer.DeferredTransactionRecord{
		Status: issuer.DeferredTransactionIssued, Credentials: []oid4vci.IssuedCredential{{Credential: "signed-credential"}},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Invalidate(ctx, "txn-1"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if got := s.records["txn-1"].Credentials; got != nil {
		t.Errorf("Credentials after Invalidate = %v, want none", got)
	}
	if err := s.Create(ctx, "txn-1", issuer.DeferredTransactionRecord{}); err == nil {
		t.Error("Create reused an invalidated transaction_id")
	}
}
