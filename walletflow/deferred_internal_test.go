package walletflow

import (
	"context"
	"sync"
	"testing"
	"time"
)

// blockingDeferredStore pauses the first ListDeferred, once it has read
// the store, until proceed is closed.
type blockingDeferredStore struct {
	*MemoryDeferredStore
	listed, proceed chan struct{}
	once            sync.Once
}

func (s *blockingDeferredStore) ListDeferred(ctx context.Context) ([]PendingDeferred, error) {
	out, err := s.MemoryDeferredStore.ListDeferred(ctx)
	s.once.Do(func() {
		close(s.listed)
		<-s.proceed
	})
	return out, err
}

// A Deferred settled while Wallet.Deferred was listing the store isn't
// handed out again as a pending one: abandoning that would delete the
// holder key the stored credential is bound to.
func TestDeferred_SkipsOneSettledWhileListing(t *testing.T) {
	ctx := context.Background()
	keys := NewMemoryKeyStore()
	holder, err := keys.NewKey(ctx, KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	mem := NewMemoryDeferredStore()
	creds := NewMemoryCredentialStore()
	w := &Wallet{deps: Dependencies{Deferred: mem, Keys: keys, Credentials: creds, Clock: time.Now},
		deferred: map[string]*Deferred{}, liveKeys: map[string]int{}}
	if err := mem.PutDeferred(ctx, PendingDeferred{ID: "d1", HolderKeyIDs: []string{holder.ID()}}); err != nil {
		t.Fatal(err)
	}
	list, err := w.Deferred(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("Deferred = %v, %v", list, err)
	}
	d1 := list[0]

	blocking := &blockingDeferredStore{MemoryDeferredStore: mem, listed: make(chan struct{}), proceed: make(chan struct{})}
	w.deps.Deferred = blocking
	got := make(chan []*Deferred)
	go func() {
		l, _ := w.Deferred(ctx)
		got <- l
	}()
	<-blocking.listed
	// Meanwhile d1's Poll succeeds: the credential is stored, d1 settled.
	if err := creds.Put(ctx, StoredCredential{ID: "c1", HolderKeyID: holder.ID()}); err != nil {
		t.Fatal(err)
	}
	d1.mu.Lock()
	_ = d1.settle(ctx, false)
	d1.mu.Unlock()
	close(blocking.proceed)
	for _, d := range <-got {
		t.Errorf("Deferred returned %q (done %v), settled while listing", d.ID(), d.Done())
		_ = d.Abandon(ctx)
	}
	if _, err := keys.Key(ctx, holder.ID()); err != nil {
		t.Errorf("the stored credential's holder key: %v", err)
	}
}

// Abandoning a Deferred never deletes a holder key a stored credential's
// copy is bound to; its other holder keys go.
func TestDeferredAbandon_KeepsHolderKeysInUse(t *testing.T) {
	ctx := context.Background()
	keys := NewMemoryKeyStore()
	used, err := keys.NewKey(ctx, KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	unused, err := keys.NewKey(ctx, KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	ds := NewMemoryDeferredStore()
	creds := NewMemoryCredentialStore()
	w := &Wallet{deps: Dependencies{Deferred: ds, Keys: keys, Credentials: creds, Grants: NewMemoryGrantStore(), Clock: time.Now},
		deferred: map[string]*Deferred{}, liveKeys: map[string]int{}}
	if err := creds.Put(ctx, StoredCredential{ID: "c1", Copies: []CredentialCopy{{Credential: "x", HolderKeyID: used.ID()}}}); err != nil {
		t.Fatal(err)
	}
	if err := ds.PutDeferred(ctx, PendingDeferred{ID: "d1", HolderKeyIDs: []string{used.ID(), unused.ID()}}); err != nil {
		t.Fatal(err)
	}
	list, err := w.Deferred(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("Deferred = %v, %v", list, err)
	}
	if err := list[0].Abandon(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Key(ctx, used.ID()); err != nil {
		t.Errorf("the stored credential's holder key: %v", err)
	}
	if _, err := keys.Key(ctx, unused.ID()); err == nil {
		t.Error("the unused holder key was kept")
	}
}
