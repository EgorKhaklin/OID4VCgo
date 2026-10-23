package verifier_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// TestTransactions_ResultRetention: a completed request's result is
// reported for one Lifetime past the request's expiry and not after.
func TestTransactions_ResultRetention(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) { c.Lifetime = time.Minute })
	start := f.now
	begun := f.begin("browser-binding-A", false)
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
		t.Fatal(err)
	}
	f.now = start.Add(2*time.Minute - time.Second)
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); err != nil || view.Status != verifier.TransactionDone || view.Result == nil {
		t.Fatalf("Lookup within the retention = %+v, %v", view, err)
	}
	f.now = start.Add(2 * time.Minute)
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); err != nil || view.Status != verifier.TransactionExpired || view.Result != nil {
		t.Errorf("Lookup past the retention = %+v, %v; want expired, no result", view, err)
	}
}

// TestTransactions_Forget: Forget drops a completed request's result
// and closes it.
func TestTransactions_Forget(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	begun := f.begin("browser-binding-A", false)
	jwe := f.answer(begun, nil)
	if _, err := f.txs.HandleResponse(ctx, jwe); err != nil {
		t.Fatal(err)
	}
	if err := f.txs.Forget(ctx, begun.ID); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); err != nil || view.Status != verifier.TransactionClosed || view.Result != nil {
		t.Errorf("Lookup after Forget = %+v, %v; want closed, no result", view, err)
	}
	if _, err := f.txs.HandleResponse(ctx, jwe); !errors.Is(err, verifier.ErrTransactionClosed) {
		t.Errorf("answer after Forget: %v, want ErrTransactionClosed", err)
	}
	// Served as for any closed request (see RequestObject).
	if _, err := f.txs.RequestObject(ctx, begun.ID); err != nil {
		t.Errorf("the request object after Forget: %v", err)
	}
	if err := f.txs.Forget(ctx, "unknown"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Forget of an unknown request: %v, want ErrTransactionUnknown", err)
	}
}

// TestTransactions_ForgetSameDevice: Forget of a same-device request
// awaiting its redirect retires the response_code with the result.
func TestTransactions_ForgetSameDevice(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	begun := f.begin("browser-binding-A", true)
	answered, err := f.txs.HandleResponse(ctx, f.answer(begun, nil))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(answered.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	code := redirect.Query().Get("response_code")
	if err := f.txs.Forget(ctx, begun.ID); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if _, err := f.txs.Redeem(ctx, code, "browser-binding-A"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Redeem after Forget: %v, want ErrTransactionUnknown", err)
	}
}
