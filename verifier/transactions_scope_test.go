package verifier_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// otherScope is Transactions sharing f's store with lax's policy: no
// Accept, so it would take any answer that verifies.
func (f *txFixture) otherScope(t *testing.T, v *verifier.Verifier, scope string) *verifier.Transactions {
	t.Helper()
	other, err := verifier.NewTransactions(v, f.store, verifier.TransactionsConfig{
		RequestURIBase: txBase, RedirectURI: "https://verifier.example.com/continue",
		Verify: f.verify, Scope: scope,
	})
	if err != nil {
		t.Fatalf("NewTransactions: %v", err)
	}
	return other
}

// strictFixture is a txFixture whose Accept refuses every answer.
func strictFixture(t *testing.T) (*txFixture, error) {
	refused := errors.New("this use case's policy refuses the holder")
	return newTxFixture(t, func(cfg *verifier.TransactionsConfig) {
		cfg.Accept = func(context.Context, string, verifier.VerifyResponseResult) error { return refused }
	}), refused
}

// Two use cases of one relying party — one client certificate, so one
// client_id, with their own response URIs and policies — share a store:
// an answer to one posted to the other's response endpoint mustn't
// complete the first's request under the second's policy.
func TestTransactions_SharedStoreSameClientID(t *testing.T) {
	f, refused := strictFixture(t)
	ctx := context.Background()
	cfg, deps := validConfig(t)
	cfg.ClientCertificate, deps.Signer = f.vcfg.ClientCertificate, f.vdeps.Signer
	var err error
	if cfg.ResponseURI, err = fapi.ParseEndpointURL("https://verifier.example.com/b/response"); err != nil {
		t.Fatal(err)
	}
	vB, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	if vB.ClientID() != f.v.ClientID() {
		t.Fatal("the two use cases should share a client_id")
	}
	txB := f.otherScope(t, vB, "")

	begun := f.begin(testBinding+"-0123456789", false)
	answer := f.answer(begun, nil)
	if _, err := f.txs.HandleResponse(ctx, answer); !errors.Is(err, refused) {
		t.Fatalf("its own Transactions: %v, want its Accept's refusal", err)
	}
	if _, err := txB.HandleResponse(ctx, answer); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Fatalf("the other use case's HandleResponse: %v, want ErrTransactionUnknown", err)
	}
	if view, err := f.txs.Lookup(ctx, begun.ID, testBinding+"-0123456789"); err != nil || view.Status != verifier.TransactionPending {
		t.Fatalf("after the other use case's attempt: %+v, %v; want still pending", view, err)
	}
}

// Every path that reads a transaction by its ID, or by its key or
// response_code, refuses another scope's as unknown.
func TestTransactions_ScopeIsolatesEveryPath(t *testing.T) {
	ctx := context.Background()
	const binding = "browser-binding-0123456789"
	for name, other := range map[string]func(*testing.T, *txFixture) *verifier.Transactions{
		"an explicit scope": func(t *testing.T, f *txFixture) *verifier.Transactions { return f.otherScope(t, f.v, "lax") },
		"another client_id": func(t *testing.T, f *txFixture) *verifier.Transactions {
			return f.otherScope(t, newTestVerifier(t), "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, refused := strictFixture(t)
			other := other(t, f)
			for _, sameDevice := range []bool{false, true} {
				begun := f.begin(binding, sameDevice)
				answer := f.answer(begun, nil)
				if _, err := other.HandleResponse(ctx, answer); !errors.Is(err, verifier.ErrTransactionUnknown) {
					t.Errorf("same-device %v: HandleResponse: %v, want ErrTransactionUnknown", sameDevice, err)
				}
				if _, err := other.RequestObject(ctx, begun.ID); !errors.Is(err, verifier.ErrTransactionUnknown) {
					t.Errorf("RequestObject: %v, want ErrTransactionUnknown", err)
				}
				if _, err := other.Lookup(ctx, begun.ID, binding); !errors.Is(err, verifier.ErrTransactionUnknown) {
					t.Errorf("Lookup: %v, want ErrTransactionUnknown", err)
				}
				if err := other.Close(ctx, begun.ID); !errors.Is(err, verifier.ErrTransactionUnknown) {
					t.Errorf("Close: %v, want ErrTransactionUnknown", err)
				}
				if err := other.Forget(ctx, begun.ID); !errors.Is(err, verifier.ErrTransactionUnknown) {
					t.Errorf("Forget: %v, want ErrTransactionUnknown", err)
				}
				if _, err := f.txs.HandleResponse(ctx, answer); !errors.Is(err, refused) {
					t.Errorf("its own Transactions: %v, want its Accept's refusal", err)
				}
				if view, err := f.txs.Lookup(ctx, begun.ID, binding); err != nil || view.Status != verifier.TransactionPending || view.LastError == "" {
					t.Errorf("same-device %v: %+v, %v; want still pending, with its own refusal recorded", sameDevice, view, err)
				}
			}

			// An unencrypted error naming another scope's request is
			// acknowledged with nothing, as one naming no request is.
			if got := other.HandleUnencryptedError(ctx, "access_denied", f.stateOf(f.begin(binding, true))); got != (verifier.Answered{}) {
				t.Errorf("HandleUnencryptedError: %+v, want nothing", got)
			}

			// A Digital Credentials API request.
			dc := f.beginDCAPI(binding)
			if _, err := other.HandleDCAPIResponse(ctx, dc.ID, binding, f.dcapiAnswer(dc, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionUnknown) {
				t.Errorf("HandleDCAPIResponse: %v, want ErrTransactionUnknown", err)
			}
		})
	}
}

// A same-device response_code redeems only in the scope that issued it.
func TestTransactions_ScopeIsolatesRedeem(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	other := f.otherScope(t, f.v, "elsewhere")
	const binding = "browser-binding-0123456789"
	answered, err := f.txs.HandleResponse(ctx, f.answer(f.begin(binding, true), nil))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(answered.RedirectURI)
	code := u.Query().Get("response_code")
	if _, err := other.Redeem(ctx, code, binding); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("another scope's Redeem: %v, want ErrTransactionUnknown", err)
	}
	if view, err := f.txs.Redeem(ctx, code, binding); err != nil || view.Status != verifier.TransactionDone {
		t.Errorf("its own Redeem: %+v, %v", view, err)
	}
}

// A transaction saved before scopes were recorded is read with the
// derived scope only.
func TestTransactions_UnscopedTransaction(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	explicit := f.otherScope(t, f.v, "explicit")
	derivedAlike := f.otherScope(t, newTestVerifier(t), "")
	const binding = "browser-binding-0123456789"
	begun := f.begin(binding, false)
	if err := f.store.Update(ctx, begun.ID, func(tx *verifier.Transaction) error {
		if tx.Owner == "" {
			t.Error("a new transaction records no owner")
		}
		tx.Owner = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := explicit.Lookup(ctx, begun.ID, binding); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("an explicit scope reads an unscoped transaction: %v", err)
	}
	if _, err := derivedAlike.Lookup(ctx, begun.ID, binding); err != nil {
		t.Errorf("a derived scope doesn't read an unscoped transaction: %v", err)
	}
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
		t.Errorf("its own Transactions: %v", err)
	}
}

// ownerDroppingStore is a TransactionStore that doesn't persist Owner.
type ownerDroppingStore struct{ verifier.TransactionStore }

func (s ownerDroppingStore) Create(ctx context.Context, tx verifier.Transaction) error {
	tx.Owner = ""
	return s.TransactionStore.Create(ctx, tx)
}

// forgetfulStore is a TransactionStore whose Get finds nothing.
type forgetfulStore struct{ verifier.TransactionStore }

func (forgetfulStore) Get(context.Context, string) (verifier.Transaction, error) {
	return verifier.Transaction{}, verifier.ErrTransactionUnknown
}

// A store that drops Owner would make every derived scope read the
// others' transactions: Begin and BeginDCAPI refuse it, every time,
// naming the store.
func TestTransactions_StoreDroppingOwner(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	cfg := verifier.TransactionsConfig{RequestURIBase: txBase, Verify: f.verify}
	txs, err := verifier.NewTransactions(f.v, ownerDroppingStore{f.store}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	const binding = "browser-binding-0123456789"
	for i := range 2 {
		if _, err := txs.Begin(ctx, f.query, binding, false); err == nil || !strings.Contains(err.Error(), "Owner") || !strings.Contains(err.Error(), "ownerDroppingStore") {
			t.Errorf("Begin %d: %v, want the store refused for dropping Owner", i, err)
		}
		if _, err := txs.BeginDCAPI(ctx, f.query, binding, dcapiOrigin); err == nil || !strings.Contains(err.Error(), "Owner") {
			t.Errorf("BeginDCAPI %d: %v, want the store refused for dropping Owner", i, err)
		}
	}

	// A store that can't read back what it created is refused too.
	forgetful, err := verifier.NewTransactions(f.v, forgetfulStore{f.store}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forgetful.Begin(ctx, f.query, binding, false); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Begin with a store that can't read back: %v, want its error", err)
	}

	// A store that keeps Owner is checked once, then trusted.
	for range 2 {
		if _, err := f.txs.Begin(ctx, f.query, binding, false); err != nil {
			t.Fatal(err)
		}
		if _, err := f.txs.BeginDCAPI(ctx, f.query, binding, dcapiOrigin); err != nil {
			t.Fatal(err)
		}
	}
}

// Under AssuranceProduction, a transaction without an Owner is no
// Transactions' at all, the derived scope's included.
func TestTransactions_UnscopedTransactionProduction(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	prod, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	verify := f.verify
	verify.AnyIssuerForAnyType = true
	txs, err := verifier.NewTransactions(prod, assuredTransactionStore{f.store}, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: verify, NoStatusCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	const binding = "browser-binding-0123456789"
	begun, err := txs.Begin(ctx, f.query, binding, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txs.Lookup(ctx, begun.ID, binding); err != nil {
		t.Fatalf("its own transaction: %v", err)
	}
	if err := f.store.Update(ctx, begun.ID, func(tx *verifier.Transaction) error {
		tx.Owner = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := txs.Lookup(ctx, begun.ID, binding); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("an unscoped transaction under AssuranceProduction: %v, want ErrTransactionUnknown", err)
	}
}
