package verifier_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// IssuerAuthorized sees an SD-JWT VC's type, the requested types and
// its verified issuer chain, and its refusal discards the presentation
// as untrusted_issuer (SD-JWT VC draft-19 §7.7).
func TestIssuerAuthorized_SDJWTVC(t *testing.T) {
	var seen verifier.IssuerAuthorization
	refuse := false
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) {
		c.Verify.IssuerAuthorized = func(_ context.Context, a verifier.IssuerAuthorization) error {
			seen = a
			if refuse {
				return errors.New("this issuer may not issue " + a.Type)
			}
			return nil
		}
	})
	ctx := context.Background()

	begun := f.begin("browser-binding-A", false)
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
		t.Fatalf("authorized: %v", err)
	}
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); err != nil || view.Status != verifier.TransactionDone || view.Result == nil {
		t.Fatalf("authorized: Lookup = %+v, %v", view, err)
	}
	if seen.CredentialQueryID != "cred" || seen.Format != "dc+sd-jwt" || seen.Type != "urn:tx:1" ||
		!slices.Equal(seen.RequestedTypes, []string{"urn:tx:1"}) || len(seen.IssuerChain) == 0 || seen.Claims["given_name"] != "Jean" {
		t.Errorf("IssuerAuthorization = %+v", seen)
	}

	refuse = true
	begun = f.begin("browser-binding-A", false)
	_, err := f.txs.HandleResponse(ctx, f.answer(begun, nil))
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonUntrustedIssuer {
		t.Fatalf("refused: HandleResponse = %v, want untrusted_issuer", err)
	}
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); err != nil || view.Result != nil || !strings.Contains(view.LastError, "(untrusted_issuer)") {
		t.Fatalf("refused: Lookup = %+v, %v; want the answer refused", view, err)
	}
}

// IssuerAuthorized sees an mdoc's doctype, and its refusal fails the
// presentation as untrusted_issuer.
func TestIssuerAuthorized_Mdoc(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	var seen verifier.IssuerAuthorization
	_, err := mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) {
		r.IssuerAuthorized = func(_ context.Context, a verifier.IssuerAuthorization) error {
			seen = a
			return errors.New("not for this doctype")
		}
	})
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonUntrustedIssuer {
		t.Fatalf("VerifyResponse = %v, want untrusted_issuer", err)
	}
	if seen.Format != "mso_mdoc" || seen.Type != testmdoc.DocType || !slices.Equal(seen.RequestedTypes, []string{testmdoc.DocType}) ||
		!slices.Equal(seen.MatchedTypes, []string{testmdoc.DocType}) {
		t.Errorf("IssuerAuthorization = %+v", seen)
	}
}
