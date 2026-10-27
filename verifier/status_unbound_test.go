package verifier_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An mdoc verified with no issuer chain, whose MSO names no status
// Certificate, can't have its status list's signer bound to its issuer:
// without a StatusIssuerPolicy deciding the signer, RequireValidStatus
// refuses its status check rather than let another IACA under the same
// roots sign a VALID list for it.
func TestRequireValidStatus_MdocUnboundWithoutChain(t *testing.T) {
	iaca, _ := testcert.CA(t, "IACA")
	other, otherKey := testcert.CA(t, "another IACA")
	signer, signerKey := testcert.Leaf(t, "the other IACA's status signer", other, otherKey)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	roots.AddCert(other)
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sl, err := statuslist.New(statuslist.Bits1, []uint8{0}, "")
		if err != nil {
			t.Error(err)
		}
		exp := time.Now().Add(time.Hour).Unix()
		token, err := statuslist.IssueTokenCWTX5Chain(signerKey, cose.ES256, statuslist.TokenClaims{Sub: base + r.URL.Path, Iat: time.Now().Unix(), Exp: &exp, StatusList: sl}, []*x509.Certificate{signer})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", statuslist.CWTTokenMediaType)
		_, _ = w.Write(token)
	}))
	defer srv.Close()
	base = srv.URL
	checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	res := verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{
		MdocStatus: &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 0, URI: base + "/victim"}},
	}}}
	ctx := context.Background()
	if err := verifier.RequireValidStatus(checker)(ctx, "id", res); err == nil || !strings.Contains(err.Error(), "can't be bound") {
		t.Errorf("a list signed under another IACA, with nothing to bind it to: %v, want refused", err)
	}
	refuse := func(string, *x509.Certificate, [][]*x509.Certificate) error { return context.Canceled }
	if err := verifier.RequireValidStatusFrom(checker, refuse)(ctx, "id", res); err == nil {
		t.Error("a StatusIssuerPolicy refusing the signer: accepted")
	}
	if err := verifier.RequireValidStatusFrom(checker, verifier.AnyStatusListSigner)(ctx, "id", res); err != nil {
		t.Errorf("AnyStatusListSigner, opted into: %v", err)
	}
}
